// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/policy/groups"
)

var (
	cnpToGroupsControllerGroup = controller.NewGroup("cilium-network-policy-to-groups")
)

func init() {
	runtime.ErrorHandlers = []runtime.ErrorHandler{
		k8s.K8sErrorHandler,
	}
}

// enableCNPWatcher waits for the CiliumNetworkPolicy CRD availability and then
// garbage collects stale CiliumNetworkPolicy status field entries.
func enableCNPWatcher(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) error {
	log.Info("Starting CNP derivative handler")
	cnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	ciliumV2Controller := informer.NewInformerWithStore(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumNetworkPolicyList](clientset.CiliumV2().CiliumNetworkPolicies("")),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				k8sEventMetric(resources.MetricCNP, resources.MetricCreate)
				if cnp := informer.CastInformerEvent[types.SlimCNP](obj); cnp != nil {
					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativeCNPIfNeeded(clientset, cnpCpy.CiliumNetworkPolicy)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				k8sEventMetric(resources.MetricCNP, resources.MetricUpdate)
				if oldCNP := informer.CastInformerEvent[types.SlimCNP](oldObj); oldCNP != nil {
					if newCNP := informer.CastInformerEvent[types.SlimCNP](newObj); newCNP != nil {
						if oldCNP.DeepEqual(newCNP) {
							return
						}

						// We need to deepcopy this structure because we are writing
						// fields.
						// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
						newCNPCpy := newCNP.DeepCopy()
						oldCNPCpy := oldCNP.DeepCopy()

						groups.UpdateDerivativeCNPIfNeeded(clientset, newCNPCpy.CiliumNetworkPolicy, oldCNPCpy.CiliumNetworkPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				k8sEventMetric(resources.MetricCNP, resources.MetricDelete)
				cnp := informer.CastInformerEvent[types.SlimCNP](obj)
				if cnp == nil {
					return
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
			},
		},
		k8s.TransformToCNP,
		cnpStore,
	)

	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ciliumV2Controller.Run(ctx.Done())
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController("cnp-to-groups",
		controller.ControllerParams{
			Group: cnpToGroupsControllerGroup,
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation(clientset)
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
