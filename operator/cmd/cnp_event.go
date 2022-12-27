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
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/groups"
)

var (
	// cnpStatusUpdateInterval is the amount of time between status updates
	// being sent to the K8s apiserver for a given CNP.
	cnpStatusUpdateInterval time.Duration
)

func init() {
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
}

// enableCNPWatcher waits for the CiliumNetworkPolicy CRD availability and then
// garbage collects stale CiliumNetworkPolicy status field entries.
func enableCNPWatcher(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) error {
	enableCNPStatusUpdates := kvstoreEnabled() && option.Config.K8sEventHandover && !option.Config.DisableCNPStatusUpdates
	if enableCNPStatusUpdates {
		log.Info("Starting CNP Status handover from kvstore to k8s")
	}
	log.Info("Starting CNP derivative handler")

	var (
		cnpStatusMgr *k8s.CNPStatusEventHandler
	)
	cnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	if enableCNPStatusUpdates {
		cnpStatusMgr = k8s.NewCNPStatusEventHandler(clientset, cnpStore, cnpStatusUpdateInterval)
		cnpSharedStore, err := store.JoinSharedStore(store.Configuration{
			Prefix: k8s.CNPStatusesPath,
			KeyCreator: func() store.Key {
				return &k8s.CNPNSWithMeta{}
			},
			Observer: cnpStatusMgr,
		})
		if err != nil {
			return err
		}

		// It is safe to update the CNP store here given the CNP Store
		// will only be used by StartStatusHandler method which is used in the
		// cilium v2 controller below.
		cnpStatusMgr.UpdateCNPStore(cnpSharedStore)
	}

	ciliumV2Controller := informer.NewInformerWithStore(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumNetworkPolicyList](clientset.CiliumV2().CiliumNetworkPolicies("")),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				k8sEventMetric(resources.MetricCNP, resources.MetricCreate)
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativeCNPIfNeeded(clientset, cnpCpy.CiliumNetworkPolicy)
					if enableCNPStatusUpdates {
						cnpStatusMgr.StartStatusHandler(cnpCpy)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				k8sEventMetric(resources.MetricCNP, resources.MetricUpdate)
				if oldCNP := k8s.ObjToSlimCNP(oldObj); oldCNP != nil {
					if newCNP := k8s.ObjToSlimCNP(newObj); newCNP != nil {
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
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
				if enableCNPStatusUpdates {
					cnpStatusMgr.StopStatusHandler(cnp)
				}
			},
		},
		k8s.ConvertToCNP,
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
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation(clientset)
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
