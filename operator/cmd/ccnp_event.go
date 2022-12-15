// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"sync"
	"time"

	"k8s.io/client-go/tools/cache"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/groups"
)

func k8sEventMetric(scope, action string) {
	metrics.EventTS.WithLabelValues(metrics.LabelEventSourceK8s, scope, action).SetToCurrentTime()
}

// enableCCNPWatcher is similar to enableCNPWatcher but handles the watch events for
// clusterwide policies. Since, internally Clusterwide policies are implemented
// using CiliumNetworkPolicy itself, the entire implementation uses the methods
// associcated with CiliumNetworkPolicy.
func enableCCNPWatcher(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) error {
	enableCNPStatusUpdates := kvstoreEnabled() && option.Config.K8sEventHandover && !option.Config.DisableCNPStatusUpdates
	if enableCNPStatusUpdates {
		log.Info("Starting a CCNP Status handover from kvstore to k8s")
	}
	log.Info("Starting CCNP derivative handler")

	var (
		ccnpStatusMgr *k8s.CCNPStatusEventHandler
	)
	ccnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	if enableCNPStatusUpdates {
		ccnpStatusMgr = k8s.NewCCNPStatusEventHandler(clientset, ccnpStore, operatorOption.Config.CNPStatusUpdateInterval)
		ccnpSharedStore, err := store.JoinSharedStore(store.Configuration{
			Prefix: k8s.CCNPStatusesPath,
			KeyCreator: func() store.Key {
				return &k8s.CNPNSWithMeta{}
			},
			Observer: ccnpStatusMgr,
		})
		if err != nil {
			return err
		}

		// It is safe to update the CCNP store here given the CCNP Store
		// will only be used by StartStatusHandler method which is used in the
		// cilium v2 controller below.
		ccnpStatusMgr.UpdateCNPStore(ccnpSharedStore)
	}

	ciliumV2Controller := informer.NewInformerWithStore(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumClusterwideNetworkPolicyList](clientset.CiliumV2().CiliumClusterwideNetworkPolicies()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricCreate)
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativeCCNPIfNeeded(clientset, cnpCpy.CiliumNetworkPolicy)
					if enableCNPStatusUpdates {
						ccnpStatusMgr.StartStatusHandler(cnpCpy)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricUpdate)
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

						groups.UpdateDerivativeCCNPIfNeeded(clientset, newCNPCpy.CiliumNetworkPolicy, oldCNPCpy.CiliumNetworkPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				k8sEventMetric(resources.MetricCCNP, resources.MetricDelete)
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
				if enableCNPStatusUpdates {
					ccnpStatusMgr.StopStatusHandler(cnp)
				}
			},
		},
		k8s.ConvertToCCNP,
		ccnpStore,
	)
	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ciliumV2Controller.Run(ctx.Done())
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController("ccnp-to-groups",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation(clientset)
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
