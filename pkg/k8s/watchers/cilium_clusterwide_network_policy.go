// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
)

func (k *K8sWatcher) ciliumClusterwideNetworkPoliciesInit(ciliumNPClient client.Clientset) {
	apiGroup := k8sAPIGroupCiliumClusterwideNetworkPolicyV2
	_, ciliumV2ClusterwidePolicyController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumClusterwideNetworkPolicyList](
			ciliumNPClient.CiliumV2().CiliumClusterwideNetworkPolicies()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				initialRecvTime := time.Now()
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(apiGroup, resources.MetricCCNP, resources.MetricCreate, valid, equal)
				}()
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
					valid = true
					if cnp.RequiresDerivative() {
						return
					}

					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					err := k.addCiliumNetworkPolicyV2(ciliumNPClient, cnpCpy, initialRecvTime)
					k.K8sEventProcessed(resources.MetricCCNP, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				initialRecvTime := time.Now()
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricCCNP, resources.MetricUpdate, valid, equal) }()
				if oldCNP := k8s.ObjToSlimCNP(oldObj); oldCNP != nil {
					if newCNP := k8s.ObjToSlimCNP(newObj); newCNP != nil {
						valid = true
						if oldCNP.DeepEqual(newCNP) {
							equal = true
							return
						}

						if newCNP.RequiresDerivative() {
							return
						}

						// We need to deepcopy this structure because we are writing
						// fields.
						// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
						oldCNPCpy := oldCNP.DeepCopy()
						newCNPCpy := newCNP.DeepCopy()

						err := k.updateCiliumNetworkPolicyV2(ciliumNPClient, oldCNPCpy, newCNPCpy, initialRecvTime)
						k.K8sEventProcessed(resources.MetricCCNP, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricCCNP, resources.MetricDelete, valid, equal) }()
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}
				valid = true
				err := k.deleteCiliumNetworkPolicyV2(cnp)
				k.K8sEventProcessed(resources.MetricCCNP, resources.MetricDelete, err == nil)
			},
		},
		k8s.ConvertToCCNP,
	)

	k.blockWaitGroupToSyncResources(
		k.stop,
		nil,
		ciliumV2ClusterwidePolicyController.HasSynced,
		apiGroup,
	)

	go ciliumV2ClusterwidePolicyController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(apiGroup)
}
