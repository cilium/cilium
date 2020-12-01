// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchers

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
)

func (k *K8sWatcher) ciliumClusterwideNetworkPoliciesInit(ciliumNPClient *k8s.K8sCiliumClient) {
	ccnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	ciliumV2ClusterwidePolicyController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			cilium_v2.CCNPPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricCreate, valid, equal) }()
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {
					valid = true
					if cnp.RequiresDerivative() {
						return
					}

					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					err := k.addCiliumNetworkPolicyV2(ciliumNPClient, cnpCpy)
					k.K8sEventProcessed(metricCCNP, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricUpdate, valid, equal) }()
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

						err := k.updateCiliumNetworkPolicyV2(ciliumNPClient, oldCNPCpy, newCNPCpy)
						k.K8sEventProcessed(metricCCNP, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricDelete, valid, equal) }()
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}
				valid = true
				err := k.deleteCiliumNetworkPolicyV2(cnp)
				k.K8sEventProcessed(metricCCNP, metricDelete, err == nil)
			},
		},
		k8s.ConvertToCCNP,
		ccnpStore,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		ciliumV2ClusterwidePolicyController.HasSynced,
		k8sAPIGroupCiliumClusterwideNetworkPolicyV2,
	)

	go ciliumV2ClusterwidePolicyController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumClusterwideNetworkPolicyV2)
}
