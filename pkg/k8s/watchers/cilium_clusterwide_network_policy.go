// Copyright 2016-2019 Authors of Cilium
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
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/serializer"
)

func (k *K8sWatcher) ciliumClusterwideNetworkPoliciesInit(ciliumNPClient *k8s.K8sCiliumClient, serCCNPs *serializer.FunctionQueue, swgCCNPs *lock.StoppableWaitGroup) {
	var (
		ccnpEventStore    cache.Store
		ccnpConverterFunc informer.ConvertFunc
	)
	ccnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	switch {
	case k8sversion.Capabilities().Patch:
		// k8s >= 1.13 does not require a store to update CNP status so
		// we don't even need to keep the status of a CNP with us.
		ccnpConverterFunc = k8s.ConvertToCNP
	default:
		ccnpEventStore = ccnpStore
		ccnpConverterFunc = k8s.ConvertToCNPWithStatus
	}

	ciliumV2ClusterwidePolicyController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			"ciliumclusterwidenetworkpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricCreate, valid, equal) }()
				if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
					valid = true
					swgCCNPs.Add()
					serCCNPs.Enqueue(func() error {
						defer swgCCNPs.Done()
						if cnp.RequiresDerivative() {
							return nil
						}
						err := k.addCiliumNetworkPolicyV2(ciliumNPClient, ccnpEventStore, cnp)
						k.K8sEventProcessed(metricCCNP, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricUpdate, valid, equal) }()
				if oldCNP := k8s.CopyObjToV2CNP(oldObj); oldCNP != nil {
					valid = true
					if newCNP := k8s.CopyObjToV2CNP(newObj); newCNP != nil {
						if k8s.EqualV2CNP(oldCNP, newCNP) {
							equal = true
							return
						}

						swgCCNPs.Add()
						serCCNPs.Enqueue(func() error {
							defer swgCCNPs.Done()
							if newCNP.RequiresDerivative() {
								return nil
							}

							err := k.updateCiliumNetworkPolicyV2(ciliumNPClient, ccnpEventStore, oldCNP, newCNP)
							k.K8sEventProcessed(metricCCNP, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCCNP, metricDelete, valid, equal) }()
				cnp := k8s.CopyObjToV2CNP(obj)
				if cnp == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					cnp = k8s.CopyObjToV2CNP(deletedObj.Obj)
					if cnp == nil {
						return
					}
				}
				valid = true
				swgCCNPs.Add()
				serCCNPs.Enqueue(func() error {
					defer swgCCNPs.Done()
					err := k.deleteCiliumNetworkPolicyV2(cnp)
					k.K8sEventProcessed(metricCCNP, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		ccnpConverterFunc,
		ccnpStore,
	)
	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		swgCCNPs,
		ciliumV2ClusterwidePolicyController,
		k8sAPIGroupCiliumClusterwideNetworkPolicyV2,
	)

	go ciliumV2ClusterwidePolicyController.Run(wait.NeverStop)
	k.k8sAPIGroups.addAPI(k8sAPIGroupCiliumClusterwideNetworkPolicyV2)
}
