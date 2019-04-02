// Copyright 2018-2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

const maxConcurrentUpdates = 4

func init() {
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
}

func enableCNPWatcher() error {

	_, ciliumV2Controller := k8s.NewInformer(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(),
			"ciliumnetworkpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
					if !cnp.RequiresDerivative() {
						log.WithFields(logrus.Fields{
							logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
							logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
						}).Debug("CNP does not have derivative policies, skipped")
						return
					}

					controllerManager.UpdateController(fmt.Sprintf("add-derivative-cnp-%s", cnp.ObjectMeta.Name),
						controller.ControllerParams{
							DoFunc: func(ctx context.Context) error {
								return addDerivativeCNP(cnp.CiliumNetworkPolicy)
							},
						})
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if oldCNP := k8s.CopyObjToV2CNP(oldObj); oldCNP != nil {
					if newCNP := k8s.CopyObjToV2CNP(newObj); newCNP != nil {
						if k8s.EqualV2CNP(oldCNP, newCNP) {
							return
						}

						if !newCNP.RequiresDerivative() {
							if oldCNP.RequiresDerivative() {
								log.WithFields(logrus.Fields{
									logfields.CiliumNetworkPolicyName: newCNP.ObjectMeta.Name,
									logfields.K8sNamespace:            newCNP.ObjectMeta.Namespace,
								}).Info("New CNP does not have derivative policy, but old had. Deleted old policies")

								controllerManager.UpdateController(fmt.Sprintf("delete-derivatve-cnp-%s", oldCNP.ObjectMeta.Name),
									controller.ControllerParams{
										DoFunc: func(ctx context.Context) error {
											return DeleteDerivativeCNP(oldCNP.CiliumNetworkPolicy)
										},
									})
							}

							return
						}

						controllerManager.UpdateController(fmt.Sprintf("CNP-Derivative-update-%s", newCNP.ObjectMeta.Name),
							controller.ControllerParams{
								DoFunc: func(ctx context.Context) error {
									return addDerivativeCNP(newCNP.CiliumNetworkPolicy)
								},
							})
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
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
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
			},
		},
		k8s.ConvertToCNP,
	)
	go ciliumV2Controller.Run(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				// Retrieves all the CNP that has currently a
				// derivative policy and creates the new
				// derivatives policies with the latest
				// information from providers.  To avoid issues
				// with rate-limiting this function will
				// execute the addDerivative function with a
				// max number of concurrent calls, defined on
				// maxConcurrentUpdates.
				cnpToUpdate := cnpCache.GetAllCNP()
				sem := make(chan bool, maxConcurrentUpdates)
				for _, cnp := range cnpToUpdate {
					sem <- true
					go func(cnp *cilium_v2.CiliumNetworkPolicy) {
						defer func() { <-sem }()
						addDerivativeCNP(cnp)
					}(cnp)
				}
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}

var cnpCache = cnpCacheMap{}

type cnpCacheMap struct {
	sync.Map
}

func (cnpCache *cnpCacheMap) UpdateCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Store(cnp.ObjectMeta.UID, cnp)
}

func (cnpCache *cnpCacheMap) DeleteCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Delete(cnp.ObjectMeta.UID)
}

func (cnpCache *cnpCacheMap) GetAllCNP() []*cilium_v2.CiliumNetworkPolicy {
	result := []*cilium_v2.CiliumNetworkPolicy{}
	cnpCache.Range(func(k, v interface{}) bool {
		result = append(result, v.(*cilium_v2.CiliumNetworkPolicy))
		return true
	})
	return result
}
