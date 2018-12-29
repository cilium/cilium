// Copyright 2018 Authors of Cilium
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
	"fmt"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	reSyncPeriod         = 5 * time.Minute
	maxConcurrentUpdates = 4
)

var (
	ciliumNPClient *clientset.Clientset
)

func enableCNPWatcher() error {
	restConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration: %s", err)
	}

	ciliumNPClient, err = clientset.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create cilium network policy client: %s", err)
	}

	watcher := k8sUtils.ResourceEventHandlerFactory(
		func(i interface{}) func() error {
			return func() error {
				cnp := i.(*cilium_v2.CiliumNetworkPolicy)
				if !cnp.RequiresDerivative() {
					log.WithFields(logrus.Fields{
						logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
						logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
					}).Debug("CNP does not have derivative policies, skipped")
					return nil
				}

				controllerManager.UpdateController(fmt.Sprintf("add-derivative-cnp-%s", cnp.ObjectMeta.Name),
					controller.ControllerParams{
						DoFunc: func() error {
							return addDerivativeCNP(cnp)
						},
					})

				return nil
			}
		},
		func(i interface{}) func() error {
			return func() error {
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				DeleteDerivativeFromCache(i.(*cilium_v2.CiliumNetworkPolicy))
				return nil
			}
		},
		func(old, new interface{}) func() error {
			return func() error {
				newCNP := new.(*cilium_v2.CiliumNetworkPolicy)
				oldCNP := old.(*cilium_v2.CiliumNetworkPolicy)

				if !newCNP.RequiresDerivative() {
					if oldCNP.RequiresDerivative() {
						log.WithFields(logrus.Fields{
							logfields.CiliumNetworkPolicyName: newCNP.ObjectMeta.Name,
							logfields.K8sNamespace:            newCNP.ObjectMeta.Namespace,
						}).Info("New CNP does not have derivative policy, but old had. Deleted old policies")

						controllerManager.UpdateController(fmt.Sprintf("delete-derivatve-cnp-%s", oldCNP.ObjectMeta.Name),
							controller.ControllerParams{
								DoFunc: func() error {
									return DeleteDerivativeCNP(oldCNP)
								},
							})
					}

					return nil
				}

				controllerManager.UpdateController(fmt.Sprintf("CNP-Derivative-update-%s", newCNP.ObjectMeta.Name),
					controller.ControllerParams{
						DoFunc: func() error {
							return addDerivativeCNP(newCNP)
						},
					})

				return nil
			}
		},
		nil,
		&cilium_v2.CiliumNetworkPolicy{},
		ciliumNPClient,
		reSyncPeriod,
		metrics.EventTSK8s,
	)

	si := informer.NewSharedInformerFactory(ciliumNPClient, reSyncPeriod)
	ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
	ciliumV2Controller.AddEventHandler(watcher)
	si.Start(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func() error {
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
