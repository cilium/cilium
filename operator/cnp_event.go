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
	"time"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/groups"

	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	reSyncPeriod = 5 * time.Minute
)

func enableCNPWatcher() error {
	watcher := k8sUtils.ResourceEventHandlerFactory(
		func(i interface{}) func() error {
			return func() error {
				cnp := i.(*cilium_v2.CiliumNetworkPolicy)
				groups.AddDerivativeCNPIfNeeded(cnp)
				return nil
			}
		},
		func(i interface{}) func() error {
			return func() error {
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(i.(*cilium_v2.CiliumNetworkPolicy))
				return nil
			}
		},
		func(old, new interface{}) func() error {
			return func() error {
				newCNP := new.(*cilium_v2.CiliumNetworkPolicy)
				oldCNP := old.(*cilium_v2.CiliumNetworkPolicy)
				groups.UpdateDerivativeCNPIfNeeded(newCNP, oldCNP)
				return nil
			}
		},
		nil,
		&cilium_v2.CiliumNetworkPolicy{},
		ciliumK8sClient,
		reSyncPeriod,
		metrics.EventTSK8s,
	)

	si := informer.NewSharedInformerFactory(ciliumK8sClient, reSyncPeriod)
	ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
	ciliumV2Controller.AddEventHandler(watcher)
	si.Start(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func() error {
				groups.UpdateCNPInformation()
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
