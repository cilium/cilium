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
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/togroups"
)

const (
	reSyncPeriod = 1 * time.Second
)

func EnableCNPWatcher() error {

	restConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration: %s", err)
	}

	ciliumNPClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create cilium network policy client: %s", err)
	}

	watcher := k8sUtils.ResourceEventHandlerFactory(
		func(i interface{}) func() error {
			return func() error {
				cnp := i.(*cilium_v2.CiliumNetworkPolicy)
				togroups.AddChildrenCNPIfNeeded(cnp)
				return nil
			}
		},
		func(i interface{}) func() error {
			return func() error {
				cnp := i.(*cilium_v2.CiliumNetworkPolicy)
				togroups.DeleteChildrenCNP(cnp)
				return nil
			}
		},
		func(old, new interface{}) func() error {
			return func() error {
				newCNP := new.(*cilium_v2.CiliumNetworkPolicy)
				oldCNP := old.(*cilium_v2.CiliumNetworkPolicy)
				togroups.UpdateChildrenCNPIfNeeded(newCNP, oldCNP)
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

	return nil
}
