// Copyright 2018-2020 Authors of Cilium
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
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/groups"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

// enableCCNPWatcher is similar to enableCNPWatcher but handles the watch events for
// clusterwide policies. Since, internally Clusterwide policies are implemented
// using CiliumNetworkPolicy itself, the entire implementation uses the methods
// associcated with CiliumNetworkPolicy.
func enableCCNPWatcher() error {
	log.Info("Starting to garbage collect stale CiliumClusterwideNetworkPolicy status field entries...")

	var (
		ccnpConverterFunc informer.ConvertFunc
		ccnpStatusMgr     *k8s.CCNPStatusEventHandler
	)
	ccnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	switch {
	case k8sversion.Capabilities().Patch:
		// k8s >= 1.13 does not require a store to update CNP status so
		// we don't even need to keep the status of a CNP with us.
		ccnpConverterFunc = k8s.ConvertToCCNP
	default:
		ccnpConverterFunc = k8s.ConvertToCCNPWithStatus
	}

	if kvstoreEnabled() {
		ccnpStatusMgr = k8s.NewCCNPStatusEventHandler(ccnpStore, operatorOption.Config.CNPStatusUpdateInterval)
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
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(),
			cilium_v2.CCNPPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumClusterwideNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {

					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativeCCNPIfNeeded(cnpCpy.CiliumNetworkPolicy)
					if kvstoreEnabled() {
						ccnpStatusMgr.StartStatusHandler(cnpCpy)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
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

						groups.UpdateDerivativeCCNPIfNeeded(newCNPCpy.CiliumNetworkPolicy, oldCNPCpy.CiliumNetworkPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
				if kvstoreEnabled() {
					ccnpStatusMgr.StopStatusHandler(cnp)
				}
			},
		},
		ccnpConverterFunc,
		ccnpStore,
	)
	go ciliumV2Controller.Run(wait.NeverStop)

	controller.NewManager().UpdateController("ccnp-to-groups",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation()
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
