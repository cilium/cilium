// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync/atomic"

	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
)

var cesNotify = subscriber.NewCES()

func (k *K8sCiliumEndpointsWatcher) ciliumEndpointSliceInit(ctx context.Context) {
	k.logger.Info("Initializing CES controller")

	// Register for all ces updates.
	cesNotify.Register(newCESSubscriber(k.logger, k))

	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		ctx.Done(),
		nil,
		func() bool { return synced.Load() },
		k8sAPIGroupCiliumEndpointSliceV2Alpha1,
	)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointSliceV2Alpha1)

	go func() {
		events := k.resources.CiliumEndpointSlice.Events(ctx)
		cache := make(map[resource.Key]*cilium_api_v2a1.CiliumEndpointSlice)
		for event := range events {
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				var needUpdate bool
				oldObj, ok := cache[event.Key]
				if !ok {
					cesNotify.NotifyAdd(event.Object)
					needUpdate = true
				} else if !oldObj.DeepEqual(event.Object) {
					cesNotify.NotifyUpdate(oldObj, event.Object)
					needUpdate = true
				}
				if needUpdate {
					cache[event.Key] = event.Object
				}
			case resource.Delete:
				cesNotify.NotifyDelete(event.Object)
				delete(cache, event.Key)
			}
			event.Done(nil)
		}
	}()
}
