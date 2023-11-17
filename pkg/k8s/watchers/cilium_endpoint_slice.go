// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"
	"sync/atomic"

	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/kvstore"
)

var (
	cesNotify = subscriber.NewCES()
)

func (k *K8sWatcher) ciliumEndpointSliceInit(ctx context.Context, asyncControllers *sync.WaitGroup) {
	log.Info("Initializing CES controller")

	var once sync.Once
	apiGroup := k8sAPIGroupCiliumEndpointSliceV2Alpha1

	// Register for all ces updates.
	cesNotify.Register(newCESSubscriber(k))

	for {
		var synced atomic.Bool
		stop := make(chan struct{})

		k.blockWaitGroupToSyncResources(
			stop,
			nil,
			func() bool { return synced.Load() },
			apiGroup,
		)
		k.k8sAPIGroups.AddAPI(apiGroup)

		// Signalize that we have put node controller in the wait group to sync resources.
		once.Do(asyncControllers.Done)

		// derive another context to signal Events() in case of kvstore connection
		eventsCtx, cancel := context.WithCancel(ctx)

		go func() {
			defer close(stop)

			events := k.resources.CiliumEndpointSlice.Events(eventsCtx)
			cache := make(map[resource.Key]*cilium_api_v2a1.CiliumEndpointSlice)
			for event := range events {
				var err error
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
				event.Done(err)
			}
		}()

		select {
		case <-kvstore.Connected():
			log.Info("Connected to key-value store, stopping CiliumEndpointSlice watcher")
			cancel()
			k.cancelWaitGroupToSyncResources(apiGroup)
			k.k8sAPIGroups.RemoveAPI(apiGroup)
			<-stop
		case <-ctx.Done():
			cancel()
			<-stop
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-kvstore.Client().Disconnected():
			log.Info("Disconnected from key-value store, restarting CiliumEndpointSlice watcher")
		}
	}
}
