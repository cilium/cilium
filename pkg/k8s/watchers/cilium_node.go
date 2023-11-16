// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/node/types"
)

func (k *K8sWatcher) ciliumNodeInit(ctx context.Context, asyncControllers *sync.WaitGroup) {
	// CiliumNode objects are used for node discovery until the key-value
	// store is connected
	var once sync.Once
	apiGroup := k8sAPIGroupCiliumNodeV2

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

			events := k.resources.CiliumNode.Events(eventsCtx)

			// Set forceCiliumNodeFromApiServer to false so that any attempts of getting the
			// CiliumNode go through the Resource[T] cache.
			// This must be done only after Events() is called, since Resource[CiliumNode] is
			// marked as stoppable.
			k.forceCiliumNodeFromApiServer.Store(false)

			cache := make(map[resource.Key]*cilium_v2.CiliumNode)
			for event := range events {
				var err error
				switch event.Kind {
				case resource.Sync:
					synced.Store(true)
				case resource.Upsert:
					var needUpdate bool
					oldObj, ok := cache[event.Key]
					if !ok {
						needUpdate = k.onCiliumNodeInsert(event.Object)
					} else {
						needUpdate = k.onCiliumNodeUpdate(oldObj, event.Object)
					}
					if needUpdate {
						cache[event.Key] = event.Object.DeepCopy()
					}
				case resource.Delete:
					k.onCiliumNodeDelete(event.Object)
					delete(cache, event.Key)
				}
				event.Done(err)
			}
		}()

		select {
		case <-kvstore.Connected():
			log.Info("Connected to key-value store, stopping CiliumNode watcher")
			cancel()
			// Set forceCiliumNodeFromApiServer to true so that any attempts of getting the
			// CiliumNode are performed with a request sent to kube-apiserver directly instead
			// of relying on an outdated version of the CiliumNode in the Resource[T] cache.
			k.forceCiliumNodeFromApiServer.Store(true)
			k.cancelWaitGroupToSyncResources(apiGroup)
			k.k8sAPIGroups.RemoveAPI(apiGroup)
		case <-ctx.Done():
			cancel()
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-kvstore.Client().Disconnected():
			log.Info("Disconnected from key-value store, restarting CiliumNode watcher")
		}
	}
}

func (k *K8sWatcher) onCiliumNodeInsert(ciliumNode *cilium_v2.CiliumNode) bool {
	if k8s.IsLocalCiliumNode(ciliumNode) {
		return false
	}
	n := types.ParseCiliumNode(ciliumNode)
	k.nodeDiscoverManager.NodeUpdated(n)
	return true
}

func (k *K8sWatcher) onCiliumNodeUpdate(oldNode, newNode *cilium_v2.CiliumNode) bool {
	// Comparing Annotations here since wg-pub-key annotation is used to exchange rotated WireGuard keys.
	if oldNode.DeepEqual(newNode) &&
		comparator.MapStringEquals(oldNode.ObjectMeta.Labels, newNode.ObjectMeta.Labels) &&
		comparator.MapStringEquals(oldNode.ObjectMeta.Annotations, newNode.ObjectMeta.Annotations) {
		return false
	}
	return k.onCiliumNodeInsert(newNode)
}

func (k *K8sWatcher) onCiliumNodeDelete(ciliumNode *cilium_v2.CiliumNode) {
	n := types.ParseCiliumNode(ciliumNode)
	k.nodeDiscoverManager.NodeDeleted(n)
}

// GetCiliumNode returns the CiliumNode "nodeName" from the local Resource[T] store. If the
// local Resource[T] store is not initialized then it will fallback retrieving the node
// from kube-apiserver.
func (k *K8sWatcher) GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error) {
	// If the key-value store is connected or if we still haven't subscribed to the resource events stream,
	// we cannot rely on the CiliumNode Resource[T] local cache, thus we call the kube-apiserver directly.
	if k.forceCiliumNodeFromApiServer.Load() {
		return k.clientset.CiliumV2().CiliumNodes().Get(ctx, nodeName, v1.GetOptions{})
	}

	// Resource[T] ensures that the underlying cache is synced before returning from the call to Store().
	store, err := k.resources.CiliumNode.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve CiliumNode store: %w", err)
	}
	ciliumNode, exists, err := store.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return nil, fmt.Errorf("unable to get CiliumNode %s from local store: %w", nodeName, err)
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "cilium",
			Resource: "CiliumNode",
		}, nodeName)
	}
	return ciliumNode.DeepCopy(), nil
}
