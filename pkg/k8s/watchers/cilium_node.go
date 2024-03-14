// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

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

		// derive another context to signal Events() and Store() in case of kvstore connection
		subCtx, cancel := context.WithCancel(ctx)

		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(stop)

			events := k.resources.CiliumNode.Events(subCtx)
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

		wg.Add(1)
		go func() {
			defer wg.Done()

			store, err := k.resources.CiliumNode.Store(subCtx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.WithError(err).Warning("unable to retrieve CiliumNode local store, going to query kube-apiserver directly")
				}
				return
			}

			k.ciliumNodeStore.Store(&store)

			<-subCtx.Done()

			store.Release()
			k.ciliumNodeStore.Store(nil)
		}()

		select {
		case <-kvstore.Connected():
			log.Info("Connected to key-value store, stopping CiliumNode watcher")
			cancel()
			k.cancelWaitGroupToSyncResources(apiGroup)
			k.k8sAPIGroups.RemoveAPI(apiGroup)
			wg.Wait()
		case <-ctx.Done():
			cancel()
			wg.Wait()
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
	k.nodeManager.NodeUpdated(n)
	return true
}

func (k *K8sWatcher) onCiliumNodeUpdate(oldNode, newNode *cilium_v2.CiliumNode) bool {
	// Comparing Annotations here since wg-pub-key annotation is used to exchange rotated WireGuard keys.
	if oldNode.DeepEqual(newNode) &&
		maps.Equal(oldNode.ObjectMeta.Labels, newNode.ObjectMeta.Labels) &&
		maps.Equal(oldNode.ObjectMeta.Annotations, newNode.ObjectMeta.Annotations) {
		return false
	}
	return k.onCiliumNodeInsert(newNode)
}

func (k *K8sWatcher) onCiliumNodeDelete(ciliumNode *cilium_v2.CiliumNode) {
	if k8s.IsLocalCiliumNode(ciliumNode) {
		return
	}
	n := types.ParseCiliumNode(ciliumNode)
	k.nodeManager.NodeDeleted(n)
}

// GetCiliumNode returns the CiliumNode "nodeName" from the local Resource[T] store. If the
// local Resource[T] store is not initialized or the key value store is connected, then it will
// retrieve the node from kube-apiserver.
// Note that it may be possible (although rare) that the requested nodeName is not yet in the
// store if the local cache is falling behind due to the high amount of CiliumNode events
// received from the k8s API server. To mitigate this, the caller should retry GetCiliumNode
// for a given interval to be sure that a CiliumNode with that name has not actually been created.
func (k *K8sWatcher) GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error) {
	store := k.ciliumNodeStore.Load()
	if store == nil {
		return k.clientset.CiliumV2().CiliumNodes().Get(ctx, nodeName, v1.GetOptions{})
	}

	ciliumNode, exists, err := (*store).GetByKey(resource.Key{Name: nodeName})
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
