// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nm "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/node/types"
)

type k8sCiliumNodeWatcherParams struct {
	cell.In

	Logger *slog.Logger

	Clientset         k8sClient.Clientset
	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	NodeManager nm.NodeManager
}

func newK8sCiliumNodeWatcher(params k8sCiliumNodeWatcherParams) *K8sCiliumNodeWatcher {
	return &K8sCiliumNodeWatcher{
		logger:            params.Logger,
		clientset:         params.Clientset,
		k8sResourceSynced: params.K8sResourceSynced,
		k8sAPIGroups:      params.K8sAPIGroups,
		resources:         params.Resources,
		nodeManager:       params.NodeManager,
	}
}

type K8sCiliumNodeWatcher struct {
	logger *slog.Logger

	clientset k8sClient.Clientset

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources
	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups
	resources    agentK8s.Resources

	nodeManager nodeManager

	ciliumNodeStore atomic.Pointer[resource.Store[*cilium_v2.CiliumNode]]
}

func (k *K8sCiliumNodeWatcher) ciliumNodeInit(ctx context.Context) {
	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		ctx.Done(),
		nil,
		func() bool { return synced.Load() },
		k8sAPIGroupCiliumNodeV2,
	)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumNodeV2)

	go func() {
		events := k.resources.CiliumNode.Events(ctx)
		cache := make(map[resource.Key]*cilium_v2.CiliumNode)
		for event := range events {
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
				k.nodeManager.NodeSync()

				// The informer just synchronized, so the Store call will not block.
				store, err := k.resources.CiliumNode.Store(ctx)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						k.logger.Warn("unable to retrieve CiliumNode local store, going to query kube-apiserver directly", logfields.Error, err)
					}
				} else {
					k.ciliumNodeStore.Store(&store)
				}

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
			event.Done(nil)
		}
	}()
}

func (k *K8sCiliumNodeWatcher) onCiliumNodeInsert(ciliumNode *cilium_v2.CiliumNode) bool {
	if k8s.IsLocalCiliumNode(ciliumNode) {
		return false
	}
	n := types.ParseCiliumNode(ciliumNode)
	k.nodeManager.NodeUpdated(n)
	return true
}

func (k *K8sCiliumNodeWatcher) onCiliumNodeUpdate(oldNode, newNode *cilium_v2.CiliumNode) bool {
	// Comparing Annotations here since wg-pub-key annotation is used to exchange rotated WireGuard keys.
	if oldNode.DeepEqual(newNode) &&
		maps.Equal(oldNode.ObjectMeta.Labels, newNode.ObjectMeta.Labels) &&
		maps.Equal(oldNode.ObjectMeta.Annotations, newNode.ObjectMeta.Annotations) {
		return false
	}
	return k.onCiliumNodeInsert(newNode)
}

func (k *K8sCiliumNodeWatcher) onCiliumNodeDelete(ciliumNode *cilium_v2.CiliumNode) {
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
func (k *K8sCiliumNodeWatcher) GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error) {
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
