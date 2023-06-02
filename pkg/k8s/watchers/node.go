// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync/atomic"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// RegisterNodeSubscriber allows registration of subscriber.Node implementations.
// On k8s Node events all registered subscriber.Node implementations will
// have their event handling methods called in order of registration.
func (k *K8sWatcher) RegisterNodeSubscriber(s subscriber.Node) {
	k.NodeChain.Register(s)
}

// The NodeUpdate interface is used to provide an abstraction for the
// nodediscovery.NodeDiscovery object logic used to update a node entry in the
// KVStore and the k8s CiliumNode.
type NodeUpdate interface {
	UpdateLocalNode()
}

func nodeEventsAreEqual(oldNode, newNode *slim_corev1.Node) bool {
	if !comparator.MapStringEquals(oldNode.GetLabels(), newNode.GetLabels()) {
		return false
	}

	return true
}

func (k *K8sWatcher) NodesInit(k8sClient client.Clientset) {
	k.nodesInitOnce.Do(func() {
		var synced atomic.Bool
		synced.Store(false)
		swg := lock.NewStoppableWaitGroup()
		k.blockWaitGroupToSyncResources(
			k.stop,
			swg,
			func() bool { return synced.Load() },
			k8sAPIGroupNodeV1Core,
		)
		go k.nodeEventLoop(&synced, swg)
	})
}

func (k *K8sWatcher) nodeEventLoop(synced *atomic.Bool, swg *lock.StoppableWaitGroup) {
	apiGroup := k8sAPIGroupNodeV1Core
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := k.resources.LocalNode.Events(ctx)
	var oldNode *slim_corev1.Node
	for {
		select {
		case <-k.stop:
			cancel()
		case event, ok := <-events:
			if !ok {
				return
			}
			var errs error
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				newNode := event.Object
				if oldNode == nil {
					k.K8sEventReceived(apiGroup, metricNode, resources.MetricCreate, true, false)
					errs = k.NodeChain.OnAddNode(newNode, swg)
					k.K8sEventProcessed(metricNode, resources.MetricCreate, errs == nil)
				} else {
					equal := nodeEventsAreEqual(oldNode, newNode)
					k.K8sEventReceived(apiGroup, metricNode, resources.MetricUpdate, true, equal)
					if !equal {
						errs = k.NodeChain.OnUpdateNode(oldNode, newNode, swg)
						k.K8sEventProcessed(metricNode, resources.MetricUpdate, errs == nil)
					}
				}
				oldNode = newNode
			}
			event.Done(errs)
		}
	}
}

// GetK8sNode returns the *local Node* from the local store.
func (k *K8sWatcher) GetK8sNode(ctx context.Context, nodeName string) (*slim_corev1.Node, error) {
	// Retrieve the store. Blocks until synced (or ctx cancelled).
	store, err := k.resources.LocalNode.Store(ctx)
	if err != nil {
		return nil, err
	}
	node, exists, err := store.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return node.DeepCopy(), nil
}

// ciliumNodeUpdater implements the subscriber.Node interface and is used
// to keep CiliumNode objects in sync with the node ones.
type ciliumNodeUpdater struct {
	kvStoreNodeUpdater NodeUpdate
}

func NewCiliumNodeUpdater(kvStoreNodeUpdater NodeUpdate) *ciliumNodeUpdater {
	return &ciliumNodeUpdater{
		kvStoreNodeUpdater: kvStoreNodeUpdater,
	}
}

func (u *ciliumNodeUpdater) OnAddNode(newNode *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	// We don't need to run OnAddNode because Cilium will fetch the state from
	// k8s upon initialization and will populate the KVStore [1] node with this
	// information or create a Cilium Node CR [2].
	// [1] https://github.com/cilium/cilium/blob/2bea69a54a00f10bec093347900cc66395269154/daemon/cmd/daemon.go#L1102
	// [2] https://github.com/cilium/cilium/blob/2bea69a54a00f10bec093347900cc66395269154/daemon/cmd/daemon.go#L864-L868
	return nil
}

func (u *ciliumNodeUpdater) OnUpdateNode(oldNode, newNode *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	u.updateCiliumNode(newNode)

	return nil
}

func (u *ciliumNodeUpdater) OnDeleteNode(*slim_corev1.Node, *lock.StoppableWaitGroup) error {
	return nil
}

func (u *ciliumNodeUpdater) updateCiliumNode(node *slim_corev1.Node) {
	if node.Name != nodeTypes.GetName() {
		// The cilium node updater should only update the information relevant
		// to itself. It should not update any of the other nodes.
		log.Errorf("BUG: trying to update node %q while we should only update for %q", node.Name, nodeTypes.GetName())
		return
	}

	u.kvStoreNodeUpdater.UpdateLocalNode()
}
