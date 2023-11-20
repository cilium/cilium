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
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
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
	return comparator.MapStringEquals(oldNode.GetLabels(), newNode.GetLabels()) &&
		comparator.MapStringEquals(oldNode.GetAnnotations(), newNode.GetAnnotations())
}

func (k *K8sWatcher) NodesInit(k8sClient client.Clientset) {
	k.nodesInitOnce.Do(func() {
		var synced atomic.Bool
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
					k.k8sResourceSynced.SetEventTimestamp(apiGroup)
					errs = k.NodeChain.OnAddNode(newNode, swg)
				} else {
					equal := nodeEventsAreEqual(oldNode, newNode)
					k.k8sResourceSynced.SetEventTimestamp(apiGroup)
					if !equal {
						errs = k.NodeChain.OnUpdateNode(oldNode, newNode, swg)
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
