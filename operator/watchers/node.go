// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"sync"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var (
	// nodeSyncOnce is used to make sure nodesInit is only setup once.
	nodeSyncOnce sync.Once

	// slimNodeStore contains all cluster nodes store as slim_core.Node
	slimNodeStore cache.Store

	// slimNodeStoreSynced is closed once the slimNodeStore is synced
	// with k8s.
	slimNodeStoreSynced = make(chan struct{})

	nodeController cache.Controller

	nodeQueue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "node-queue")
)

// NodeQueueShutDown is a wrapper to expose ShutDown for the global nodeQueue.
// It is meant to be used in unit test like the identity-gc one in operator/identity/
// in order to avoid goleak complaining about leaked goroutines.
func NodeQueueShutDown() {
	nodeQueue.ShutDown()
}

type slimNodeGetter interface {
	GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error)
	ListK8sSlimNode() []*slim_corev1.Node
}

type nodeGetter struct{}

// GetK8sSlimNode returns a slim_corev1.Node from the local store.
// The return structure should only be used for read purposes and should never
// be written into it.
func (nodeGetter) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	nodeInterface, exists, err := slimNodeStore.GetByKey(nodeName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*slim_corev1.Node), nil
}

func (nodeGetter) ListK8sSlimNode() []*slim_corev1.Node {
	nodesInt := slimNodeStore.List()
	out := make([]*slim_corev1.Node, 0, len(nodesInt))
	for i := range nodesInt {
		out = append(out, nodesInt[i].(*slim_corev1.Node))
	}
	return out
}

// nodesInit starts up a node watcher to handle node events.
func nodesInit(wg *sync.WaitGroup, slimClient slimclientset.Interface, stopCh <-chan struct{}) {
	nodeSyncOnce.Do(func() {
		slimNodeStore, nodeController = informer.NewInformer(
			utils.ListerWatcherFromTyped[*slim_corev1.NodeList](slimClient.CoreV1().Nodes()),
			&slim_corev1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					key, _ := queueKeyFunc(obj)
					nodeQueue.Add(key)
				},
				UpdateFunc: func(_, newObj interface{}) {
					key, _ := queueKeyFunc(newObj)
					nodeQueue.Add(key)
				},
			},
			convertToNode,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer nodeQueue.ShutDown()
			nodeController.Run(stopCh)
		}()

		cache.WaitForCacheSync(stopCh, nodeController.HasSynced)
		close(slimNodeStoreSynced)
	})
}

func convertToNode(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Node:
		n := &slim_corev1.Node{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: slim_corev1.NodeSpec{
				Taints: concreteObj.Spec.Taints,
			},
			Status: slim_corev1.NodeStatus{
				Conditions: concreteObj.Status.Conditions,
			},
		}
		*concreteObj = slim_corev1.Node{}
		return n
	case cache.DeletedFinalStateUnknown:
		node, ok := concreteObj.Obj.(*slim_corev1.Node)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Node{
				TypeMeta: node.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            node.Name,
					ResourceVersion: node.ResourceVersion,
				},
				Spec: slim_corev1.NodeSpec{
					Taints: node.Spec.Taints,
				},
				Status: slim_corev1.NodeStatus{
					Conditions: node.Status.Conditions,
				},
			},
		}
		// Small GC optimization
		*node = slim_corev1.Node{}
		return dfsu
	default:
		return obj
	}
}
