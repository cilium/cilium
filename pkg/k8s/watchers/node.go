// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"

	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	// onceNodeInitStart is used to guarantee that only one function call of
	// NodesInit is executed.
	onceNodeInitStart sync.Once
)

// RegisterNodeSubscriber allows registration of subscriber.Node implementations.
// On k8s Node events all registered subscriber.Node implementations will
// have their event handling methods called in order of registration.
func (k *K8sWatcher) RegisterNodeSubscriber(s subscriber.Node) {
	k.NodeChain.Register(s)
}

func (k *K8sWatcher) NodesInit(k8sClient *k8s.K8sClient) {
	onceNodeInitStart.Do(func() {
		swg := lock.NewStoppableWaitGroup()

		nodeStore, nodeController := informer.NewInformer(
			cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
				"nodes", v1.NamespaceAll, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName())),
			&v1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid bool
					if node := k8s.ObjToV1Node(obj); node != nil {
						valid = true
						if hasAgentNotReadyTaint(node) || !k8s.HasCiliumIsUpCondition(node) {
							k8sClient.ReMarkNodeReady()
						}
						errs := k.NodeChain.OnAddNode(node, swg)
						k.K8sEventProcessed(metricNode, metricCreate, errs == nil)
					}
					k.K8sEventReceived(metricNode, metricCreate, valid, false)
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					if oldNode := k8s.ObjToV1Node(oldObj); oldNode != nil {
						valid = true
						if newNode := k8s.ObjToV1Node(newObj); newNode != nil {
							if hasAgentNotReadyTaint(newNode) || !k8s.HasCiliumIsUpCondition(newNode) {
								k8sClient.ReMarkNodeReady()
							}

							oldNodeLabels := oldNode.GetLabels()
							newNodeLabels := newNode.GetLabels()
							if comparator.MapStringEquals(oldNodeLabels, newNodeLabels) {
								equal = true
							} else {
								errs := k.NodeChain.OnUpdateNode(oldNode, newNode, swg)
								k.K8sEventProcessed(metricNode, metricUpdate, errs == nil)
							}
						}
					}
					k.K8sEventReceived(metricNode, metricUpdate, valid, equal)
				},
				DeleteFunc: func(obj interface{}) {
				},
			},
			nil,
		)

		k.nodeStore = nodeStore

		k.blockWaitGroupToSyncResources(wait.NeverStop, swg, nodeController.HasSynced, k8sAPIGroupNodeV1Core)
		go nodeController.Run(k.stop)
		k.k8sAPIGroups.AddAPI(k8sAPIGroupNodeV1Core)
	})
}

// hasAgentNotReadyTaint returns true if the given node has the Cilium Agen
// Not Ready Node Taint.
func hasAgentNotReadyTaint(k8sNode *v1.Node) bool {
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key == ciliumio.AgentNotReadyNodeTaint {
			return true
		}
	}
	return false
}

// GetK8sNode returns the *local Node* from the local store.
func (k *K8sWatcher) GetK8sNode(_ context.Context, nodeName string) (*v1.Node, error) {
	k.WaitForCacheSync(k8sAPIGroupNodeV1Core)
	pName := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}
	nodeInterface, exists, err := k.nodeStore.Get(pName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*v1.Node).DeepCopy(), nil
}
