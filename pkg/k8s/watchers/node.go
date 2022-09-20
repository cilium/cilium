// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
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

func nodeEventsAreEqual(oldNode, newNode *v1.Node) bool {
	if !comparator.MapStringEquals(oldNode.GetLabels(), newNode.GetLabels()) {
		return false
	}

	return true
}

func (k *K8sWatcher) NodesInit(k8sClient *k8s.K8sClient) {
	apiGroup := k8sAPIGroupNodeV1Core
	k.nodesInitOnce.Do(func() {
		swg := lock.NewStoppableWaitGroup()

		nodeStore, nodeController := informer.NewInformer(
			utils.ListerWatcherWithFields(
				utils.ListerWatcherFromTyped[*v1.NodeList](k8sClient.CoreV1().Nodes()),
				fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName())),
			&v1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid bool
					if node := k8s.ObjToV1Node(obj); node != nil {
						valid = true
						errs := k.NodeChain.OnAddNode(node, swg)
						k.K8sEventProcessed(metricNode, resources.MetricCreate, errs == nil)
					}
					k.K8sEventReceived(apiGroup, metricNode, resources.MetricCreate, valid, false)
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					if oldNode := k8s.ObjToV1Node(oldObj); oldNode != nil {
						valid = true
						if newNode := k8s.ObjToV1Node(newObj); newNode != nil {
							equal = nodeEventsAreEqual(oldNode, newNode)
							if !equal {
								errs := k.NodeChain.OnUpdateNode(oldNode, newNode, swg)
								k.K8sEventProcessed(metricNode, resources.MetricCreate, errs == nil)
							}
						}
					}
					k.K8sEventReceived(apiGroup, metricNode, resources.MetricCreate, valid, false)
				},
				DeleteFunc: func(obj interface{}) {
				},
			},
			nil,
		)

		k.nodeStore = nodeStore

		k.blockWaitGroupToSyncResources(wait.NeverStop, swg, nodeController.HasSynced, k8sAPIGroupNodeV1Core)
		go nodeController.Run(k.stop)
		k.k8sAPIGroups.AddAPI(apiGroup)
	})
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
