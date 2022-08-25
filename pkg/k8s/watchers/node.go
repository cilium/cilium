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

// The NodeUpdate interface is used to provide an abstraction for the
// nodediscovery.NodeDiscovery object logic used to update a node entry in the
// KVStore and the k8s CiliumNode.
type NodeUpdate interface {
	UpdateLocalNode()
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

func (u *ciliumNodeUpdater) OnAddNode(newNode *v1.Node, swg *lock.StoppableWaitGroup) error {
	// We don't need to run OnAddNode because Cilium will fetch the state from
	// k8s upon initialization and will populate the KVStore [1] node with this
	// information or create a Cilium Node CR [2].
	// [1] https://github.com/cilium/cilium/blob/2bea69a54a00f10bec093347900cc66395269154/daemon/cmd/daemon.go#L1102
	// [2] https://github.com/cilium/cilium/blob/2bea69a54a00f10bec093347900cc66395269154/daemon/cmd/daemon.go#L864-L868
	return nil
}

func (u *ciliumNodeUpdater) OnUpdateNode(oldNode, newNode *v1.Node, swg *lock.StoppableWaitGroup) error {
	u.updateCiliumNode(newNode)

	return nil
}

func (u *ciliumNodeUpdater) OnDeleteNode(*v1.Node, *lock.StoppableWaitGroup) error {
	return nil
}

func (u *ciliumNodeUpdater) updateCiliumNode(node *v1.Node) {
	if node.Name != nodeTypes.GetName() {
		// The cilium node updater should only update the information relevant
		// to itself. It should not update any of the other nodes.
		log.Errorf("BUG: trying to update node %q while we should only update for %q", node.Name, nodeTypes.GetName())
		return
	}

	u.kvStoreNodeUpdater.UpdateLocalNode()
}
