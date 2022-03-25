// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
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

// The KVStoreNodeUpdater interface is used to provide an abstraction for the
// nodediscovery.NodeDiscovery object logic used to update a node entry in the
// KV store.
type KVStoreNodeUpdater interface {
	UpdateKVNodeEntry(node *nodeTypes.Node) error
}

func nodeEventsAreEqual(oldNode, newNode *v1.Node) bool {
	if !comparator.MapStringEquals(oldNode.GetLabels(), newNode.GetLabels()) {
		return false
	}

	return true
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
							equal = nodeEventsAreEqual(oldNode, newNode)
							if !equal {
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
	k8sWatcher         *K8sWatcher
	kvStoreNodeUpdater KVStoreNodeUpdater
}

func NewCiliumNodeUpdater(k8sWatcher *K8sWatcher, kvStoreNodeUpdater KVStoreNodeUpdater) *ciliumNodeUpdater {
	return &ciliumNodeUpdater{
		k8sWatcher:         k8sWatcher,
		kvStoreNodeUpdater: kvStoreNodeUpdater,
	}
}

func (u *ciliumNodeUpdater) OnAddNode(newNode *v1.Node, swg *lock.StoppableWaitGroup) error {
	u.updateCiliumNode(u.kvStoreNodeUpdater, newNode)

	return nil
}

func (u *ciliumNodeUpdater) OnUpdateNode(oldNode, newNode *v1.Node, swg *lock.StoppableWaitGroup) error {
	u.updateCiliumNode(u.kvStoreNodeUpdater, newNode)

	return nil
}

func (u *ciliumNodeUpdater) OnDeleteNode(*v1.Node, *lock.StoppableWaitGroup) error {
	return nil
}

func (u *ciliumNodeUpdater) updateCiliumNode(kvStoreNodeUpdater KVStoreNodeUpdater, node *v1.Node) {
	var (
		controllerName = fmt.Sprintf("sync-node-with-ciliumnode (%v)", node.Name)

		nodeSlim      = k8s.ConvertToNode(node.DeepCopy()).(*slim_corev1.Node)
		k8sNodeParsed = k8s.ParseNode(nodeSlim, source.Local)
	)

	k8sNodeParsed.NodeIdentity = uint32(identity.ReservedIdentityHost)

	doFunc := func(ctx context.Context) (err error) {
		if option.Config.KVStore != "" && !option.Config.JoinCluster {
			return kvStoreNodeUpdater.UpdateKVNodeEntry(k8sNodeParsed)
		} else {
			u.k8sWatcher.ciliumNodeStoreMU.RLock()
			defer u.k8sWatcher.ciliumNodeStoreMU.RUnlock()

			if u.k8sWatcher.ciliumNodeStore == nil {
				return errors.New("CiliumNode cache store not yet initialized")
			}

			ciliumNodeInterface, exists, err := u.k8sWatcher.ciliumNodeStore.GetByKey(node.Name)
			if err != nil {
				return fmt.Errorf("failed to get CiliumNode resource from cache store: %w", err)
			}
			if !exists {
				return nil
			}

			ciliumNode := ciliumNodeInterface.(*ciliumv2.CiliumNode).DeepCopy()

			ciliumNode.Labels = node.GetLabels()

			if _, err = k8s.CiliumClient().CiliumV2().CiliumNodes().Update(ctx, ciliumNode, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update CiliumNode labels: %w", err)
			}
		}

		return nil
	}

	k8sCM.UpdateController(controllerName,
		controller.ControllerParams{
			DoFunc: doFunc,
		})
}
