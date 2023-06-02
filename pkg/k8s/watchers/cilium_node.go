// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// RegisterCiliumNodeSubscriber allows registration of subscriber.CiliumNode implementations.
// On CiliumNode events all registered subscriber.CiliumNode implementations will
// have their event handling methods called in order of registration.
func (k *K8sWatcher) RegisterCiliumNodeSubscriber(s subscriber.CiliumNode) {
	k.CiliumNodeChain.Register(s)
}

func (k *K8sWatcher) ciliumNodeInit(ciliumNPClient client.Clientset, asyncControllers *sync.WaitGroup) {
	// CiliumNode objects are used for node discovery until the key-value
	// store is connected
	var once sync.Once
	apiGroup := k8sAPIGroupCiliumNodeV2
	for {
		swgNodes := lock.NewStoppableWaitGroup()
		ciliumNodeStore, ciliumNodeInformer := informer.NewInformer(
			utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](ciliumNPClient.CiliumV2().CiliumNodes()),
			&cilium_v2.CiliumNode{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(apiGroup, metricCiliumNode, resources.MetricCreate, valid, equal) }()
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						valid = true
						n := nodeTypes.ParseCiliumNode(ciliumNode)
						errs := k.CiliumNodeChain.OnAddCiliumNode(ciliumNode, swgNodes)
						if k.egressGatewayManager != nil {
							k.egressGatewayManager.OnUpdateNode(n)
						}
						if n.IsLocal() {
							return
						}
						k.nodeDiscoverManager.NodeUpdated(n)
						k.K8sEventProcessed(metricCiliumNode, resources.MetricCreate, errs == nil)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(apiGroup, metricCiliumNode, resources.MetricUpdate, valid, equal) }()
					if oldCN := k8s.ObjToCiliumNode(oldObj); oldCN != nil {
						if ciliumNode := k8s.ObjToCiliumNode(newObj); ciliumNode != nil {
							valid = true
							isLocal := k8s.IsLocalCiliumNode(ciliumNode)
							// Comparing Annotations here since wg-pub-key annotation is used to exchange rotated Wireguard keys.
							if oldCN.DeepEqual(ciliumNode) &&
								comparator.MapStringEquals(oldCN.ObjectMeta.Labels, ciliumNode.ObjectMeta.Labels) &&
								comparator.MapStringEquals(oldCN.ObjectMeta.Annotations, ciliumNode.ObjectMeta.Annotations) {
								equal = true
								if !isLocal {
									// For remote nodes, we return early here to avoid unnecessary update events if
									// nothing in the spec or status has changed. But for local nodes, we want to
									// propagate the new resource version (not compared in DeepEqual) such that any
									// CiliumNodeChain subscribers are able to perform updates to the local CiliumNode
									// object using the most recent resource version.
									return
								}
							}
							n := nodeTypes.ParseCiliumNode(ciliumNode)
							errs := k.CiliumNodeChain.OnUpdateCiliumNode(oldCN, ciliumNode, swgNodes)
							if k.egressGatewayManager != nil {
								k.egressGatewayManager.OnUpdateNode(n)
							}
							if isLocal {
								return
							}
							k.nodeDiscoverManager.NodeUpdated(n)
							k.K8sEventProcessed(metricCiliumNode, resources.MetricUpdate, errs == nil)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(apiGroup, metricCiliumNode, resources.MetricDelete, valid, equal) }()
					ciliumNode := k8s.ObjToCiliumNode(obj)
					if ciliumNode == nil {
						return
					}
					valid = true
					n := nodeTypes.ParseCiliumNode(ciliumNode)
					if k.egressGatewayManager != nil {
						k.egressGatewayManager.OnDeleteNode(n)
					}
					errs := k.CiliumNodeChain.OnDeleteCiliumNode(ciliumNode, swgNodes)
					if errs != nil {
						valid = false
					}
					k.nodeDiscoverManager.NodeDeleted(n)
				},
			},
			k8s.ConvertToCiliumNode,
		)
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, swgNodes, ciliumNodeInformer.HasSynced, apiGroup)

		k.ciliumNodeStoreMU.Lock()
		k.ciliumNodeStore = ciliumNodeStore
		k.ciliumNodeStoreMU.Unlock()

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.AddAPI(apiGroup)
		go ciliumNodeInformer.Run(isConnected)

		<-kvstore.Connected()
		log.Info("Connected to key-value store, stopping CiliumNode watcher")

		// Set the ciliumNodeStore as nil so that any attempts of getting the
		// CiliumNode are performed with a request sent to kube-apiserver
		// directly instead of relying on an outdated version of the CiliumNode
		// in this cache.
		k.ciliumNodeStoreMU.Lock()
		k.ciliumNodeStore = nil
		k.ciliumNodeStoreMU.Unlock()

		close(isConnected)

		k.cancelWaitGroupToSyncResources(apiGroup)
		k.k8sAPIGroups.RemoveAPI(apiGroup)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumNode watcher")
	}
}

// GetCiliumNode returns the CiliumNode "nodeName" from the local store. If the
// local store is not initialized then it will fallback retrieving the node
// from kube-apiserver.
func (k *K8sWatcher) GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error) {
	var (
		err                      error
		nodeInterface            interface{}
		exists, getFromAPIServer bool
	)
	k.ciliumNodeStoreMU.RLock()
	// k.ciliumNodeStore might not be set in all invocations of GetCiliumNode,
	// for example, during Cilium initialization GetCiliumNode is called from
	// WaitForNodeInformation, which happens before ciliumNodeStore,
	// so we will fallback to perform an API request to kube-apiserver.
	if k.ciliumNodeStore == nil {
		getFromAPIServer = true
	} else {
		nodeInterface, exists, err = k.ciliumNodeStore.GetByKey(nodeName)
	}
	k.ciliumNodeStoreMU.RUnlock()

	if !exists || getFromAPIServer {
		// fallback to using the kube-apiserver
		return k.clientset.CiliumV2().CiliumNodes().Get(ctx, nodeName, v1.GetOptions{})
	}

	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "cilium",
			Resource: "CiliumNode",
		}, nodeName)
	}
	return nodeInterface.(*cilium_v2.CiliumNode).DeepCopy(), nil
}
