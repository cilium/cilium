// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func (k *K8sWatcher) ciliumNodeInit(ciliumNPClient *k8s.K8sCiliumClient, asyncControllers *sync.WaitGroup) {
	// CiliumNode objects are used for node discovery until the key-value
	// store is connected
	var once sync.Once
	for {
		swgNodes := lock.NewStoppableWaitGroup()
		_, ciliumNodeInformer := informer.NewInformer(
			cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
				cilium_v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
			&cilium_v2.CiliumNode{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricCreate, valid, equal) }()
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						valid = true
						n := nodeTypes.ParseCiliumNode(ciliumNode)
						errs := k.CiliumNodeChain.OnAddCiliumNode(ciliumNode, swgNodes)
						if n.IsLocal() {
							return
						}
						k.nodeDiscoverManager.NodeUpdated(n)
						k.K8sEventProcessed(metricCiliumNode, metricCreate, errs == nil)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricUpdate, valid, equal) }()
					if oldCN := k8s.ObjToCiliumNode(oldObj); oldCN != nil {
						if ciliumNode := k8s.ObjToCiliumNode(newObj); ciliumNode != nil {
							valid = true
							if oldCN.DeepEqual(ciliumNode) {
								equal = true
								return
							}
							n := nodeTypes.ParseCiliumNode(ciliumNode)
							errs := k.CiliumNodeChain.OnUpdateCiliumNode(oldCN, ciliumNode, swgNodes)
							if n.IsLocal() {
								return
							}
							k.nodeDiscoverManager.NodeUpdated(n)
							k.K8sEventProcessed(metricCiliumNode, metricUpdate, errs == nil)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumNode, metricDelete, valid, equal) }()
					ciliumNode := k8s.ObjToCiliumNode(obj)
					if ciliumNode == nil {
						return
					}
					valid = true
					n := nodeTypes.ParseCiliumNode(ciliumNode)
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
		k.blockWaitGroupToSyncResources(isConnected, swgNodes, ciliumNodeInformer.HasSynced, k8sAPIGroupCiliumNodeV2)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumNodeV2)
		go ciliumNodeInformer.Run(isConnected)

		<-kvstore.Connected()
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumNode watcher")

		k.cancelWaitGroupToSyncResources(k8sAPIGroupCiliumNodeV2)
		k.k8sAPIGroups.RemoveAPI(k8sAPIGroupCiliumNodeV2)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumNode watcher")
	}
}
