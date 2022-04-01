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
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/kvstore"
)

// RegisterCiliumEndpointSubscriber allows registration of
// subscriber.CiliumEndpoint implementations.  On CiliumEndpoint events all
// registered subscriber.CiliumEndpoint implementations will have their event
// handling methods called in order of registration.
func (k *K8sWatcher) RegisterCiliumEndpointSubscriber(s subscriber.CiliumEndpoint) {
	k.CiliumEndpointChain.Register(s)
}

func (k *K8sWatcher) ciliumEndpointsInit(ciliumNPClient *k8s.K8sCiliumClient, asyncControllers *sync.WaitGroup) {
	// CiliumEndpoint objects are used for ipcache discovery until the
	// key-value store is connected
	var once sync.Once
	for {
		_, ciliumEndpointInformer := informer.NewInformer(
			cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
				cilium_v2.CEPPluralName, v1.NamespaceAll, fields.Everything()),
			&cilium_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricCreate, valid, equal) }()
					if ciliumEndpoint, ok := obj.(*types.CiliumEndpoint); ok {
						valid = true
						err := k.CiliumEndpointChain.OnAddCiliumEndpoint(ciliumEndpoint)
						k.K8sEventProcessed(metricCiliumEndpoint, metricCreate, err == nil)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricUpdate, valid, equal) }()
					if oldCE := k8s.ObjToCiliumEndpoint(oldObj); oldCE != nil {
						if newCE := k8s.ObjToCiliumEndpoint(newObj); newCE != nil {
							valid = true
							if oldCE.DeepEqual(newCE) {
								equal = true
								return
							}
							err := k.CiliumEndpointChain.OnUpdateCiliumEndpoint(oldCE, newCE)
							k.K8sEventProcessed(metricCiliumEndpoint, metricUpdate, err == nil)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricDelete, valid, equal) }()
					ciliumEndpoint := k8s.ObjToCiliumEndpoint(obj)
					if ciliumEndpoint == nil {
						return
					}
					valid = true
					k.CiliumEndpointChain.OnDeleteCiliumEndpoint(ciliumEndpoint)
				},
			},
			k8s.ConvertToCiliumEndpoint,
		)
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, nil, ciliumEndpointInformer.HasSynced, k8sAPIGroupCiliumEndpointV2)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointV2)
		go ciliumEndpointInformer.Run(isConnected)

		<-kvstore.Connected()
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumEndpoint watcher")

		k.k8sAPIGroups.RemoveAPI(k8sAPIGroupCiliumEndpointV2)
		k.cancelWaitGroupToSyncResources(k8sAPIGroupCiliumEndpointV2)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumEndpoint watcher")
	}
}
