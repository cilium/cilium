// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchers

import (
	"context"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/source"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEndpointsInit(ciliumNPClient *k8s.K8sCiliumClient, serCiliumEndpoints *serializer.FunctionQueue, asyncControllers *sync.WaitGroup) {
	// CiliumEndpoint objects are used for ipcache discovery until the
	// key-value store is connected
	var once sync.Once
	for {
		swgCiliumEndpoints := lock.NewStoppableWaitGroup()
		_, ciliumEndpointInformer := informer.NewInformer(
			cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
				"ciliumendpoints", v1.NamespaceAll, fields.Everything()),
			&cilium_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricCreate, valid, equal) }()
					if ciliumEndpoint, ok := obj.(*types.CiliumEndpoint); ok {
						valid = true
						endpoint := ciliumEndpoint.DeepCopy()
						swgCiliumEndpoints.Add()
						serCiliumEndpoints.Enqueue(func() error {
							defer swgCiliumEndpoints.Done()
							endpointUpdated(endpoint)
							k.K8sEventProcessed(metricCiliumEndpoint, metricCreate, true)
							return nil
						}, serializer.NoRetry)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricUpdate, valid, equal) }()
					if ciliumEndpoint, ok := newObj.(*types.CiliumEndpoint); ok {
						valid = true
						endpoint := ciliumEndpoint.DeepCopy()
						swgCiliumEndpoints.Add()
						serCiliumEndpoints.Enqueue(func() error {
							defer swgCiliumEndpoints.Done()
							endpointUpdated(endpoint)
							k.K8sEventProcessed(metricCiliumEndpoint, metricUpdate, true)
							return nil
						}, serializer.NoRetry)
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(metricCiliumEndpoint, metricDelete, valid, equal) }()
					ciliumEndpoint := k8s.CopyObjToCiliumEndpoint(obj)
					if ciliumEndpoint == nil {
						deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							return
						}
						// Delete was not observed by the watcher but is
						// removed from kube-apiserver. This is the last
						// known state and the object no longer exists.
						ciliumEndpoint = k8s.CopyObjToCiliumEndpoint(deletedObj.Obj)
						if ciliumEndpoint == nil {
							return
						}
					}
					valid = true
					swgCiliumEndpoints.Add()
					serCiliumEndpoints.Enqueue(func() error {
						defer swgCiliumEndpoints.Done()
						endpointDeleted(ciliumEndpoint)
						return nil
					}, serializer.NoRetry)
				},
			},
			k8s.ConvertToCiliumEndpoint,
		)
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, swgCiliumEndpoints, ciliumEndpointInformer, k8sAPIGroupCiliumEndpointV2)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.addAPI(k8sAPIGroupCiliumEndpointV2)
		go ciliumEndpointInformer.Run(isConnected)

		<-kvstore.Client().Connected(context.TODO())
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumEndpoint watcher")

		k.k8sAPIGroups.removeAPI(k8sAPIGroupCiliumEndpointV2)
		k.cancelWaitGroupToSyncResources(k8sAPIGroupCiliumEndpointV2)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumEndpoint watcher")
	}
}

func endpointUpdated(endpoint *types.CiliumEndpoint) {
	// default to the standard key
	encryptionKey := node.GetIPsecKeyIdentity()

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
	}

	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	if endpoint.Networking != nil {
		if endpoint.Networking.NodeIP == "" {
			// When upgrading from an older version, the nodeIP may
			// not be available yet in the CiliumEndpoint and we
			// have to wait for it to be propagated
			return
		}

		nodeIP := net.ParseIP(endpoint.Networking.NodeIP)
		if nodeIP == nil {
			log.WithField("nodeIP", endpoint.Networking.NodeIP).Warning("Unable to parse node IP while processing CiliumEndpoint update")
			return
		}

		k8sMeta := &ipcache.K8sMetadata{
			Namespace: endpoint.Namespace,
			PodName:   endpoint.Name,
		}

		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				ipcache.IPIdentityCache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
					ipcache.Identity{ID: id, Source: source.CustomResource})
			}

			if pair.IPV6 != "" {
				ipcache.IPIdentityCache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
					ipcache.Identity{ID: id, Source: source.CustomResource})
			}
		}
	}
}

func endpointDeleted(endpoint *types.CiliumEndpoint) {
	if endpoint.Networking != nil {
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				ipcache.IPIdentityCache.Delete(pair.IPV4, source.CustomResource)
			}

			if pair.IPV6 != "" {
				ipcache.IPIdentityCache.Delete(pair.IPV6, source.CustomResource)
			}
		}
	}
}
