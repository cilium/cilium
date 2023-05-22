// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/node"
)

var (
	cesNotify = subscriber.NewCES()
)

// CreateCiliumEndpointSliceLocalPodIndexFunc returns an IndexFunc that indexes CiliumEndpointSlices
// by their corresponding Pod, which are running locally on this Node.
func CreateCiliumEndpointSliceLocalPodIndexFunc() cache.IndexFunc {
	nodeIP := node.GetCiliumEndpointNodeIP()
	return func(obj interface{}) ([]string, error) {
		ces, ok := obj.(*v2alpha1.CiliumEndpointSlice)
		if !ok {
			return nil, fmt.Errorf("unexpected object type: %T", obj)
		}
		indices := []string{}
		for _, ep := range ces.Endpoints {
			if ep.Networking.NodeIP == nodeIP {
				indices = append(indices, ep.Networking.NodeIP)
				break
			}
		}
		return indices, nil
	}
}

func (k *K8sWatcher) ciliumEndpointSliceInit(client client.Clientset, asyncControllers *sync.WaitGroup) {
	log.Info("Initializing CES controller")
	var once sync.Once

	// Register for all ces updates.
	cesNotify.Register(newCESSubscriber(k))

	for {
		cesIndexer, cesInformer := informer.NewIndexerInformer(
			utils.ListerWatcherFromTyped[*cilium_v2a1.CiliumEndpointSliceList](
				client.CiliumV2alpha1().CiliumEndpointSlices()),
			&cilium_v2a1.CiliumEndpointSlice{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if ces := k8s.ObjToCiliumEndpointSlice(obj); ces != nil {
						cesNotify.NotifyAdd(ces)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if oldCES := k8s.ObjToCiliumEndpointSlice(oldObj); oldCES != nil {
						if newCES := k8s.ObjToCiliumEndpointSlice(newObj); newCES != nil {
							if oldCES.DeepEqual(newCES) {
								return
							}
							cesNotify.NotifyUpdate(oldCES, newCES)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					if ces := k8s.ObjToCiliumEndpointSlice(obj); ces != nil {
						cesNotify.NotifyDelete(ces)
					}
				},
			},
			nil,
			cache.Indexers{
				"localNode": CreateCiliumEndpointSliceLocalPodIndexFunc(),
			},
		)
		k.ciliumEndpointSliceIndexerMU.Lock()
		k.ciliumEndpointSliceIndexer = cesIndexer
		k.ciliumEndpointSliceIndexerMU.Unlock()
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(
			isConnected,
			nil,
			cesInformer.HasSynced,
			k8sAPIGroupCiliumEndpointSliceV2Alpha1,
		)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointSliceV2Alpha1)
		go cesInformer.Run(isConnected)

		<-kvstore.Connected()
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumEndpointSlice watcher")
		k.k8sAPIGroups.RemoveAPI(k8sAPIGroupCiliumEndpointSliceV2Alpha1)
		k.cancelWaitGroupToSyncResources(k8sAPIGroupCiliumEndpointSliceV2Alpha1)
		<-kvstore.Client().Disconnected()
		log.Info("Disconnected from key-value store, restarting CiliumEndpointSlice watcher")
	}
}
