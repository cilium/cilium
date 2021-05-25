// Copyright 2019-2021 Authors of Cilium
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
	"sync"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/lock"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// endpointSlicesInit returns true if the cluster contains endpoint slices.
func (k *K8sWatcher) endpointSlicesInit(k8sClient kubernetes.Interface, swgEps *lock.StoppableWaitGroup) bool {
	var (
		hasEndpointSlices = make(chan struct{})
		once              sync.Once
		esClient          rest.Interface
		objType           runtime.Object
		addFunc, delFunc  func(obj interface{})
		updateFunc        func(oldObj, newObj interface{})
		apiGroup          string
	)

	if k8s.SupportsEndpointSliceV1() {
		apiGroup = K8sAPIGroupEndpointSliceV1Discovery
		esClient = k8sClient.DiscoveryV1().RESTClient()
		objType = &slim_discover_v1.EndpointSlice{}
		addFunc = func(obj interface{}) {
			once.Do(func() {
				// signalize that we have received an endpoint slice
				// so it means the cluster has endpoint slices enabled.
				close(hasEndpointSlices)
			})
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricCreate, valid, equal) }()
			if k8sEP := k8s.ObjToV1EndpointSlice(obj); k8sEP != nil {
				valid = true
				k.K8sSvcCache.UpdateEndpointSlicesV1(k8sEP, swgEps)
				k.K8sEventProcessed(metricEndpointSlice, metricCreate, true)
			}
		}
		updateFunc = func(oldObj, newObj interface{}) {
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricUpdate, valid, equal) }()
			if oldk8sEP := k8s.ObjToV1EndpointSlice(oldObj); oldk8sEP != nil {
				if newk8sEP := k8s.ObjToV1EndpointSlice(newObj); newk8sEP != nil {
					valid = true
					if oldk8sEP.DeepEqual(newk8sEP) {
						equal = true
						return
					}

					k.K8sSvcCache.UpdateEndpointSlicesV1(newk8sEP, swgEps)
					k.K8sEventProcessed(metricEndpointSlice, metricUpdate, true)
				}
			}
		}
		delFunc = func(obj interface{}) {
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricDelete, valid, equal) }()
			k8sEP := k8s.ObjToV1EndpointSlice(obj)
			if k8sEP == nil {
				return
			}
			valid = true
			k.K8sSvcCache.DeleteEndpointSlices(k8sEP, swgEps)
			k.K8sEventProcessed(metricEndpointSlice, metricDelete, true)
		}
	} else {
		apiGroup = K8sAPIGroupEndpointSliceV1Beta1Discovery
		esClient = k8sClient.DiscoveryV1beta1().RESTClient()
		objType = &slim_discover_v1beta1.EndpointSlice{}
		addFunc = func(obj interface{}) {
			once.Do(func() {
				// signalize that we have received an endpoint slice
				// so it means the cluster has endpoint slices enabled.
				close(hasEndpointSlices)
			})
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricCreate, valid, equal) }()
			if k8sEP := k8s.ObjToV1Beta1EndpointSlice(obj); k8sEP != nil {
				valid = true
				k.K8sSvcCache.UpdateEndpointSlicesV1Beta1(k8sEP, swgEps)
				k.K8sEventProcessed(metricEndpointSlice, metricCreate, true)
			}
		}
		updateFunc = func(oldObj, newObj interface{}) {
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricUpdate, valid, equal) }()
			if oldk8sEP := k8s.ObjToV1Beta1EndpointSlice(oldObj); oldk8sEP != nil {
				if newk8sEP := k8s.ObjToV1Beta1EndpointSlice(newObj); newk8sEP != nil {
					valid = true
					if oldk8sEP.DeepEqual(newk8sEP) {
						equal = true
						return
					}

					k.K8sSvcCache.UpdateEndpointSlicesV1Beta1(newk8sEP, swgEps)
					k.K8sEventProcessed(metricEndpointSlice, metricUpdate, true)
				}
			}
		}
		delFunc = func(obj interface{}) {
			var valid, equal bool
			defer func() { k.K8sEventReceived(metricEndpointSlice, metricDelete, valid, equal) }()
			k8sEP := k8s.ObjToV1Beta1EndpointSlice(obj)
			if k8sEP == nil {
				return
			}
			valid = true
			k.K8sSvcCache.DeleteEndpointSlices(k8sEP, swgEps)
			k.K8sEventProcessed(metricEndpointSlice, metricDelete, true)
		}
	}

	_, endpointController := informer.NewInformer(
		cache.NewListWatchFromClient(esClient,
			"endpointslices", v1.NamespaceAll, fields.Everything()),
		objType,
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    addFunc,
			UpdateFunc: updateFunc,
			DeleteFunc: delFunc,
		},
		nil,
	)
	ecr := make(chan struct{})
	k.blockWaitGroupToSyncResources(ecr, swgEps, endpointController.HasSynced, apiGroup)
	go endpointController.Run(ecr)
	k.k8sAPIGroups.AddAPI(apiGroup)

	if k8s.HasEndpointSlice(hasEndpointSlices, endpointController) {
		return true
	}

	// K8s is not running with endpoint slices enabled, stop the endpoint slice
	// controller to avoid watching for unnecessary stuff in k8s.
	k.k8sAPIGroups.RemoveAPI(apiGroup)
	close(ecr)
	return false
}
