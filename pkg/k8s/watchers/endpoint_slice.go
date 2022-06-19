// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"net/netip"
	"sync"

	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

// endpointSlicesInit returns true if the cluster contains endpoint slices.
func (k *K8sWatcher) endpointSlicesInit(slimClient slimclientset.Interface, swgEps *lock.StoppableWaitGroup) bool {
	var (
		hasEndpointSlices = make(chan struct{})
		once              sync.Once
		esLW              cache.ListerWatcher
		objType           runtime.Object
		addFunc, delFunc  func(obj interface{})
		updateFunc        func(oldObj, newObj interface{})
		apiGroup          string
	)

	if k8s.SupportsEndpointSliceV1() {
		apiGroup = resources.K8sAPIGroupEndpointSliceV1Discovery
		esLW = utils.ListerWatcherFromTyped[*slim_discover_v1.EndpointSliceList](
			slimClient.DiscoveryV1().EndpointSlices(""))
		objType = &slim_discover_v1.EndpointSlice{}
		addFunc = func(obj interface{}) {
			once.Do(func() {
				// signalize that we have received an endpoint slice
				// so it means the cluster has endpoint slices enabled.
				close(hasEndpointSlices)
			})
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricCreate, valid, equal)
			}()
			if k8sEP := k8s.ObjToV1EndpointSlice(obj); k8sEP != nil {
				valid = true
				k.updateK8sEndpointSliceV1(k8sEP, swgEps)
				k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricCreate, true)
			}
		}
		updateFunc = func(oldObj, newObj interface{}) {
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricUpdate, valid, equal)
			}()
			if oldk8sEP := k8s.ObjToV1EndpointSlice(oldObj); oldk8sEP != nil {
				if newk8sEP := k8s.ObjToV1EndpointSlice(newObj); newk8sEP != nil {
					valid = true
					if oldk8sEP.DeepEqual(newk8sEP) {
						equal = true
						return
					}

					k.updateK8sEndpointSliceV1(newk8sEP, swgEps)
					k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricUpdate, true)
				}
			}
		}
		delFunc = func(obj interface{}) {
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricDelete, valid, equal)
			}()
			k8sEP := k8s.ObjToV1EndpointSlice(obj)
			if k8sEP == nil {
				return
			}
			valid = true
			k.K8sSvcCache.DeleteEndpointSlices(k8sEP, swgEps)
			k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricDelete, true)
		}
	} else {
		apiGroup = resources.K8sAPIGroupEndpointSliceV1Beta1Discovery
		esLW = utils.ListerWatcherFromTyped[*slim_discover_v1beta1.EndpointSliceList](
			slimClient.DiscoveryV1beta1().EndpointSlices(""))
		objType = &slim_discover_v1beta1.EndpointSlice{}
		addFunc = func(obj interface{}) {
			once.Do(func() {
				// signalize that we have received an endpoint slice
				// so it means the cluster has endpoint slices enabled.
				close(hasEndpointSlices)
			})
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricCreate, valid, equal)
			}()
			if k8sEP := k8s.ObjToV1Beta1EndpointSlice(obj); k8sEP != nil {
				valid = true
				k.updateK8sEndpointSliceV1Beta1(k8sEP, swgEps)
				k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricCreate, true)
			}
		}
		updateFunc = func(oldObj, newObj interface{}) {
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricUpdate, valid, equal)
			}()
			if oldk8sEP := k8s.ObjToV1Beta1EndpointSlice(oldObj); oldk8sEP != nil {
				if newk8sEP := k8s.ObjToV1Beta1EndpointSlice(newObj); newk8sEP != nil {
					valid = true
					if oldk8sEP.DeepEqual(newk8sEP) {
						equal = true
						return
					}

					k.updateK8sEndpointSliceV1Beta1(newk8sEP, swgEps)
					k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricUpdate, true)
				}
			}
		}
		delFunc = func(obj interface{}) {
			var valid, equal bool
			defer func() {
				k.K8sEventReceived(apiGroup, resources.MetricEndpointSlice, resources.MetricDelete, valid, equal)
			}()
			k8sEP := k8s.ObjToV1Beta1EndpointSlice(obj)
			if k8sEP == nil {
				return
			}
			valid = true
			k.K8sSvcCache.DeleteEndpointSlices(k8sEP, swgEps)
			k.K8sEventProcessed(resources.MetricEndpointSlice, resources.MetricDelete, true)
		}
	}

	_, endpointController := informer.NewInformer(
		esLW,
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
	k.cancelWaitGroupToSyncResources(apiGroup)
	k.k8sAPIGroups.RemoveAPI(apiGroup)
	close(ecr)
	return false
}

func (k *K8sWatcher) updateK8sEndpointSliceV1(eps *slim_discover_v1.EndpointSlice, swgEps *lock.StoppableWaitGroup) {
	k.K8sSvcCache.UpdateEndpointSlicesV1(eps, swgEps)

	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateEndpointSliceV1(eps)
	}

	k.addKubeAPIServerServiceEPSliceV1(eps)
}

func (k *K8sWatcher) updateK8sEndpointSliceV1Beta1(eps *slim_discover_v1beta1.EndpointSlice, swgEps *lock.StoppableWaitGroup) {
	k.K8sSvcCache.UpdateEndpointSlicesV1Beta1(eps, swgEps)

	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateEndpointSliceV1Beta1(eps)
	}

	k.addKubeAPIServerServiceEPSliceV1Beta1(eps)
}

func (k *K8sWatcher) addKubeAPIServerServiceEPSliceV1(eps *slim_discover_v1.EndpointSlice) {
	if eps == nil ||
		eps.GetLabels()[slim_discover_v1.LabelServiceName] != "kubernetes" ||
		eps.Namespace != "default" {
		return
	}

	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpointSlice,
		eps.ObjectMeta.GetNamespace(),
		eps.ObjectMeta.GetName(),
	)
	desiredIPs := make(map[netip.Prefix]struct{})
	for _, e := range eps.Endpoints {
		for _, addr := range e.Addresses {
			insertK8sPrefix(desiredIPs, addr, resource)
		}
	}
	k.handleKubeAPIServerServiceEPChanges(desiredIPs, resource)
}

func (k *K8sWatcher) addKubeAPIServerServiceEPSliceV1Beta1(eps *slim_discover_v1beta1.EndpointSlice) {
	if eps == nil ||
		eps.GetLabels()[slim_discover_v1beta1.LabelServiceName] != "kubernetes" ||
		eps.Namespace != "default" {
		return
	}

	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpointSlicev1beta1,
		eps.ObjectMeta.GetNamespace(),
		eps.ObjectMeta.GetName(),
	)
	desiredIPs := make(map[netip.Prefix]struct{})
	for _, e := range eps.Endpoints {
		for _, addr := range e.Addresses {
			insertK8sPrefix(desiredIPs, addr, resource)
		}
	}
	k.handleKubeAPIServerServiceEPChanges(desiredIPs, resource)
}

// initEndpointsOrSlices initializes either the "Endpoints" or "EndpointSlice"
// resources for Kubernetes service backends.
func (k *K8sWatcher) initEndpointsOrSlices(slimClient slimclientset.Interface, serviceOptModifier func(*v1meta.ListOptions)) {
	swgEps := lock.NewStoppableWaitGroup()
	switch {
	case k8s.SupportsEndpointSlice():
		// We don't add the service option modifier here, as endpointslices do not
		// mirror service proxy name label present in the corresponding service.
		connected := k.endpointSlicesInit(slimClient, swgEps)
		// The cluster has endpoint slices so we should not check for v1.Endpoints
		if connected {
			break
		}
		fallthrough
	default:
		k.endpointsInit(slimClient, swgEps, serviceOptModifier)
	}
}
