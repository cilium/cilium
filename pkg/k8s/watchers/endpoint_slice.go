// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

package watchers

import (
	"sync"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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
				k.updateK8sEndpointSliceV1(k8sEP, swgEps)
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

					k.updateK8sEndpointSliceV1(newk8sEP, swgEps)
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
				k.updateK8sEndpointSliceV1Beta1(k8sEP, swgEps)
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

					k.updateK8sEndpointSliceV1Beta1(newk8sEP, swgEps)
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
	if eps == nil || eps.Name != "kubernetes" {
		return
	}

	// We must perform a diff on the ipcache.IdentityMetadata map in order to
	// figure out which IPs are stale and should be removed, before we inject
	// new IPs into the ipcache. The reason is because kube-apiserver will
	// constantly reconcile this specific object, even when it's been deleted;
	// effectively, this means we can avoid listening for the delete event.
	// Therefore, any changes to this specific object can be handled in a
	// "flattened" manner, since the most up-to-date form of it will be an add
	// or update event. The former is sent when Cilium is syncing with K8s and
	// the latter is sent anytime after.
	//
	// For example:
	//   * if a backend is removed or updated, then this will be in the form of
	//     an update event.
	//   * if the entire object is deleted, then it will quickly be recreated
	//     and this will be in the form of an add event.

	ips := ipcache.FilterMetadataByLabels(labels.LabelKubeAPIServer)
	currentIPs := make(map[string]struct{}, len(ips))
	for _, v := range ips {
		currentIPs[v] = struct{}{}
	}

	desiredIPs := make(map[string]struct{}, len(currentIPs))
	for _, e := range eps.Endpoints {
		for _, addr := range e.Addresses {
			desiredIPs[addr] = struct{}{}
		}
	}

	toRemove := make(map[string]labels.Labels)
	for ip := range currentIPs {
		if _, ok := desiredIPs[ip]; !ok {
			toRemove[ip] = labels.LabelKubeAPIServer
		}
	}
	ipcache.RemoveAllPrefixesWithLabels(
		toRemove,
		source.CustomResource,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)

	for ip := range desiredIPs {
		ipcache.UpsertMetadata(ip, labels.LabelKubeAPIServer)
	}

	// Use CustomResource as the source similar to the way the CiliumNode
	// (pkg/node/manager.Manager) handler does because the ipcache entry needs
	// to be overwrite-able by this handler and the CiliumNode handler. If we
	// used Kubernetes as the source, then the ipcache entries inserted (first)
	// by the CN handler wouldn't be overwrite-able by the entries inserted
	// from this handler.
	ipcache.IPIdentityCache.TriggerLabelInjection(
		source.CustomResource,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)
}

func (k *K8sWatcher) addKubeAPIServerServiceEPSliceV1Beta1(eps *slim_discover_v1beta1.EndpointSlice) {
	if eps == nil || eps.Name != "kubernetes" {
		return
	}

	// See comment in addKubeAPIServerServiceEPSliceV1().

	ips := ipcache.FilterMetadataByLabels(labels.LabelKubeAPIServer)
	currentIPs := make(map[string]struct{}, len(ips))
	for _, v := range ips {
		currentIPs[v] = struct{}{}
	}

	desiredIPs := make(map[string]struct{}, len(currentIPs))
	for _, e := range eps.Endpoints {
		for _, addr := range e.Addresses {
			desiredIPs[addr] = struct{}{}
		}
	}

	toRemove := make(map[string]labels.Labels)
	for ip := range currentIPs {
		if _, ok := desiredIPs[ip]; !ok {
			toRemove[ip] = labels.LabelKubeAPIServer
		}
	}
	ipcache.RemoveAllPrefixesWithLabels(
		toRemove,
		source.CustomResource,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)

	for ip := range desiredIPs {
		ipcache.UpsertMetadata(ip, labels.LabelKubeAPIServer)
	}

	// Use CustomResource as the source similar to the way the CiliumNode
	// (pkg/node/manager.Manager) handler does because the ipcache entry needs
	// to be overwrite-able by this handler and the CiliumNode handler. If we
	// used Kubernetes as the source, then the ipcache entries inserted (first)
	// by the CN handler wouldn't be overwrite-able by the entries inserted
	// from this handler.
	ipcache.IPIdentityCache.TriggerLabelInjection(
		source.CustomResource,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)
}

// initEndpointsOrSlices initializes either the "Endpoints" or "EndpointSlice"
// resources for Kubernetes service backends.
func (k *K8sWatcher) initEndpointsOrSlices(k8sClient kubernetes.Interface, serviceOptModifier func(*v1meta.ListOptions)) {
	swgEps := lock.NewStoppableWaitGroup()
	switch {
	case k8s.SupportsEndpointSlice():
		// We don't add the service option modifier here, as endpointslices do not
		// mirror service proxy name label present in the corresponding service.
		connected := k.endpointSlicesInit(k8sClient, swgEps)
		// The cluster has endpoint slices so we should not check for v1.Endpoints
		if connected {
			break
		}
		fallthrough
	default:
		k.endpointsInit(k8sClient, swgEps, serviceOptModifier)
	}
}
