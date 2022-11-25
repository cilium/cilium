// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discoveryv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// SharedResourceCell provides a set of shared handles to Kubernetes resources used throughout the
	// Cilium agent. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	SharedResourcesCell = cell.Module(
		"k8s-shared-resources",
		"Shared Kubernetes resources",

		cell.Provide(
			serviceResource,
			localNodeResource,
			namespaceResource,
			lbIPPoolsResource,
			endpointsResource,
		),
	)
)

type SharedResources struct {
	cell.In
	LocalNode  resource.Resource[*corev1.Node]
	Services   resource.Resource[*slim_corev1.Service]
	Namespaces resource.Resource[*slim_corev1.Namespace]
	LBIPPools  resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	Endpoints  resource.Resource[*Endpoints]
}

func serviceResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*slim_corev1.Service], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
	if err != nil {
		return nil, err
	}
	lw := utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](cs.Slim().CoreV1().Services(""))
	lw = utils.ListerWatcherWithModifier(lw, optsModifier)
	return resource.New[*slim_corev1.Service](lc, lw), nil
}

func localNodeResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return resource.New[*corev1.Node](lc, lw), nil
}

func namespaceResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*slim_corev1.Namespace], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](cs.Slim().CoreV1().Namespaces())
	return resource.New[*slim_corev1.Namespace](lc, lw), nil
}

func lbIPPoolsResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](
		cs.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
	)
	return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](lc, lw), nil
}

// endpointsListerWatcher implements List and Watch for endpoints/endpointslices. It
// performs the capability check on first call to List/Watch. This allows constructing
// the resource before the client has been started and capabilities have been probed.
type endpointsListerWatcher struct {
	cs client.Clientset

	once                sync.Once
	cachedListerWatcher cache.ListerWatcher
}

func (lw *endpointsListerWatcher) getListerWatcher() (k8sRuntime.Object, cache.ListerWatcher) {
	var obj k8sRuntime.Object
	lw.once.Do(func() {
		if SupportsEndpointSlice() {
			if SupportsEndpointSliceV1() {
				log.Infof("Using discoveryv1.EndpointSlice")
				lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_discoveryv1.EndpointSliceList](
					lw.cs.Slim().DiscoveryV1().EndpointSlices(""),
				)
				obj = &slim_discoveryv1.EndpointSlice{}
			} else {
				log.Infof("Using discoveryv1beta1.EndpointSlice")
				lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_discoveryv1beta1.EndpointSliceList](
					lw.cs.Slim().DiscoveryV1beta1().EndpointSlices(""),
				)
				obj = &slim_discoveryv1beta1.EndpointSlice{}
			}
		} else {
			log.Infof("Using v1.Endpoints")
			lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_corev1.EndpointsList](
				lw.cs.Slim().CoreV1().Endpoints(""),
			)
			obj = &slim_corev1.Endpoints{}
		}
	})
	return obj, lw.cachedListerWatcher
}

func (elw *endpointsListerWatcher) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	_, lw := elw.getListerWatcher()
	return lw.List(opts)
}

func (elw *endpointsListerWatcher) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	_, lw := elw.getListerWatcher()
	return lw.Watch(opts)
}

func transformEndpoint(obj any) (any, error) {
	switch obj := obj.(type) {
	case *slim_corev1.Endpoints:
		_, eps := ParseEndpoints(obj)
		return eps, nil
	case *slim_discoveryv1.EndpointSlice:
		_, eps := ParseEndpointSliceV1(obj)
		return eps, nil
	case *slim_discoveryv1beta1.EndpointSlice:
		_, eps := ParseEndpointSliceV1Beta1(obj)
		return eps, nil
	default:
		return nil, fmt.Errorf("%T not a known endpoint or endpoint slice object", obj)
	}
}

func endpointsResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*Endpoints], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	elw := &endpointsListerWatcher{cs: cs}
	obj, _ := elw.getListerWatcher() // FIXME clean this up

	return resource.New[*Endpoints](
		lc,
		elw,
		resource.WithTransform(obj, transformEndpoint),
	), nil
}
