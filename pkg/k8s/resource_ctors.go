// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discoveryv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

func ServiceResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Service], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
	if err != nil {
		return nil, err
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](cs.Slim().CoreV1().Services("")),
		append(opts, optsModifier)...,
	)
	return resource.New[*slim_corev1.Service](lc, lw), nil
}

func NodeResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](cs.Slim().CoreV1().Nodes()),
		opts...,
	)
	return resource.New[*slim_corev1.Node](lc, lw), nil
}

func CiliumNodeResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](lc, lw), nil
}

func PodResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Pod], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.PodList](cs.Slim().CoreV1().Pods("")),
		opts...,
	)
	return resource.New[*slim_corev1.Pod](lc, lw), nil
}

func NamespaceResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Namespace], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](cs.Slim().CoreV1().Namespaces()),
		opts...,
	)
	return resource.New[*slim_corev1.Namespace](lc, lw), nil
}

func LBIPPoolsResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](cs.CiliumV2alpha1().CiliumLoadBalancerIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](lc, lw), nil
}

func CiliumIdentityResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](cs.CiliumV2().CiliumIdentities()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumIdentity](lc, lw), nil
}

func CiliumNetworkPolicyResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNetworkPolicyList](cs.CiliumV2().CiliumNetworkPolicies("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNetworkPolicy](lc, lw), nil
}

func CiliumClusterwideNetworkPolicyResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideNetworkPolicyList](cs.CiliumV2().CiliumClusterwideNetworkPolicies()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumClusterwideNetworkPolicy](lc, lw), nil
}

func CiliumCIDRGroupResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumCIDRGroupList](cs.CiliumV2alpha1().CiliumCIDRGroups()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumCIDRGroup](lc, lw), nil
}

func EndpointsResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*Endpoints], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
	if err != nil {
		return nil, err
	}

	lw := &endpointsListerWatcher{cs: cs, optsModifier: optsModifier}
	return resource.New[*Endpoints](
		lc,
		lw,
		resource.WithLazyTransform(lw.getSourceObj, transformEndpoint),
	), nil
}

// endpointsListerWatcher implements List and Watch for endpoints/endpointslices. It
// performs the capability check on first call to List/Watch. This allows constructing
// the resource before the client has been started and capabilities have been probed.
type endpointsListerWatcher struct {
	cs           client.Clientset
	optsModifier func(*metav1.ListOptions)
	sourceObj    k8sRuntime.Object

	once                sync.Once
	cachedListerWatcher cache.ListerWatcher
}

func (lw *endpointsListerWatcher) getSourceObj() k8sRuntime.Object {
	lw.getListerWatcher() // force the construction
	return lw.sourceObj
}

func (lw *endpointsListerWatcher) getListerWatcher() cache.ListerWatcher {
	lw.once.Do(func() {
		if SupportsEndpointSlice() {
			if SupportsEndpointSliceV1() {
				log.Info("Using discoveryv1.EndpointSlice")
				lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_discoveryv1.EndpointSliceList](
					lw.cs.Slim().DiscoveryV1().EndpointSlices(""),
				)
				lw.sourceObj = &slim_discoveryv1.EndpointSlice{}
			} else {
				log.Info("Using discoveryv1beta1.EndpointSlice")
				lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_discoveryv1beta1.EndpointSliceList](
					lw.cs.Slim().DiscoveryV1beta1().EndpointSlices(""),
				)
				lw.sourceObj = &slim_discoveryv1beta1.EndpointSlice{}
			}
		} else {
			log.Info("Using v1.Endpoints")
			lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_corev1.EndpointsList](
				lw.cs.Slim().CoreV1().Endpoints(""),
			)
			lw.sourceObj = &slim_corev1.Endpoints{}
		}
		lw.cachedListerWatcher = utils.ListerWatcherWithModifier(lw.cachedListerWatcher, lw.optsModifier)
	})
	return lw.cachedListerWatcher
}

func (lw *endpointsListerWatcher) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return lw.getListerWatcher().List(opts)
}

func (lw *endpointsListerWatcher) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return lw.getListerWatcher().Watch(opts)
}

func transformEndpoint(obj any) (any, error) {
	switch obj := obj.(type) {
	case *slim_corev1.Endpoints:
		return ParseEndpoints(obj), nil
	case *slim_discoveryv1.EndpointSlice:
		return ParseEndpointSliceV1(obj), nil
	case *slim_discoveryv1beta1.EndpointSlice:
		return ParseEndpointSliceV1Beta1(obj), nil
	default:
		return nil, fmt.Errorf("%T not a known endpoint or endpoint slice object", obj)
	}
}
