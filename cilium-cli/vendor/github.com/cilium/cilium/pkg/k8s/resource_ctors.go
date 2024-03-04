// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"sync"

	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discoveryv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/node"
)

// Config defines the configuration options for k8s resources.
type Config struct {
	EnableK8sEndpointSlice bool

	// K8sServiceProxyName is the value of service.kubernetes.io/service-proxy-name label,
	// that identifies the service objects Cilium should handle.
	// If the provided value is an empty string, Cilium will manage service objects when
	// the label is not present. For more details -
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/2447-Make-kube-proxy-service-abstraction-optional
	K8sServiceProxyName string
}

// DefaultConfig represents the default k8s resources config values.
var DefaultConfig = Config{
	EnableK8sEndpointSlice: true,
}

// Flags implements the cell.Flagger interface.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-k8s-endpoint-slice", def.EnableK8sEndpointSlice, "Enables k8s EndpointSlice feature in Cilium if the k8s cluster supports it")
	flags.String("k8s-service-proxy-name", def.K8sServiceProxyName, "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
}

// ServiceResource builds the Resource[Service] object.
func ServiceResource(lc cell.Lifecycle, cfg Config, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Service], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	optsModifier, err := utils.GetServiceAndEndpointListOptionsModifier(cfg.K8sServiceProxyName)
	if err != nil {
		return nil, err
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](cs.Slim().CoreV1().Services("")),
		append(opts, optsModifier)...,
	)
	return resource.New[*slim_corev1.Service](lc, lw, resource.WithMetric("Service")), nil
}

func NodeResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](cs.Slim().CoreV1().Nodes()),
		opts...,
	)
	return resource.New[*slim_corev1.Node](lc, lw, resource.WithMetric("Node")), nil
}

func CiliumNodeResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](lc, lw,
		resource.WithMetric("CiliumNode"),
		resource.WithStoppableInformer(),
	), nil
}

func PodResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Pod], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.PodList](cs.Slim().CoreV1().Pods("")),
		opts...,
	)
	return resource.New[*slim_corev1.Pod](lc, lw, resource.WithMetric("Pod")), nil
}

func NamespaceResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Namespace], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](cs.Slim().CoreV1().Namespaces()),
		opts...,
	)
	return resource.New[*slim_corev1.Namespace](lc, lw, resource.WithMetric("Namespace")), nil
}

func LBIPPoolsResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](cs.CiliumV2alpha1().CiliumLoadBalancerIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](lc, lw, resource.WithMetric("CiliumLoadBalancerIPPool")), nil
}

func CiliumIdentityResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](cs.CiliumV2().CiliumIdentities()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumIdentity](lc, lw, resource.WithMetric("CiliumIdentityList")), nil
}

func NetworkPolicyResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_networkingv1.NetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_networkingv1.NetworkPolicyList](cs.Slim().NetworkingV1().NetworkPolicies("")),
		opts...,
	)
	return resource.New[*slim_networkingv1.NetworkPolicy](lc, lw, resource.WithMetric("NetworkPolicy")), nil
}

func CiliumNetworkPolicyResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNetworkPolicyList](cs.CiliumV2().CiliumNetworkPolicies("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNetworkPolicy](lc, lw, resource.WithMetric("CiliumNetworkPolicy")), nil
}

func CiliumClusterwideNetworkPolicyResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideNetworkPolicyList](cs.CiliumV2().CiliumClusterwideNetworkPolicies()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumClusterwideNetworkPolicy](lc, lw, resource.WithMetric("CiliumClusterwideNetworkPolicy")), nil
}

func CiliumCIDRGroupResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumCIDRGroupList](cs.CiliumV2alpha1().CiliumCIDRGroups()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumCIDRGroup](lc, lw, resource.WithMetric("CiliumCIDRGroup")), nil
}

func CiliumPodIPPoolResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumPodIPPoolList](cs.CiliumV2alpha1().CiliumPodIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumPodIPPool](lc, lw, resource.WithMetric("CiliumPodIPPool")), nil
}

func CiliumBGPPeeringPolicyResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPPeeringPolicyList](cs.CiliumV2alpha1().CiliumBGPPeeringPolicies()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy](lc, lw, resource.WithMetric("CiliumBGPPeeringPolicies")), nil
}

func CiliumBGPNodeConfigResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPNodeConfigList](cs.CiliumV2alpha1().CiliumBGPNodeConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPNodeConfig](lc, lw, resource.WithMetric("CiliumBGPNodeConfig")), nil
}

func CiliumBGPAdvertisementResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPAdvertisementList](cs.CiliumV2alpha1().CiliumBGPAdvertisements()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPAdvertisement](lc, lw, resource.WithMetric("CiliumBGPAdvertisement")), nil
}

func CiliumBGPPeerConfigResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPPeerConfigList](cs.CiliumV2alpha1().CiliumBGPPeerConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPPeerConfig](lc, lw, resource.WithMetric("CiliumBGPPeerConfig")), nil
}

func EndpointsResource(lc cell.Lifecycle, cfg Config, cs client.Clientset) (resource.Resource[*Endpoints], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	endpointsOptsModifier, err := utils.GetServiceAndEndpointListOptionsModifier(cfg.K8sServiceProxyName)
	if err != nil {
		return nil, err
	}

	endpointSliceOpsModifier, err := utils.GetEndpointSliceListOptionsModifier()
	if err != nil {
		return nil, err
	}
	lw := &endpointsListerWatcher{
		cs:                         cs,
		enableK8sEndpointSlice:     cfg.EnableK8sEndpointSlice,
		endpointsOptsModifier:      endpointsOptsModifier,
		endpointSlicesOptsModifier: endpointSliceOpsModifier,
	}
	return resource.New[*Endpoints](
		lc,
		lw,
		resource.WithLazyTransform(lw.getSourceObj, transformEndpoint),
		resource.WithMetric("Endpoint"),
		resource.WithName("endpoints"),
	), nil
}

// endpointsListerWatcher implements List and Watch for endpoints/endpointslices. It
// performs the capability check on first call to List/Watch. This allows constructing
// the resource before the client has been started and capabilities have been probed.
type endpointsListerWatcher struct {
	cs                         client.Clientset
	enableK8sEndpointSlice     bool
	endpointsOptsModifier      func(*metav1.ListOptions)
	endpointSlicesOptsModifier func(*metav1.ListOptions)
	sourceObj                  k8sRuntime.Object

	once                sync.Once
	cachedListerWatcher cache.ListerWatcher
}

func (lw *endpointsListerWatcher) getSourceObj() k8sRuntime.Object {
	lw.getListerWatcher() // force the construction
	return lw.sourceObj
}

func (lw *endpointsListerWatcher) getListerWatcher() cache.ListerWatcher {
	lw.once.Do(func() {
		if lw.enableK8sEndpointSlice && version.Capabilities().EndpointSlice {
			if version.Capabilities().EndpointSliceV1 {
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
			lw.cachedListerWatcher = utils.ListerWatcherWithModifier(lw.cachedListerWatcher, lw.endpointSlicesOptsModifier)
		} else {
			log.Info("Using v1.Endpoints")
			lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_corev1.EndpointsList](
				lw.cs.Slim().CoreV1().Endpoints(""),
			)
			lw.sourceObj = &slim_corev1.Endpoints{}
			lw.cachedListerWatcher = utils.ListerWatcherWithModifier(lw.cachedListerWatcher, lw.endpointsOptsModifier)
		}
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

// CiliumSlimEndpointResource uses the "localNode" IndexFunc to build the resource indexer.
// The IndexFunc accesses the local node info to get its IP, so it depends on the local node store
// to initialize it before the first access.
// To reflect this, the node.LocalNodeStore dependency is explicitly requested in the function
// signature.
func CiliumSlimEndpointResource(lc cell.Lifecycle, cs client.Clientset, _ *node.LocalNodeStore, opts ...func(*metav1.ListOptions)) (resource.Resource[*types.CiliumEndpoint], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](cs.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll)),
		opts...,
	)
	indexers := cache.Indexers{
		"localNode": ciliumEndpointLocalPodIndexFunc,
	}
	return resource.New[*types.CiliumEndpoint](lc, lw,
		resource.WithLazyTransform(func() k8sRuntime.Object {
			return &cilium_api_v2.CiliumEndpoint{}
		}, TransformToCiliumEndpoint),
		resource.WithMetric("CiliumEndpoint"),
		resource.WithIndexers(indexers),
		resource.WithStoppableInformer(),
	), nil
}

// ciliumEndpointLocalPodIndexFunc is an IndexFunc that indexes only local
// CiliumEndpoints, by their local Node IP.
func ciliumEndpointLocalPodIndexFunc(obj any) ([]string, error) {
	cep, ok := obj.(*types.CiliumEndpoint)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}
	indices := []string{}
	if cep.Networking == nil {
		log.WithField("ciliumendpoint", cep.GetNamespace()+"/"+cep.GetName()).
			Debug("cannot index CiliumEndpoint by node without network status")
		return nil, nil
	}
	if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() {
		indices = append(indices, cep.Networking.NodeIP)
	}
	return indices, nil
}

// CiliumEndpointSliceResource uses the "localNode" IndexFunc to build the resource indexer.
// The IndexFunc accesses the local node info to get its IP, so it depends on the local node store
// to initialize it before the first access.
// To reflect this, the node.LocalNodeStore dependency is explicitly requested in the function
// signature.
func CiliumEndpointSliceResource(lc cell.Lifecycle, cs client.Clientset, _ *node.LocalNodeStore, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](cs.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	indexers := cache.Indexers{
		"localNode": ciliumEndpointSliceLocalPodIndexFunc,
	}
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](lc, lw,
		resource.WithMetric("CiliumEndpointSlice"),
		resource.WithIndexers(indexers),
		resource.WithStoppableInformer(),
	), nil
}

// ciliumEndpointSliceLocalPodIndexFunc is an IndexFunc that indexes CiliumEndpointSlices
// by their corresponding Pod, which are running locally on this Node.
func ciliumEndpointSliceLocalPodIndexFunc(obj any) ([]string, error) {
	ces, ok := obj.(*cilium_api_v2alpha1.CiliumEndpointSlice)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}
	indices := []string{}
	for _, ep := range ces.Endpoints {
		if ep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() {
			indices = append(indices, ep.Networking.NodeIP)
			break
		}
	}
	return indices, nil
}

func CiliumExternalWorkloads(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumExternalWorkload], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumExternalWorkloadList](cs.CiliumV2().CiliumExternalWorkloads()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumExternalWorkload](lc, lw, resource.WithMetric("CiliumExternalWorkloads")), nil
}

func CiliumEnvoyConfigResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEnvoyConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEnvoyConfigList](cs.CiliumV2().CiliumEnvoyConfigs("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumEnvoyConfig](lc, lw, resource.WithMetric("CiliumEnvoyConfig")), nil
}

func CiliumClusterwideEnvoyConfigResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumClusterwideEnvoyConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideEnvoyConfigList](cs.CiliumV2().CiliumClusterwideEnvoyConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumClusterwideEnvoyConfig](lc, lw, resource.WithMetric("CiliumClusterwideEnvoyConfig")), nil
}
