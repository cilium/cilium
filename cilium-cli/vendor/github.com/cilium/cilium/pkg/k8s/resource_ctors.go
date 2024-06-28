// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discoveryv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
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

const (
	NamespaceIndex = "namespace"
	ByKeyIndex     = "by-key-index"
)

// Flags implements the cell.Flagger interface.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-k8s-endpoint-slice", def.EnableK8sEndpointSlice, "Enables k8s EndpointSlice feature in Cilium if the k8s cluster supports it")
	flags.String("k8s-service-proxy-name", def.K8sServiceProxyName, "Value of K8s service-proxy-name label for which Cilium handles the services (empty = all services without service.kubernetes.io/service-proxy-name label)")
}

// namespaceIndexFunc is an IndexFunc that indexes Namespace of Kubernetes
// types by their namespace.
func namespaceIndexFunc(obj any) ([]string, error) {
	object, ok := obj.(utils.NamespaceNameGetter)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}
	return []string{object.GetNamespace()}, nil
}

func GetIdentitiesByKeyFunc(keyFunc func(map[string]string) allocator.AllocatorKey) func(obj interface{}) ([]string, error) {
	return func(obj interface{}) ([]string, error) {
		if identity, ok := obj.(*cilium_api_v2.CiliumIdentity); ok {
			return []string{keyFunc(identity.SecurityLabels).GetKey()}, nil
		}
		return []string{}, fmt.Errorf("object other than CiliumIdentity was pushed to the store")
	}
}

// Dependencies for Cilium resources that may be used by Cilium Agent.
// When CRDSyncPromise is provided, watchers of resources using this
// will block until all CRDs used by the agent have been registered.
// Agent will fail to start if Cilium Operator does not register all
// the CRDs in time.
type CiliumResourceParams struct {
	cell.In

	Lifecycle      cell.Lifecycle
	ClientSet      client.Clientset
	CRDSyncPromise promise.Promise[synced.CRDSync] `optional:"true"`
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
	indexers := cache.Indexers{
		NamespaceIndex: namespaceIndexFunc,
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](cs.Slim().CoreV1().Services("")),
		append(opts, optsModifier)...,
	)
	return resource.New[*slim_corev1.Service](
		lc, lw,
		resource.WithMetric("Service"),
		resource.WithIndexers(indexers),
	), nil
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

func CiliumNodeResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](params.ClientSet.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](params.Lifecycle, lw,
		resource.WithMetric("CiliumNode"),
		resource.WithStoppableInformer(),
		resource.WithCRDSync(params.CRDSyncPromise), // optional, can be nil
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

func LBIPPoolsResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](params.ClientSet.CiliumV2alpha1().CiliumLoadBalancerIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](params.Lifecycle, lw, resource.WithMetric("CiliumLoadBalancerIPPool"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumIdentityResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](params.ClientSet.CiliumV2().CiliumIdentities()),
		opts...,
	)

	indexers := cache.Indexers{
		ByKeyIndex: GetIdentitiesByKeyFunc((&key.GlobalIdentity{}).PutKeyFromMap),
	}

	return resource.New[*cilium_api_v2.CiliumIdentity](params.Lifecycle, lw, resource.WithMetric("CiliumIdentityList"), resource.WithIndexers(indexers), resource.WithCRDSync(params.CRDSyncPromise)), nil
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

func CiliumNetworkPolicyResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNetworkPolicy], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNetworkPolicyList](params.ClientSet.CiliumV2().CiliumNetworkPolicies("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNetworkPolicy](params.Lifecycle, lw, resource.WithMetric("CiliumNetworkPolicy"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumClusterwideNetworkPolicyResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideNetworkPolicyList](params.ClientSet.CiliumV2().CiliumClusterwideNetworkPolicies()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumClusterwideNetworkPolicy](params.Lifecycle, lw, resource.WithMetric("CiliumClusterwideNetworkPolicy"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumCIDRGroupResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumCIDRGroupList](params.ClientSet.CiliumV2alpha1().CiliumCIDRGroups()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumCIDRGroup](params.Lifecycle, lw, resource.WithMetric("CiliumCIDRGroup"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumPodIPPoolResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumPodIPPoolList](params.ClientSet.CiliumV2alpha1().CiliumPodIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumPodIPPool](params.Lifecycle, lw, resource.WithMetric("CiliumPodIPPool"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumBGPPeeringPolicyResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPPeeringPolicyList](params.ClientSet.CiliumV2alpha1().CiliumBGPPeeringPolicies()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy](params.Lifecycle, lw, resource.WithMetric("CiliumBGPPeeringPolicies"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumBGPNodeConfigResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPNodeConfigList](params.ClientSet.CiliumV2alpha1().CiliumBGPNodeConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPNodeConfig](params.Lifecycle, lw, resource.WithMetric("CiliumBGPNodeConfig"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumBGPAdvertisementResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPAdvertisement], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPAdvertisementList](params.ClientSet.CiliumV2alpha1().CiliumBGPAdvertisements()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPAdvertisement](params.Lifecycle, lw, resource.WithMetric("CiliumBGPAdvertisement"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumBGPPeerConfigResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPPeerConfigList](params.ClientSet.CiliumV2alpha1().CiliumBGPPeerConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPPeerConfig](params.Lifecycle, lw, resource.WithMetric("CiliumBGPPeerConfig"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func EndpointsResource(lc cell.Lifecycle, cfg Config, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*Endpoints], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	endpointsOptsModifier, err := utils.GetServiceAndEndpointListOptionsModifier(cfg.K8sServiceProxyName)
	if err != nil {
		return nil, err
	}

	endpointSliceOptsModifier, err := utils.GetEndpointSliceListOptionsModifier()
	if err != nil {
		return nil, err
	}

	lw := &endpointsListerWatcher{
		cs:                          cs,
		enableK8sEndpointSlice:      cfg.EnableK8sEndpointSlice,
		endpointsOptsModifiers:      append(opts, endpointsOptsModifier),
		endpointSlicesOptsModifiers: append(opts, endpointSliceOptsModifier),
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
	cs                          client.Clientset
	enableK8sEndpointSlice      bool
	endpointsOptsModifiers      []func(*metav1.ListOptions)
	endpointSlicesOptsModifiers []func(*metav1.ListOptions)
	sourceObj                   k8sRuntime.Object

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
			lw.cachedListerWatcher = utils.ListerWatcherWithModifiers(lw.cachedListerWatcher, lw.endpointSlicesOptsModifiers...)
		} else {
			log.Info("Using v1.Endpoints")
			lw.cachedListerWatcher = utils.ListerWatcherFromTyped[*slim_corev1.EndpointsList](
				lw.cs.Slim().CoreV1().Endpoints(""),
			)
			lw.sourceObj = &slim_corev1.Endpoints{}
			lw.cachedListerWatcher = utils.ListerWatcherWithModifiers(lw.cachedListerWatcher, lw.endpointsOptsModifiers...)
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
func CiliumSlimEndpointResource(params CiliumResourceParams, _ *node.LocalNodeStore, opts ...func(*metav1.ListOptions)) (resource.Resource[*types.CiliumEndpoint], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](params.ClientSet.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll)),
		opts...,
	)
	indexers := cache.Indexers{
		"localNode": ciliumEndpointLocalPodIndexFunc,
	}
	return resource.New[*types.CiliumEndpoint](params.Lifecycle, lw,
		resource.WithLazyTransform(func() k8sRuntime.Object {
			return &cilium_api_v2.CiliumEndpoint{}
		}, TransformToCiliumEndpoint),
		resource.WithMetric("CiliumEndpoint"),
		resource.WithIndexers(indexers),
		resource.WithStoppableInformer(),
		resource.WithCRDSync(params.CRDSyncPromise),
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
func CiliumEndpointSliceResource(params CiliumResourceParams, _ *node.LocalNodeStore, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](params.ClientSet.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	indexers := cache.Indexers{
		"localNode": ciliumEndpointSliceLocalPodIndexFunc,
	}
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](params.Lifecycle, lw,
		resource.WithMetric("CiliumEndpointSlice"),
		resource.WithIndexers(indexers),
		resource.WithStoppableInformer(),
		resource.WithCRDSync(params.CRDSyncPromise),
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

func CiliumExternalWorkloads(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumExternalWorkload], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumExternalWorkloadList](params.ClientSet.CiliumV2().CiliumExternalWorkloads()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumExternalWorkload](params.Lifecycle, lw, resource.WithMetric("CiliumExternalWorkloads"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumEnvoyConfigResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEnvoyConfig], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEnvoyConfigList](params.ClientSet.CiliumV2().CiliumEnvoyConfigs("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumEnvoyConfig](params.Lifecycle, lw, resource.WithMetric("CiliumEnvoyConfig"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func CiliumClusterwideEnvoyConfigResource(params CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumClusterwideEnvoyConfig], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideEnvoyConfigList](params.ClientSet.CiliumV2().CiliumClusterwideEnvoyConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumClusterwideEnvoyConfig](params.Lifecycle, lw, resource.WithMetric("CiliumClusterwideEnvoyConfig"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}
