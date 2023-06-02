// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"strings"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type envoyConfigManager struct {
	client             client.Clientset
	informer           cache.Controller
	store              cache.Store
	maxRetries         int
	idleTimeoutSeconds int
}

func newEnvoyConfigManager(ctx context.Context, client client.Clientset, maxRetries int, idleTimeoutSeconds int) (*envoyConfigManager, error) {
	manager := &envoyConfigManager{
		client:             client,
		maxRetries:         maxRetries,
		idleTimeoutSeconds: idleTimeoutSeconds,
	}

	manager.store, manager.informer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*ciliumv2.CiliumEnvoyConfigList](client.CiliumV2().CiliumEnvoyConfigs(corev1.NamespaceAll)),
		&ciliumv2.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	go manager.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync envoy configs")
	}
	return manager, nil
}

// getByKey is a wrapper of Store.GetByKey but with concrete CiliumEnvoyConfig object
func (em *envoyConfigManager) getByKey(key string) (*ciliumv2.CiliumEnvoyConfig, bool, error) {
	objFromCache, exists, err := em.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}
	envoyConfig, ok := objFromCache.(*ciliumv2.CiliumEnvoyConfig)
	if !ok {
		return nil, exists, fmt.Errorf("got invalid object from cache")
	}
	return envoyConfig, exists, err
}

func (em *envoyConfigManager) MarkSynced() {
	em.informer.HasSynced()
}

func (m *Manager) getEnvoyConfigForService(svc *slim_corev1.Service) (*ciliumv2.CiliumEnvoyConfig, error) {
	resources, err := m.getResources(svc)
	if err != nil {
		return nil, err
	}
	return &ciliumv2.CiliumEnvoyConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CECKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", ciliumEnvoyLBPrefix, svc.GetName()),
			Namespace: svc.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_corev1.SchemeGroupVersion.String(),
					Kind:       "Service",
					Name:       svc.GetName(),
					UID:        svc.GetUID(),
				},
			},
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			Services: []*ciliumv2.ServiceListener{
				{
					Name:      svc.GetName(),
					Namespace: svc.GetNamespace(),
				},
			},
			Resources: resources,
		},
	}, nil
}

func (m *Manager) getResources(svc *slim_corev1.Service) ([]ciliumv2.XDSResource, error) {
	var resources []ciliumv2.XDSResource
	listener, err := m.getListenerResource(svc)
	if err != nil {
		return nil, err
	}
	resources = append(resources, listener)

	routeConfig, err := m.getRouteConfigurationResource(svc)
	if err != nil {
		return nil, err
	}
	resources = append(resources, routeConfig)

	clusters, err := m.getClusterResources(svc)
	if err != nil {
		return nil, err
	}
	resources = append(resources, clusters...)
	return resources, nil
}

func (m *Manager) getClusterResources(svc *slim_corev1.Service) ([]ciliumv2.XDSResource, error) {
	lbPolicy, ok := envoy_config_cluster_v3.Cluster_LbPolicy_value[strings.ToUpper(m.algorithm)]
	if !ok {
		lbPolicy = int32(envoy_config_cluster_v3.Cluster_ROUND_ROBIN)
	}
	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           getName(svc),
		ConnectTimeout: &durationpb.Duration{Seconds: 5},
		LbPolicy:       envoy_config_cluster_v3.Cluster_LbPolicy(lbPolicy),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
				CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{Seconds: int64(m.idleTimeoutSeconds)},
				},
				UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
					UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{
						Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
					},
				},
			}),
		},
		OutlierDetection: &envoy_config_cluster_v3.OutlierDetection{
			SplitExternalLocalOriginErrors: true,
			// The number of consecutive locally originated failures before ejection occurs.
			ConsecutiveLocalOriginFailure: &wrapperspb.UInt32Value{Value: 2},
		},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		},
	}

	var mutatorFuncs = []clusterMutator{
		lbModeClusterMutator(svc),
	}
	for _, fn := range mutatorFuncs {
		cluster = fn(cluster)
	}

	clusterBytes, err := proto.Marshal(cluster)
	if err != nil {
		return nil, err
	}
	return []ciliumv2.XDSResource{
		{
			Any: &anypb.Any{
				TypeUrl: envoy.ClusterTypeURL,
				Value:   clusterBytes,
			},
		},
	}, nil
}

func (m *Manager) getRouteConfigurationResource(svc *slim_corev1.Service) (ciliumv2.XDSResource, error) {
	routeConfig := &envoy_config_route_v3.RouteConfiguration{
		Name:         getName(svc),
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{m.getVirtualHost(svc)},
	}

	var mutatorFuncs = []routeConfigMutator{}
	for _, fn := range mutatorFuncs {
		routeConfig = fn(routeConfig)
	}

	routeBytes, err := proto.Marshal(routeConfig)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}
	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.RouteTypeURL,
			Value:   routeBytes,
		},
	}, nil
}

func (m *Manager) getListenerResource(svc *slim_corev1.Service) (ciliumv2.XDSResource, error) {
	defaultHttpConnectionManager, err := m.getConnectionManager(svc)
	if err != nil {
		return ciliumv2.XDSResource{}, nil
	}

	var filterChains []*envoy_config_listener.FilterChain
	filterChains = []*envoy_config_listener.FilterChain{
		{
			FilterChainMatch: &envoy_config_listener.FilterChainMatch{
				TransportProtocol: "raw_buffer",
			},
			Filters: []*envoy_config_listener.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: defaultHttpConnectionManager.Any,
					},
				},
			},
		},
	}

	listener := &envoy_config_listener.Listener{
		Name:         getName(svc),
		FilterChains: filterChains,
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
		},
	}

	var mutatorFuncs = []listenerMutator{}
	for _, fn := range mutatorFuncs {
		listener = fn(listener)
	}

	listenerBytes, err := proto.Marshal(listener)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}
	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ListenerTypeURL,
			Value:   listenerBytes,
		},
	}, nil
}

func (m *Manager) getConnectionManager(svc *slim_corev1.Service) (ciliumv2.XDSResource, error) {
	connectionManager := &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: getName(svc),
		RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
				RouteConfigName: getName(svc),
			},
		},
		UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:    false,
		HttpFilters: []*envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter{
			{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
				},
			},
		},
	}

	var mutatorFuncs = []httpConnectionManagerMutator{
		grpcHttpConnectionManagerMutator(svc),
	}
	for _, fn := range mutatorFuncs {
		connectionManager = fn(connectionManager)
	}

	connectionManagerBytes, err := proto.Marshal(connectionManager)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.HttpConnectionManagerTypeURL,
			Value:   connectionManagerBytes,
		},
	}, nil
}

func (m *Manager) getVirtualHost(svc *slim_corev1.Service) *envoy_config_route_v3.VirtualHost {
	route := &envoy_config_route_v3.Route{
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: getName(svc),
				},
				MaxStreamDuration: &envoy_config_route_v3.RouteAction_MaxStreamDuration{
					MaxStreamDuration: &durationpb.Duration{
						Seconds: 0,
					},
				},
			},
		},
	}

	var routeMutatorFuncs = []routeMutator{}
	for _, fn := range routeMutatorFuncs {
		route = fn(route)
	}

	virtualHost := &envoy_config_route_v3.VirtualHost{
		Name:    getName(svc),
		Domains: []string{"*"},
		Routes:  []*envoy_config_route_v3.Route{route},
	}

	var mutatorFuncs = []virtualHostMutator{}
	for _, fn := range mutatorFuncs {
		virtualHost = fn(virtualHost)
	}

	return virtualHost
}

func getName(obj metav1.Object) string {
	return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		log.WithError(err).Errorf("invalid message %s", message)
		return nil
	}
	return a
}
