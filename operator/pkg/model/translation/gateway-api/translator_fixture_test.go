// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"syscall"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var backendV1XDSResource = toAny(toEnvoyCluster("gateway-conformance-infra", "infra-backend-v1", "8080"))
var routeActionBackendV1 = toRouteAction("gateway-conformance-infra", "infra-backend-v1", "8080")

var backendV2XDSResource = toAny(toEnvoyCluster("gateway-conformance-infra", "infra-backend-v2", "8080"))
var routeActionBackendV2 = toRouteAction("gateway-conformance-infra", "infra-backend-v2", "8080")

var backendV3XDSResource = toAny(toEnvoyCluster("gateway-conformance-infra", "infra-backend-v3", "8080"))
var routeActionBackendV3 = toRouteAction("gateway-conformance-infra", "infra-backend-v3", "8080")

var httpInsecureListenerXDSResource = toAny(&envoy_config_listener.Listener{
	Name: "listener",
	FilterChains: []*envoy_config_listener.FilterChain{
		{
			FilterChainMatch: &envoy_config_listener.FilterChainMatch{TransportProtocol: "raw_buffer"},
			Filters: []*envoy_config_listener.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: toAny(&http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "listener-insecure",
							RouteSpecifier: &http_connection_manager_v3.HttpConnectionManager_Rds{
								Rds: &http_connection_manager_v3.Rds{RouteConfigName: "listener-insecure"},
							},
							UpgradeConfigs: []*http_connection_manager_v3.HttpConnectionManager_UpgradeConfig{
								{UpgradeType: "websocket"},
							},
							UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
							SkipXffAppend:    false,
							HttpFilters: []*http_connection_manager_v3.HttpFilter{
								{
									Name: "envoy.filters.http.router",
									ConfigType: &http_connection_manager_v3.HttpFilter_TypedConfig{
										TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
									},
								},
							},
						}),
					},
				},
			},
		},
	},
	ListenerFilters: []*envoy_config_listener.ListenerFilter{
		{
			Name: "envoy.filters.listener.tls_inspector",
			ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
			},
		},
	},
	SocketOptions: []*envoy_config_core_v3.SocketOption{
		{
			Description: "Enable TCP keep-alive (default to enabled)",
			Level:       syscall.SOL_SOCKET,
			Name:        syscall.SO_KEEPALIVE,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: 1,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive idle time (in seconds) (defaults to 10s)",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPIDLE,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: 10,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive probe intervals (in seconds) (defaults to 5s)",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPINTVL,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: 5,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive probe max failures.",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPCNT,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: 10,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
	},
})

// basicHTTPListeners is the internal model representation of the simple HTTP listeners
var basicHTTPListeners = []model.HTTPListener{
	{
		Name: "prod-web-gw",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "my-gateway",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1beta1",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/bar",
				},
				Backends: []model.Backend{
					{
						Name:      "my-service",
						Namespace: "default",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

// basicHTTPListenersCiliumEnvoyConfig is the generated CiliumEnvoyConfig basic http listener model.
var basicHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-my-gateway",
		Namespace: "default",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "my-gateway",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-my-gateway",
				Namespace: "default",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "my-service",
				Namespace: "default",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/bar(/.*)?$",
											},
										},
									},
									Action: toRouteAction("default", "my-service", "8080"),
								},
							},
						},
					},
				}),
			},
			{Any: toAny(toEnvoyCluster("default", "my-service", "8080"))},
		},
	},
}

// basicTLSListeners is the internal model representation of the simple TLS listeners
var basicTLSListeners = []model.TLSListener{
	{
		Name: "prod-web-gw",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "my-gateway",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1alpha2",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     443,
		Hostname: "*",
		Routes: []model.TLSRoute{
			{
				Hostnames: []string{"foo.com"},
				Backends: []model.Backend{
					{
						Name:      "my-service",
						Namespace: "default",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var basicTLSListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-my-gateway",
		Namespace: "default",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "my-gateway",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-my-gateway",
				Namespace: "default",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "my-service",
				Namespace: "default",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{
				Any: toAny(&envoy_config_listener.Listener{
					Name: "listener",
					FilterChains: []*envoy_config_listener.FilterChain{{
						FilterChainMatch: &envoy_config_listener.FilterChainMatch{
							ServerNames:       []string{"foo.com"},
							TransportProtocol: "tls",
						},
						Filters: []*envoy_config_listener.Filter{
							{
								Name: "envoy.filters.network.tcp_proxy",
								ConfigType: &envoy_config_listener.Filter_TypedConfig{
									TypedConfig: toAny(&envoy_extensions_filters_network_tcp_v3.TcpProxy{
										StatPrefix: "default/my-service:8080",
										ClusterSpecifier: &envoy_extensions_filters_network_tcp_v3.TcpProxy_Cluster{
											Cluster: "default/my-service:8080",
										},
									}),
								},
							},
						},
					}},
					ListenerFilters: []*envoy_config_listener.ListenerFilter{
						{
							Name: "envoy.filters.listener.tls_inspector",
							ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
								TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
							},
						},
					},
					SocketOptions: []*envoy_config_core_v3.SocketOption{
						{
							Description: "Enable TCP keep-alive (default to enabled)",
							Level:       syscall.SOL_SOCKET,
							Name:        syscall.SO_KEEPALIVE,
							Value: &envoy_config_core_v3.SocketOption_IntValue{
								IntValue: 1,
							},
							State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
						},
						{
							Description: "TCP keep-alive idle time (in seconds) (defaults to 10s)",
							Level:       syscall.IPPROTO_TCP,
							Name:        syscall.TCP_KEEPIDLE,
							Value: &envoy_config_core_v3.SocketOption_IntValue{
								IntValue: 10,
							},
							State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
						},
						{
							Description: "TCP keep-alive probe intervals (in seconds) (defaults to 5s)",
							Level:       syscall.IPPROTO_TCP,
							Name:        syscall.TCP_KEEPINTVL,
							Value: &envoy_config_core_v3.SocketOption_IntValue{
								IntValue: 5,
							},
							State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
						},
						{
							Description: "TCP keep-alive probe max failures.",
							Level:       syscall.IPPROTO_TCP,
							Name:        syscall.TCP_KEEPCNT,
							Value: &envoy_config_core_v3.SocketOption_IntValue{
								IntValue: 10,
							},
							State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
						},
					},
				}),
			},
			{
				Any: toAny(&envoy_config_cluster_v3.Cluster{
					Name: "default/my-service:8080",
					ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
						Type: envoy_config_cluster_v3.Cluster_EDS,
					},
					ConnectTimeout: &durationpb.Duration{Seconds: int64(5)},
					LbPolicy:       envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
					OutlierDetection: &envoy_config_cluster_v3.OutlierDetection{
						SplitExternalLocalOriginErrors: true,
					},
				}),
			},
		},
	},
}

// simpleSameNamespaceHTTPListeners is the internal model representation of Conformance/HTTPRouteSimpleSameNamespace
var simpleSameNamespaceHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var simpleSameNamespaceHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
		},
	},
}

// crossNamespaceHTTPListeners is the internal model representation of the Conformance/HTTPRouteCrossNamespace
var crossNamespaceHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "backend-namespaces",
				Namespace: "gateway-conformance-infra",
				Kind:      "Gateway",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Backends: []model.Backend{
					{
						Name:      "web-backend",
						Namespace: "gateway-conformance-web-backend",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var crossNamespaceHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-backend-namespaces",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "backend-namespaces",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-backend-namespaces",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "web-backend",
				Namespace: "gateway-conformance-web-backend",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: toRouteAction("gateway-conformance-web-backend", "web-backend", "8080"),
								},
							},
						},
					},
				}),
			},
			{Any: toAny(toEnvoyCluster("gateway-conformance-web-backend", "web-backend", "8080"))},
		},
	},
}

// exactPathMatchingHTTPListeners is the internal model representation of Conformance/HTTPExactPathMatching
var exactPathMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Kind:      "Gateway",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/one"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/two"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var exactPathMatchingHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/one",
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/two",
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
		},
	},
}

// headerMatchingHTTPListeners is the internal modal for Conformance/HTTPRouteHeaderMatching
var headerMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "orange"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "blue"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "green"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "red"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "yellow"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra", Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

// headerMatchingHTTPCiliumEnvoyConfig is the generated CiliumEnvoyConfig for Conformance/HTTPRouteHeaderMatching
var headerMatchingHTTPCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "color",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "orange",
														},
													},
												},
											},
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "two",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "one",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "two",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV2,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "color",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "blue",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "color",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "green",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "color",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "red",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV2,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "color",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "yellow",
														},
													},
												},
											},
										},
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
		},
	},
}

// hostnameIntersectionHTTPListeners is a internal model representation of the Conformance/HTTPRouteHostnameIntersection
var hostnameIntersectionHTTPListeners = []model.HTTPListener{
	{
		Name: "listener-1",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "httproute-hostname-intersection",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "very.specific.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"very.specific.com"},
				PathMatch: model.StringMatch{Prefix: "/s1"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Hostnames: []string{"very.specific.com"},
				PathMatch: model.StringMatch{Prefix: "/s3"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-2",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Namespace: "gateway-conformance-infra",
				Name:      "httproute-hostname-intersection",
			},
		},
		Port:     80,
		Hostname: "*.wildcard.io",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"bar.wildcard.io", "foo.bar.wildcard.io", "foo.wildcard.io"},
				PathMatch: model.StringMatch{Prefix: "/s2"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-3",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "httproute-hostname-intersection",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*.anotherwildcard.io",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.anotherwildcard.io"},
				PathMatch: model.StringMatch{Prefix: "/s4"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var hostnameIntersectionHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-httproute-hostname-intersection",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "httproute-hostname-intersection",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-httproute-hostname-intersection",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v3",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "very.specific.com",
							Domains: []string{"very.specific.com", "very.specific.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s1(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s3(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV3,
								},
							},
						},
						{
							Name:    "bar.wildcard.io",
							Domains: []string{"bar.wildcard.io", "bar.wildcard.io:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s2(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
						{
							Name:    "foo.bar.wildcard.io",
							Domains: []string{"foo.bar.wildcard.io", "foo.bar.wildcard.io:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s2(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
						{
							Name:    "foo.wildcard.io",
							Domains: []string{"foo.wildcard.io", "foo.wildcard.io:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s2(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
						{
							Name:    "*.anotherwildcard.io",
							Domains: []string{"*.anotherwildcard.io", "*.anotherwildcard.io:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/s4(/.*)?$",
											},
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
			{Any: backendV3XDSResource},
		},
	},
}

// listenerHostnameMatchingHTTPListeners are the internal model for Conformance/HTTPRouteListenerHostnameMatching
var listenerHostnameMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "listener-1",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-2",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "foo.bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"foo.bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-3",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra"},
		},
		Port:     80,
		Hostname: "*.bar.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.bar.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "listener-4",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*.foo.com",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"*.foo.com"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

// listenerHostNameMatchingCiliumEnvoyConfig is the generated CiliumEnvoyConfig for Conformance/HTTPRouteListenerHostnameMatching
var listenerHostNameMatchingCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-httproute-listener-hostname-matching",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Name:       "httproute-listener-hostname-matching",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-httproute-listener-hostname-matching",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v3",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "bar.com",
							Domains: []string{"bar.com", "bar.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
						{
							Name:    "foo.bar.com",
							Domains: []string{"foo.bar.com", "foo.bar.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
						{
							Name:    "*.bar.com",
							Domains: []string{"*.bar.com", "*.bar.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV3,
								},
							},
						},
						{
							Name:    "*.foo.com",
							Domains: []string{"*.foo.com", "*.foo.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
									},
									Action: routeActionBackendV3,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
			{Any: backendV3XDSResource},
		},
	},
}

// matchingAcrossHTTPListeners is the internal model for Conformance/HTTPRouteMatchingAcrossHTTPListeners
var matchingAcrossHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{"example.com", "example.net"},
				PathMatch: model.StringMatch{Exact: "/"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Hostnames:    []string{"example.com"},
				PathMatch:    model.StringMatch{Exact: "/v2"},
				HeadersMatch: []model.KeyValueMatch{{Key: "version", Match: model.StringMatch{Exact: "two"}}},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var matchingAcrossHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "example.com",
							Domains: []string{"example.com", "example.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/v2",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "two",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV2,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "one",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},

						{
							Name:    "example.net",
							Domains: []string{"example.net", "example.net:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "one",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
		},
	},
}

// matchingHTTPListeners is the internal model for Conformance/HTTPRouteMatching
var matchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "one"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/v2"},
				HeadersMatch: []model.KeyValueMatch{
					{
						Key:   "version",
						Match: model.StringMatch{Exact: "two"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var matchingHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/v2",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "two",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV2,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: "version",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "one",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
		},
	},
}

// queryParamMatchingHTTPListeners is the internal model for Conformance/HTTPRouteQueryParamMatching
var queryParamMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "whale"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "dolphin"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "animal",
						Match: model.StringMatch{Exact: "dolphin"},
					},
					{
						Key:   "color",
						Match: model.StringMatch{Exact: "blue"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				QueryParamsMatch: []model.KeyValueMatch{
					{
						Key:   "ANIMAL",
						Match: model.StringMatch{Exact: "Whale"},
					},
				},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v3",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var queryParamMatchingHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v3",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
											{
												Name: "animal",
												QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "dolphin",
														},
													},
												},
											},
											{
												Name: "color",
												QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "blue",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV3,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
											{
												Name: "animal",
												QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "whale",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
											{
												Name: "animal",
												QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "dolphin",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV2,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{
											{
												Name: "ANIMAL",
												QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "Whale",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV3,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
			{Any: backendV3XDSResource},
		},
	},
}

// methodMatchingHTTPListeners is the internal representation of the Conformance/HTTPRouteMethodMatching
var methodMatchingHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Method: model.AddressOf("POST"),
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				Method: model.AddressOf("GET"),
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v2",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}
var methodMatchingHTTPListenersHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
			{
				Name:      "infra-backend-v2",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: ":method",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "POST",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
											Prefix: "/",
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: ":method",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
															Exact: "GET",
														},
													},
												},
											},
										},
									},
									Action: routeActionBackendV2,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
			{Any: backendV2XDSResource},
		},
	},
}

// requestHeaderModifierHTTPListeners is the internal model for Conformance/HTTPRouteRequestHeaderModifier
var requestHeaderModifierHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Exact: "/set"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "set-overwrites-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/add"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "add-appends-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/remove"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToRemove: []string{"X-Header-Remove"},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/multiple"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add-1",
							Value: "header-add-1",
						},
						{
							Name:  "X-Header-Add-2",
							Value: "header-add-2",
						},
						{
							Name:  "X-Header-Add-3",
							Value: "header-add-3",
						},
					},
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set-1",
							Value: "header-set-1",
						},
						{
							Name:  "X-Header-Set-2",
							Value: "header-set-2",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove-1",
						"X-Header-Remove-2",
					},
				},
			},
			{
				PathMatch: model.StringMatch{Exact: "/case-insensitivity"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestHeaderFilter: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "header-add",
						},
					},
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "header-set",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove",
					},
				},
			},
		},
	},
}
var requestHeaderModifierHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/case-insensitivity",
										},
									},
									RequestHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add",
												Value: "header-add",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set",
												Value: "header-set",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									RequestHeadersToRemove: []string{"X-Header-Remove"},
									Action:                 routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/multiple",
										},
									},
									RequestHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-1",
												Value: "header-add-1",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-2",
												Value: "header-add-2",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-3",
												Value: "header-add-3",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set-1",
												Value: "header-set-1",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set-2",
												Value: "header-set-2",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									RequestHeadersToRemove: []string{"X-Header-Remove-1", "X-Header-Remove-2"},
									Action:                 routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/remove",
										},
									},
									RequestHeadersToRemove: []string{"X-Header-Remove"},
									Action:                 routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/set",
										},
									},
									RequestHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set",
												Value: "set-overwrites-values",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/add",
										},
									},
									RequestHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add",
												Value: "add-appends-values",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
		},
	},
}

// requestRedirectHTTPListeners is the internal representation of the Conformance/HTTPRouteRequestRedirect
var requestRedirectHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Prefix: "/hostname-redirect"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					Hostname: model.AddressOf("example.com"),
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/status-code-301"},
				Backends:  []model.Backend{},
				DirectResponse: &model.DirectResponse{
					StatusCode: 500,
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					StatusCode: model.AddressOf(301),
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/host-and-status"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				RequestRedirect: &model.HTTPRequestRedirectFilter{
					Hostname:   model.AddressOf("example.com"),
					StatusCode: model.AddressOf(301),
				},
			},
		},
	},
}
var requestRedirectHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/hostname-redirect(/.*)?$",
											},
										},
									},
									Action: &envoy_config_route_v3.Route_Redirect{
										Redirect: &envoy_config_route_v3.RedirectAction{
											HostRedirect: "example.com",
										},
									},
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/status-code-301(/.*)?$",
											},
										},
									},
									Action: &envoy_config_route_v3.Route_Redirect{
										Redirect: &envoy_config_route_v3.RedirectAction{},
									},
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/host-and-status(/.*)?$",
											},
										},
									},
									Action: &envoy_config_route_v3.Route_Redirect{
										Redirect: &envoy_config_route_v3.RedirectAction{
											HostRedirect: "example.com",
										},
									},
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
		},
	},
}

// responseHeaderModifierHTTPListeners is the internal representation of the Conformance/HTTPRouteResponseHeaderModifier
var responseHeaderModifierHTTPListeners = []model.HTTPListener{
	{
		Name: "http",
		Sources: []model.FullyQualifiedResource{
			{
				Kind:      "Gateway",
				Name:      "same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		Port: 80, Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{Prefix: "/set"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "set-overwrites-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/add"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "add-appends-values",
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/remove"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToRemove: []string{"X-Header-Remove"},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/multiple"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add-1",
							Value: "header-add-1",
						},
						{
							Name:  "X-Header-Add-2",
							Value: "header-add-2",
						},
						{
							Name:  "X-Header-Add-3",
							Value: "header-add-3",
						},
					},
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set-1",
							Value: "header-set-1",
						},
						{
							Name:  "X-Header-Set-2",
							Value: "header-set-2",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove-1",
						"X-Header-Remove-2",
					},
				},
			},
			{
				PathMatch: model.StringMatch{Prefix: "/case-insensitivity"},
				Backends: []model.Backend{
					{
						Name:      "infra-backend-v1",
						Namespace: "gateway-conformance-infra",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToAdd: []model.Header{
						{
							Name:  "X-Header-Add",
							Value: "header-add",
						},
						{
							Name:  "x-lowercase-add",
							Value: "lowercase-add",
						},
						{
							Name:  "x-Mixedcase-ADD-1",
							Value: "mixedcase-add-1",
						},
						{
							Name:  "X-mixeDcase-add-2",
							Value: "mixedcase-add-2",
						},
						{
							Name:  "X-UPPERCASE-ADD",
							Value: "uppercase-add",
						},
					},
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "header-set",
						},
					},
					HeadersToRemove: []string{
						"X-Header-Remove",
					},
				},
			},
		},
	},
}
var responseHeaderModifierHTTPListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-gateway-same-namespace",
		Namespace: "gateway-conformance-infra",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "gateway.networking.k8s.io/v1beta1",
				Kind:       "Gateway",
				Name:       "same-namespace",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-gateway-same-namespace",
				Namespace: "gateway-conformance-infra",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: httpInsecureListenerXDSResource},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "*",
							Domains: []string{"*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/case-insensitivity(/.*)?$",
											},
										},
									},
									ResponseHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add",
												Value: "header-add",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "x-lowercase-add",
												Value: "lowercase-add",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "x-Mixedcase-ADD-1",
												Value: "mixedcase-add-1",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-mixeDcase-add-2",
												Value: "mixedcase-add-2",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-UPPERCASE-ADD",
												Value: "uppercase-add",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set",
												Value: "header-set",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									ResponseHeadersToRemove: []string{"X-Header-Remove"},
									Action:                  routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/multiple(/.*)?$",
											},
										},
									},
									ResponseHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-1",
												Value: "header-add-1",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-2",
												Value: "header-add-2",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add-3",
												Value: "header-add-3",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set-1",
												Value: "header-set-1",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set-2",
												Value: "header-set-2",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									ResponseHeadersToRemove: []string{"X-Header-Remove-1", "X-Header-Remove-2"},
									Action:                  routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/remove(/.*)?$",
											},
										},
									},
									ResponseHeadersToRemove: []string{"X-Header-Remove"},
									Action:                  routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/set(/.*)?$",
											},
										},
									},
									ResponseHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Set",
												Value: "set-overwrites-values",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
									Action: routeActionBackendV1,
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/add(/.*)?$",
											},
										},
									},
									ResponseHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{
										{
											Header: &envoy_config_core_v3.HeaderValue{
												Key:   "X-Header-Add",
												Value: "add-appends-values",
											},
											AppendAction: envoy_config_core_v3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
										},
									},
									Action: routeActionBackendV1,
								},
							},
						},
					},
				}),
			},
			{Any: backendV1XDSResource},
		},
	},
}

func toEnvoyCluster(namespace, name, port string) *envoy_config_cluster_v3.Cluster {
	return &envoy_config_cluster_v3.Cluster{
		Name: fmt.Sprintf("%s/%s:%s", namespace, name, port),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_upstreams_http_v3.HttpProtocolOptions{
				CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{Seconds: int64(60)},
				},
				UpstreamProtocolOptions: &envoy_upstreams_http_v3.HttpProtocolOptions_UseDownstreamProtocolConfig{
					UseDownstreamProtocolConfig: &envoy_upstreams_http_v3.HttpProtocolOptions_UseDownstreamHttpConfig{
						Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
					},
				},
			}),
		},
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		},
		ConnectTimeout: &durationpb.Duration{Seconds: int64(5)},
		LbPolicy:       envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
		OutlierDetection: &envoy_config_cluster_v3.OutlierDetection{
			SplitExternalLocalOriginErrors: true,
		},
	}
}

func toRouteAction(namespace, name, port string) *envoy_config_route_v3.Route_Route {
	return &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: fmt.Sprintf("%s/%s:%s", namespace, name, port),
			},
			MaxStreamDuration: &envoy_config_route_v3.RouteAction_MaxStreamDuration{
				MaxStreamDuration: &durationpb.Duration{Seconds: 0},
			},
		},
	}
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
