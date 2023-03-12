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
	envoy_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
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

func toEnvoyCluster(namespace, name, port string) *envoy_config_cluster_v3.Cluster {
	return &envoy_config_cluster_v3.Cluster{
		Name: fmt.Sprintf("%s/%s:%s", namespace, name, port),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_upstreams_http_v3.HttpProtocolOptions{
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
