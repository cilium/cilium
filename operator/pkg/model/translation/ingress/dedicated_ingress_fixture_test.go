// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

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
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var socketOptions = []*envoy_config_core_v3.SocketOption{
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

func toWeightedClusterRouteAction(names []string) *envoy_config_route_v3.Route_Route {
	weightedClusters := make([]*envoy_config_route_v3.WeightedCluster_ClusterWeight, 0, len(names))
	for _, name := range names {
		weightedClusters = append(weightedClusters, &envoy_config_route_v3.WeightedCluster_ClusterWeight{
			Name:   name,
			Weight: &wrapperspb.UInt32Value{Value: 1},
		})
	}

	return &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_WeightedClusters{
				WeightedClusters: &envoy_config_route_v3.WeightedCluster{
					Clusters: weightedClusters,
				},
			},
			MaxStreamDuration: &envoy_config_route_v3.RouteAction_MaxStreamDuration{
				MaxStreamDuration: &durationpb.Duration{Seconds: 0},
			},
		},
	}
}

func toHTTPSRedirectAction() *envoy_config_route_v3.Route_Redirect {
	return &envoy_config_route_v3.Route_Redirect{
		Redirect: &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: true,
			},
		},
	}
}

func toListenerFilter(name string) *envoy_config_listener.Filter {
	return &envoy_config_listener.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: toAny(&http_connection_manager_v3.HttpConnectionManager{
				StatPrefix: name,
				RouteSpecifier: &http_connection_manager_v3.HttpConnectionManager_Rds{
					Rds: &http_connection_manager_v3.Rds{RouteConfigName: name},
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
	}
}

func toSecureListenerFilterChain(serverNames []string, certName string) *envoy_config_listener.FilterChain {
	return &envoy_config_listener.FilterChain{
		FilterChainMatch: &envoy_config_listener.FilterChainMatch{
			ServerNames:       serverNames,
			TransportProtocol: "tls",
		},
		Filters: []*envoy_config_listener.Filter{
			toListenerFilter("listener-secure"),
		},
		TransportSocket: &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
					CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
							{
								Name: certName,
								SdsConfig: &envoy_config_core_v3.ConfigSource{
									ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
										ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
											ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
											TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
											GrpcServices: []*envoy_config_core_v3.GrpcService{
												{
													TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
															ClusterName: envoy.CiliumXDSClusterName,
														},
													},
												},
											},
										},
									},
									ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
								},
							},
						},
					},
				}),
			},
		},
	}
}

func toInsecureListenerFilterChain() *envoy_config_listener.FilterChain {
	return &envoy_config_listener.FilterChain{
		FilterChainMatch: &envoy_config_listener.FilterChainMatch{
			TransportProtocol: "raw_buffer",
		},
		Filters: []*envoy_config_listener.Filter{
			toListenerFilter("listener-insecure"),
		},
	}
}

func toHTTPListenerXDSResource() *anypb.Any {
	return toAny(&envoy_config_listener.Listener{
		Name: "listener",
		FilterChains: []*envoy_config_listener.FilterChain{
			toInsecureListenerFilterChain(),
		},
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
		},
		SocketOptions: socketOptions,
	})
}

func toBothListenersXDSResource(serverNames []string, certName string) *anypb.Any {
	return toAny(&envoy_config_listener.Listener{
		Name: "listener",
		FilterChains: []*envoy_config_listener.FilterChain{
			toInsecureListenerFilterChain(),
			toSecureListenerFilterChain(serverNames, certName),
		},
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
		},
		SocketOptions: socketOptions,
	})
}

// Ingress Conformance test resources

// Conformance/DefaultBackend test
var defaultBackendListeners = []model.HTTPListener{
	{
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "load-balancing",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Backends: []model.Backend{
					{
						Name:      "default-backend",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var defaultBackendListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-ingress-random-namespace-load-balancing",
		Namespace: "random-namespace",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "Ingress",
				Name:       "load-balancing",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-ingress-load-balancing",
				Namespace: "random-namespace",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "default-backend",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: toHTTPListenerXDSResource()},
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
									Action: toRouteAction("random-namespace", "default-backend", "8080"),
								},
							},
						},
					},
				}),
			},
			{Any: toAny(toEnvoyCluster("random-namespace", "default-backend", "8080"))},
		},
	},
}

// Conformance/HostRules test
var hostRulesListeners = []model.HTTPListener{
	{
		Name: "ing-host-rules-random-namespace-*.foo.com",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "host-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "*.foo.com",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/",
				},
				Backends: []model.Backend{
					{
						Name:      "wildcard-foo-com",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "ing-host-rules-random-namespace-foo.bar.com",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "host-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "foo.bar.com",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-bar-com",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Name: "http",
						},
					},
				},
			},
		},
	},
	{
		Name: "ing-host-rules-random-namespace-foo.bar.com",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "host-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     443,
		Hostname: "foo.bar.com",
		TLS: []model.TLSSecret{
			{
				Name:      "conformance-tls",
				Namespace: "random-namespace",
			},
		},
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-bar-com",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Name: "http",
						},
					},
				},
			},
		},
	},
}

var hostRulesListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-ingress-random-namespace-host-rules",
		Namespace: "random-namespace",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "Ingress",
				Name:       "host-rules",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-ingress-host-rules",
				Namespace: "random-namespace",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "foo-bar-com",
				Namespace: "random-namespace",
				Ports:     []string{"http"},
			},
			{
				Name:      "wildcard-foo-com",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: toBothListenersXDSResource([]string{"foo.bar.com"}, "cilium-secrets/random-namespace-conformance-tls")},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "foo.bar.com",
							Domains: []string{"foo.bar.com", "foo.bar.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "(/.*)?$",
											},
										},
									},
									Action: toHTTPSRedirectAction(),
								},
							},
						},
						{
							Name:    "*.foo.com",
							Domains: []string{"*.foo.com", "*.foo.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "(/.*)?$",
											},
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												Name: ":authority",
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
													StringMatch: &envoy_type_matcher_v3.StringMatcher{
														MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
															SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
																Regex: "^[^.]+[.]foo[.]com$",
															},
														},
													},
												},
											},
										},
										QueryParameters: []*envoy_config_route_v3.QueryParameterMatcher{},
									},
									Action: toRouteAction("random-namespace", "wildcard-foo-com", "8080"),
								},
							},
						},
					},
				}),
			},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-secure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "foo.bar.com",
							Domains: []string{"foo.bar.com", "foo.bar.com:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "(/.*)?$",
											},
										},
									},
									Action: toWeightedClusterRouteAction([]string{
										"random-namespace/foo-bar-com:http",
										"random-namespace/foo-bar-com:http",
									}),
								},
							},
						},
					},
				}),
			},
			{Any: toAny(toEnvoyCluster("random-namespace", "foo-bar-com", "http"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "wildcard-foo-com", "8080"))},
		},
	},
}

// Conformance/PathRules test
var pathRulesListeners = []model.HTTPListener{
	{
		Name: "ing-path-rules-random-namespace-exact-path-rules",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "path-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "exact-path-rules",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Exact: "/foo",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-exact",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "ing-path-rules-random-namespace-mixed-path-rules",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "path-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "mixed-path-rules",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/foo",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-prefix",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{
					Exact: "/foo",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-exact",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "ing-path-rules-random-namespace-prefix-path-rules",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "path-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "prefix-path-rules",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/foo",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-prefix",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{
					Prefix: "/aaa/bbb",
				},
				Backends: []model.Backend{
					{
						Name:      "aaa-slash-bbb-prefix",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{
					Prefix: "/aaa",
				},
				Backends: []model.Backend{
					{
						Name:      "aaa-prefix",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
	{
		Name: "ing-path-rules-random-namespace-trailing-slash-path-rules",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "path-rules",
				Namespace: "random-namespace",
				Version:   "networking.k8s.io/v1",
				Kind:      "Ingress",
			},
		},
		Port:     80,
		Hostname: "trailing-slash-path-rules",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/aaa/bbb/",
				},
				Backends: []model.Backend{
					{
						Name:      "aaa-slash-bbb-slash-prefix",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
			{
				PathMatch: model.StringMatch{
					Exact: "/foo/",
				},
				Backends: []model.Backend{
					{
						Name:      "foo-slash-exact",
						Namespace: "random-namespace",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

var pathRulesListenersCiliumEnvoyConfig = &ciliumv2.CiliumEnvoyConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "cilium-ingress-random-namespace-path-rules",
		Namespace: "random-namespace",
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "Ingress",
				Name:       "path-rules",
			},
		},
	},
	Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Services: []*ciliumv2.ServiceListener{
			{
				Name:      "cilium-ingress-path-rules",
				Namespace: "random-namespace",
			},
		},
		BackendServices: []*ciliumv2.Service{
			{
				Name:      "aaa-prefix",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
			{
				Name:      "aaa-slash-bbb-prefix",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
			{
				Name:      "aaa-slash-bbb-slash-prefix",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
			{
				Name:      "foo-exact",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
			{
				Name:      "foo-prefix",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
			{
				Name:      "foo-slash-exact",
				Namespace: "random-namespace",
				Ports:     []string{"8080"},
			},
		},
		Resources: []ciliumv2.XDSResource{
			{Any: toHTTPListenerXDSResource()},
			{
				Any: toAny(&envoy_config_route_v3.RouteConfiguration{
					Name: "listener-insecure",
					VirtualHosts: []*envoy_config_route_v3.VirtualHost{
						{
							Name:    "exact-path-rules",
							Domains: []string{"exact-path-rules", "exact-path-rules:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/foo",
										},
									},
									Action: toRouteAction("random-namespace", "foo-exact", "8080"),
								},
							},
						},
						{
							Name:    "mixed-path-rules",
							Domains: []string{"mixed-path-rules", "mixed-path-rules:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/foo",
										},
									},
									Action: toRouteAction("random-namespace", "foo-exact", "8080"),
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/foo(/.*)?$",
											},
										},
									},
									Action: toRouteAction("random-namespace", "foo-prefix", "8080"),
								},
							},
						},
						{
							Name:    "prefix-path-rules",
							Domains: []string{"prefix-path-rules", "prefix-path-rules:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/aaa/bbb(/.*)?$",
											},
										},
									},
									Action: toRouteAction("random-namespace", "aaa-slash-bbb-prefix", "8080"),
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/foo(/.*)?$",
											},
										},
									},
									Action: toRouteAction("random-namespace", "foo-prefix", "8080"),
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/aaa(/.*)?$",
											},
										},
									},
									Action: toRouteAction("random-namespace", "aaa-prefix", "8080"),
								},
							},
						},
						{
							Name:    "trailing-slash-path-rules",
							Domains: []string{"trailing-slash-path-rules", "trailing-slash-path-rules:*"},
							Routes: []*envoy_config_route_v3.Route{
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
											Path: "/foo/",
										},
									},
									Action: toRouteAction("random-namespace", "foo-slash-exact", "8080"),
								},
								{
									Match: &envoy_config_route_v3.RouteMatch{
										PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
											SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
												Regex: "/aaa/bbb(/.*)?$",
											},
										},
									},
									Action: toRouteAction("random-namespace", "aaa-slash-bbb-slash-prefix", "8080"),
								},
							},
						},
					},
				}),
			},
			{Any: toAny(toEnvoyCluster("random-namespace", "aaa-prefix", "8080"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "aaa-slash-bbb-prefix", "8080"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "aaa-slash-bbb-slash-prefix", "8080"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "foo-exact", "8080"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "foo-prefix", "8080"))},
			{Any: toAny(toEnvoyCluster("random-namespace", "foo-slash-exact", "8080"))},
		},
	},
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
