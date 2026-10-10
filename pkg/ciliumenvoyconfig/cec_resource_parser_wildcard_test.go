// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_config_healthcheck "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/health_check/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_types "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/envoy"
	envoyconfig "github.com/cilium/cilium/pkg/envoy/config"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestParseResourcesNormalizesWildcardPortNames(t *testing.T) {
	for _, mode := range []envoyconfig.XDSMode{
		envoyconfig.EnvoyXDSModeSplit,
		envoyconfig.EnvoyXDSModeDeltaSplit,
		envoyconfig.EnvoyXDSModeADS,
		envoyconfig.EnvoyXDSModeStrictADS,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			parser := CECResourceParser{logger: hivetest.Logger(t), xdsMode: mode}
			for _, tt := range []struct {
				name        string
				clusterName string
				serviceName string
				wantCluster string
				wantService string
			}{
				{"qualified", "backends/service:*", "backends/service:*", "backends/service", "backends/service"},
				{"local", "backend:*", "backends/service:*", "namespace/cec/backend", "backends/service"},
				{"implicit EDS name", "backends/service:*", "", "backends/service", ""},
				{"explicit port", "backends/service:80", "backends/service:80", "backends/service:80", "backends/service:80"},
				{"not a wildcard port", "backends/service:**", "backends/service:**", "backends/service:**", "backends/service:**"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					cluster := &envoy_config_cluster.Cluster{
						Name: tt.clusterName,
						ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
							Type: envoy_config_cluster.Cluster_EDS,
						},
						EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: tt.serviceName},
						LoadAssignment:   &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: tt.clusterName},
					}
					endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: tt.clusterName}
					for _, newResources := range []bool{true, false} {
						resources, err := parser.ParseResources("namespace", "cec", []cilium_v2.XDSResource{
							{Any: toAny(cluster)}, {Any: toAny(endpoint)},
						}, false, false, false, newResources)
						require.NoError(t, err)
						require.Len(t, resources.Clusters, 1)
						parsed := resources.Clusters[tt.wantCluster]
						require.NotNil(t, parsed)
						require.Equal(t, tt.wantService, parsed.GetEdsClusterConfig().GetServiceName())
						require.Equal(t, tt.wantCluster, parsed.GetLoadAssignment().GetClusterName())
						require.Len(t, resources.Endpoints, 1)
						require.NotNil(t, resources.Endpoints[tt.wantCluster])
						require.Equal(t, tt.wantCluster, resources.Endpoints[tt.wantCluster].ClusterName)
					}
					// Parsing owns the decoded messages, not the CRD's original resources.
					require.Equal(t, tt.clusterName, cluster.Name)
					require.Equal(t, tt.serviceName, cluster.EdsClusterConfig.ServiceName)
					require.Equal(t, tt.clusterName, endpoint.ClusterName)
				})
			}
		})
	}
}

func TestParseResourcesNormalizesWildcardPortReferences(t *testing.T) {
	const clusterName = "backends/service:*"
	const normalizedName = "backends/service"
	// Already-qualified route/vhost names make suffix removal the only reason
	// to re-encode an inline route configuration. Their own suffixes must survive.
	route := &envoy_config_route.RouteConfiguration{
		Name: "namespace/cec/routes:*",
		VirtualHosts: []*envoy_config_route.VirtualHost{{
			Name:    "namespace/cec/vhost:*",
			Domains: []string{"*"},
			Routes: []*envoy_config_route.Route{
				{
					Match: &envoy_config_route.RouteMatch{PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"}},
					Action: &envoy_config_route.Route_Route{Route: &envoy_config_route.RouteAction{
						ClusterSpecifier:      &envoy_config_route.RouteAction_Cluster{Cluster: clusterName},
						RequestMirrorPolicies: []*envoy_config_route.RouteAction_RequestMirrorPolicy{{Cluster: clusterName}},
					}},
				},
				{
					Match: &envoy_config_route.RouteMatch{PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/weighted"}},
					Action: &envoy_config_route.Route_Route{Route: &envoy_config_route.RouteAction{
						ClusterSpecifier: &envoy_config_route.RouteAction_WeightedClusters{
							WeightedClusters: &envoy_config_route.WeightedCluster{
								Clusters: []*envoy_config_route.WeightedCluster_ClusterWeight{{Name: clusterName, Weight: wrapperspb.UInt32(1)}},
							},
						},
					}},
				},
			},
		}},
	}
	checkRoutes := func(t *testing.T, parsed *envoy_config_route.RouteConfiguration) {
		t.Helper()
		require.Equal(t, route.Name, parsed.Name)
		require.Equal(t, route.VirtualHosts[0].Name, parsed.VirtualHosts[0].Name)
		routes := parsed.VirtualHosts[0].Routes
		require.Equal(t, normalizedName, routes[0].GetRoute().GetCluster())
		require.Equal(t, normalizedName, routes[0].GetRoute().RequestMirrorPolicies[0].Cluster)
		require.Equal(t, normalizedName, routes[1].GetRoute().GetWeightedClusters().Clusters[0].Name)
	}
	httpFilterConfig := func(name string, config proto.Message) *envoy_config_http.HttpConnectionManager {
		return &envoy_config_http.HttpConnectionManager{
			StatPrefix: "http",
			RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{
				RouteConfigName: "namespace/cec/routes",
				ConfigSource:    envoy.CiliumXDSConfigSource,
			}},
			HttpFilters: []*envoy_config_http.HttpFilter{{
				Name:       name,
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{TypedConfig: toAny(config)},
			}},
		}
	}

	for _, tt := range []struct {
		name   string
		config proto.Message
		check  func(*testing.T, proto.Message)
	}{
		{
			name: "inline HTTP routes",
			config: &envoy_config_http.HttpConnectionManager{
				StatPrefix:     "http",
				RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{RouteConfig: route},
			},
			check: func(t *testing.T, config proto.Message) {
				checkRoutes(t, config.(*envoy_config_http.HttpConnectionManager).GetRouteConfig())
			},
		},
		{
			name: "direct TCP cluster",
			config: &envoy_config_tcp.TcpProxy{
				StatPrefix:       "tcp",
				ClusterSpecifier: &envoy_config_tcp.TcpProxy_Cluster{Cluster: clusterName},
			},
			check: func(t *testing.T, config proto.Message) {
				require.Equal(t, normalizedName, config.(*envoy_config_tcp.TcpProxy).GetCluster())
			},
		},
		{
			name: "weighted TCP clusters",
			config: &envoy_config_tcp.TcpProxy{
				StatPrefix: "tcp",
				ClusterSpecifier: &envoy_config_tcp.TcpProxy_WeightedClusters{
					WeightedClusters: &envoy_config_tcp.TcpProxy_WeightedCluster{
						Clusters: []*envoy_config_tcp.TcpProxy_WeightedCluster_ClusterWeight{{Name: clusterName, Weight: 1}},
					},
				},
			},
			check: func(t *testing.T, config proto.Message) {
				require.Equal(t, normalizedName, config.(*envoy_config_tcp.TcpProxy).GetWeightedClusters().Clusters[0].Name)
			},
		},
		{
			name: "health check clusters",
			config: httpFilterConfig("envoy.filters.http.health_check", &envoy_config_healthcheck.HealthCheck{
				PassThroughMode: wrapperspb.Bool(true),
				ClusterMinHealthyPercentages: map[string]*envoy_config_types.Percent{
					clusterName: {Value: 50},
				},
			}),
			check: func(t *testing.T, config proto.Message) {
				var healthCheck envoy_config_healthcheck.HealthCheck
				require.NoError(t, config.(*envoy_config_http.HttpConnectionManager).HttpFilters[0].GetTypedConfig().UnmarshalTo(&healthCheck))
				require.Len(t, healthCheck.ClusterMinHealthyPercentages, 1)
				require.NotNil(t, healthCheck.ClusterMinHealthyPercentages[normalizedName])
				require.Equal(t, float64(50), healthCheck.ClusterMinHealthyPercentages[normalizedName].Value)
			},
		},
		{
			name: "gRPC ext_authz cluster",
			config: httpFilterConfig("envoy.filters.http.ext_authz", &extauthzv3.ExtAuthz{
				Services: &extauthzv3.ExtAuthz_GrpcService{GrpcService: &envoy_config_core.GrpcService{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{ClusterName: clusterName},
					},
				}},
			}),
			check: func(t *testing.T, config proto.Message) {
				var auth extauthzv3.ExtAuthz
				require.NoError(t, config.(*envoy_config_http.HttpConnectionManager).HttpFilters[0].GetTypedConfig().UnmarshalTo(&auth))
				require.Equal(t, normalizedName, auth.GetGrpcService().GetEnvoyGrpc().GetClusterName())
			},
		},
		{
			name: "HTTP ext_authz cluster",
			config: httpFilterConfig("envoy.filters.http.ext_authz", &extauthzv3.ExtAuthz{
				Services: &extauthzv3.ExtAuthz_HttpService{HttpService: &extauthzv3.HttpService{
					ServerUri: &envoy_config_core.HttpUri{
						Uri:              "http://auth",
						HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{Cluster: clusterName},
					},
				}},
			}),
			check: func(t *testing.T, config proto.Message) {
				var auth extauthzv3.ExtAuthz
				require.NoError(t, config.(*envoy_config_http.HttpConnectionManager).HttpFilters[0].GetTypedConfig().UnmarshalTo(&auth))
				require.Equal(t, normalizedName, auth.GetHttpService().GetServerUri().GetCluster())
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parser := CECResourceParser{logger: hivetest.Logger(t), xdsMode: envoyconfig.EnvoyXDSModeADS}
			// An explicit address disables downstream filter injection, so this
			// exercises re-encoding triggered by suffix normalization alone.
			listener := &envoy_config_listener.Listener{
				Name: "listener",
				Address: &envoy_config_core.Address{Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Address: "127.0.0.1", PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: 12345},
					},
				}},
				FilterChains: []*envoy_config_listener.FilterChain{{Filters: []*envoy_config_listener.Filter{{
					Name:       tt.name,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: toAny(tt.config)},
				}}}},
			}
			resources, err := parser.ParseResources("namespace", "cec", []cilium_v2.XDSResource{
				{Any: toAny(listener)}, {Any: toAny(route)},
			}, false, false, false, true)
			require.NoError(t, err)
			checkRoutes(t, resources.Routes[route.Name])
			parsed := tt.config.ProtoReflect().New().Interface()
			require.NoError(t, resources.Listeners["namespace/cec/listener"].FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(parsed))
			tt.check(t, parsed)
		})
	}
}

func TestParseResourcesRejectsNormalizedWildcardPortNames(t *testing.T) {
	parser := CECResourceParser{logger: hivetest.Logger(t)}
	for _, tt := range []struct {
		name     string
		resource func(string) proto.Message
	}{
		{"Cluster", func(name string) proto.Message { return &envoy_config_cluster.Cluster{Name: name} }},
		{"ClusterLoadAssignment", func(name string) proto.Message {
			return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, newResources := range []bool{true, false} {
				_, err := parser.ParseResources("namespace", "cec", []cilium_v2.XDSResource{
					{Any: toAny(tt.resource("backends/service:*"))},
					{Any: toAny(tt.resource("backends/service"))},
				}, false, false, false, newResources)
				require.ErrorContains(t, err, "duplicate")
				_, err = parser.ParseResources("namespace", "cec", []cilium_v2.XDSResource{
					{Any: toAny(tt.resource(":*"))},
				}, false, false, false, newResources)
				require.ErrorContains(t, err, "unspecified")
			}
		})
	}
}

func TestParseResourcesRejectsNormalizedHealthCheckNameCollisions(t *testing.T) {
	for _, mode := range []envoyconfig.XDSMode{
		envoyconfig.EnvoyXDSModeSplit,
		envoyconfig.EnvoyXDSModeDeltaSplit,
		envoyconfig.EnvoyXDSModeADS,
		envoyconfig.EnvoyXDSModeStrictADS,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			for _, namespace := range []string{"namespace", ""} {
				scope := "CEC"
				if namespace == "" {
					scope = "CCEC"
				}
				t.Run(scope, func(t *testing.T) {
					for _, tt := range []struct {
						name      string
						names     []string
						wantNames []string // nil means normalization must reject a collision.
					}{
						{"qualified aliases", []string{"backends/service", "backends/service:*"}, nil},
						{"local aliases", []string{"backend", "backend:*"}, nil},
						{"qualified and local aliases", []string{namespace + "/cec/backend", "backend:*"}, nil},
						{"distinct ports", []string{"backends/service:80", "backends/service:81"}, []string{"backends/service:80", "backends/service:81"}},
						{"distinct services", []string{"backends/service:*", "backends/other"}, []string{"backends/service", "backends/other"}},
					} {
						t.Run(tt.name, func(t *testing.T) {
							thresholds := make(map[string]*envoy_config_types.Percent, len(tt.names))
							for i, name := range tt.names {
								thresholds[name] = &envoy_config_types.Percent{Value: float64(25 * (i + 1))}
							}
							healthCheck := &envoy_config_healthcheck.HealthCheck{
								PassThroughMode:              wrapperspb.Bool(true),
								ClusterMinHealthyPercentages: thresholds,
							}
							hcm := &envoy_config_http.HttpConnectionManager{
								StatPrefix: "http",
								RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{
									RouteConfigName: namespace + "/cec/routes",
									ConfigSource:    envoy.CiliumXDSConfigSource,
								}},
								HttpFilters: []*envoy_config_http.HttpFilter{{
									Name:       "envoy.filters.http.health_check",
									ConfigType: &envoy_config_http.HttpFilter_TypedConfig{TypedConfig: toAny(healthCheck)},
								}},
							}
							listener := &envoy_config_listener.Listener{
								Name: "listener",
								FilterChains: []*envoy_config_listener.FilterChain{{Filters: []*envoy_config_listener.Filter{{
									Name:       "envoy.filters.network.http_connection_manager",
									ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: toAny(hcm)},
								}}}},
							}
							allocator := NewMockPortAllocator()
							parser := CECResourceParser{logger: hivetest.Logger(t), xdsMode: mode, portAllocator: allocator}
							resources, err := parser.ParseResources(namespace, "cec", []cilium_v2.XDSResource{
								{Any: toAny(listener)},
							}, false, false, false, true)
							if tt.wantNames == nil {
								require.ErrorContains(t, err, "duplicate health-check Cluster name")
								require.Empty(t, resources.Listeners)
								// Reject before allocating a listener port or publishing any resources.
								require.Empty(t, allocator.ports)
								return
							}
							require.NoError(t, err)
							parsedListener := resources.Listeners[namespace+"/cec/listener"]
							require.NotNil(t, parsedListener)
							for _, filter := range parsedListener.FilterChains[0].Filters {
								if !filter.GetTypedConfig().MessageIs(hcm) {
									continue
								}
								var parsedHCM envoy_config_http.HttpConnectionManager
								require.NoError(t, filter.GetTypedConfig().UnmarshalTo(&parsedHCM))
								var parsedHealthCheck envoy_config_healthcheck.HealthCheck
								require.NoError(t, parsedHCM.HttpFilters[0].GetTypedConfig().UnmarshalTo(&parsedHealthCheck))
								require.Len(t, parsedHealthCheck.ClusterMinHealthyPercentages, len(tt.wantNames))
								for i, name := range tt.wantNames {
									require.NotNil(t, parsedHealthCheck.ClusterMinHealthyPercentages[name])
									require.Equal(t, float64(25*(i+1)), parsedHealthCheck.ClusterMinHealthyPercentages[name].Value)
								}
								return
							}
							t.Fatal("parsed listener is missing its HTTP connection manager")
						})
					}
				})
			}
		})
	}
}
