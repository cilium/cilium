// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

var (
	DEFAULT_CLA = envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: "cluster1",
		Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
			{
				Locality: &envoy_config_core_v3.Locality{
					Region:  "us-west",
					Zone:    "us-west-1",
					SubZone: "us-west-1a",
				},
			},
		},
	}

	DEFAULT_RESOURCES = xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
				FilterChains: []*envoy_config_listener.FilterChain{{
					Filters: []*envoy_config_listener.Filter{{
						Name: "envoy.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(&envoy_config_http.HttpConnectionManager{
								StatPrefix: "http_proxy",
								RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
									Rds: &envoy_config_http.Rds{
										RouteConfigName: "routeConfig1",
									},
								},
							}),
						},
					}},
				}},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name:           "cluster1",
				LoadAssignment: &DEFAULT_CLA,
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
					Type: *envoy_config_cluster.Cluster_EDS.Enum(),
				},
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{
			"secret1": {
				Name: "secret1",
			},
		},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
		},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
			"endpoint1": &DEFAULT_CLA,
		},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"40": {
				EndpointId:  40,
				EndpointIps: []string{"10.0.0.1"},
			},
		},
	}
)

func TestNewADSServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		metrics:              nil,
	}

	server := newADSServer(logger, nil, nil, config, nil)

	require.NotNil(t, server)
	require.NotNil(t, server.logger)
	require.NotNil(t, &server.cache)
	assert.NotEmpty(t, server.socketPath)
	assert.NotEmpty(t, server.accessLogPath)
}

func TestAddListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()

	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		if err != nil {
			t.Logf("callback received error: %v", err)
		}
	})

	require.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.NotNil(t, resources)
	require.Len(t, resources.Listeners, 1)

	actualListener := resources.Listeners["test-listener"]
	require.NotNil(t, actualListener)

	// Build the expected listener via the same production code path.
	expectedListener := server.getListenerConf("test-listener", policy.ParserTypeHTTP, 8080, false, false)

	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.ListenerFilters, 2, "expected tls_inspector + cilium.bpf_metadata listener filters")
	assert.Equal(t, "envoy.filters.listener.tls_inspector", actualListener.ListenerFilters[0].Name)
	assert.Equal(t, "cilium.bpf_metadata", actualListener.ListenerFilters[1].Name)
	assert.Len(t, actualListener.FilterChains, 2, "expected plain + TLS HTTP filter chains")
	assert.True(t, proto.Equal(expectedListener.FilterChains[0], actualListener.FilterChains[0]))
	assert.True(t, proto.Equal(expectedListener.FilterChains[1], actualListener.FilterChains[1]))
}

func TestAddAdminListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddAdminListener(ctx, 0, wg)

	// Test with valid port
	server.AddAdminListener(ctx, 9000, wg)

	resources := cache.GetAllResources(localNodeID)
	actualListener := resources.Listeners["envoy-admin-listener"]

	// Build the expected listener via the same production code path.
	expectedListener := server.getAdminListenerConfig(9000)

	require.NotNil(t, actualListener)
	require.Len(t, resources.Listeners, 1)
	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.FilterChains, 1)
	assert.Len(t, actualListener.FilterChains[0].Filters, 1, "Expected http cpnnection manager filter")
	assert.Equal(t, "envoy.filters.network.http_connection_manager", actualListener.FilterChains[0].Filters[0].Name)
}

func TestAddMetricsListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddMetricsListener(ctx, 0, wg)

	// Test with valid port
	server.AddMetricsListener(ctx, 9001, wg)

	resources := cache.GetAllResources(localNodeID)
	actualListener := resources.Listeners["envoy-prometheus-metrics-listener"]

	// Build the expected listener via the same production code path.
	expectedListener := server.getMetricsListenerConfig(9001)

	require.NotNil(t, actualListener)
	require.Len(t, resources.Listeners, 1)
	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.FilterChains, 1)
}

func TestRemoveListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {})
	require.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["test-listener"])

	revertFunc := server.RemoveListener(ctx, "test-listener", wg)
	assert.NotNil(t, revertFunc)
	require.Len(t, resources.Listeners, 0)
}

// TestUpsertEnvoyResources verifies that Envoy resources can be upserted
func TestUpsertEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()

	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["listener1"])
	require.Len(t, resources.Clusters, 1)
	require.NotNil(t, resources.Clusters["cluster1"])
	require.Len(t, resources.Secrets, 1)
	require.NotNil(t, resources.Secrets["secret1"])
	require.Len(t, resources.Routes, 1)
	require.NotNil(t, resources.Routes["routeConfig1"])
	require.Len(t, resources.Endpoints, 1)
	require.NotNil(t, resources.Endpoints["endpoint1"])
	require.Len(t, resources.NetworkPolicies, 1)
	require.NotNil(t, resources.NetworkPolicies["40"])
}

func TestUpdateEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()

	oldResources := DEFAULT_RESOURCES

	// In the resource new version, second route was added and all secrets got cleared.
	newResources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
				FilterChains: []*envoy_config_listener.FilterChain{{
					Filters: []*envoy_config_listener.Filter{
						{
							Name: "envoy.http_connection_manager",
							ConfigType: &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(&envoy_config_http.HttpConnectionManager{
									StatPrefix: "http_proxy",
									RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
										Rds: &envoy_config_http.Rds{
											RouteConfigName: "routeConfig1",
										},
									},
								}),
							},
						},
						{
							Name: "envoy.http_connection_manager",
							ConfigType: &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(&envoy_config_http.HttpConnectionManager{
									StatPrefix: "http_proxy",
									RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
										Rds: &envoy_config_http.Rds{
											RouteConfigName: "routeConfig2",
										},
									},
								}),
							},
						},
					},
				}},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name:           "cluster1",
				LoadAssignment: &DEFAULT_CLA,
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
					Type: *envoy_config_cluster.Cluster_EDS.Enum(),
				},
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
			"routeConfig2": {
				Name: "routeConfig2",
			},
		},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
			"endpoint1": &DEFAULT_CLA,
		},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"40": {
				EndpointId: 40,
			},
		},
	}

	err := server.UpdateEnvoyResources(ctx, oldResources, newResources)
	assert.NoError(t, err)
	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["listener1"])
	require.Len(t, resources.Clusters, 1)
	require.NotNil(t, resources.Clusters["cluster1"])
	require.Len(t, resources.Secrets, 0)
	require.Len(t, resources.Routes, 2)
	require.NotNil(t, resources.Routes["routeConfig1"])
	require.NotNil(t, resources.Routes["routeConfig2"])
	require.Len(t, resources.Endpoints, 1)
	require.NotNil(t, resources.Endpoints["endpoint1"])
	require.Len(t, resources.NetworkPolicies, 1)
	require.NotNil(t, resources.NetworkPolicies["40"])
}

func TestDeleteEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()

	xdsResources := xds.Resources{
		Listeners:       map[string]*envoy_config_listener.Listener{},
		Clusters:        map[string]*envoy_config_cluster.Cluster{},
		Routes:          map[string]*envoy_config_route.RouteConfiguration{},
		Endpoints:       map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		Secrets:         map[string]*envoy_config_tls.Secret{},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{},
	}

	// Deleting empty resources should be no-op.
	err := server.DeleteEnvoyResources(ctx, xdsResources)
	assert.NoError(t, err)
	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 0)
	require.Len(t, resources.Clusters, 0)
	require.Len(t, resources.Routes, 0)
	require.Len(t, resources.Endpoints, 0)
	require.Len(t, resources.Secrets, 0)
	require.Len(t, resources.NetworkPolicies, 0)

	// Add some resources and then delete them.
	err = server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)

	resources = cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["listener1"])
	require.Len(t, resources.Clusters, 1)
	require.NotNil(t, resources.Clusters["cluster1"])
	require.Len(t, resources.Secrets, 1)
	require.NotNil(t, resources.Secrets["secret1"])
	require.Len(t, resources.Routes, 1)
	require.NotNil(t, resources.Routes["routeConfig1"])
	require.Len(t, resources.Endpoints, 1)
	require.NotNil(t, resources.Endpoints["endpoint1"])
	require.Len(t, resources.NetworkPolicies, 1)
	require.NotNil(t, resources.NetworkPolicies["40"])

	err = server.DeleteEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)
	resources = cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 0)
	require.Len(t, resources.Clusters, 0)
	require.Len(t, resources.Routes, 0)
	require.Len(t, resources.Endpoints, 0)
	require.Len(t, resources.Secrets, 0)
	require.Len(t, resources.NetworkPolicies, 0)
}

func TestGetNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil)
	ctx := context.Background()

	server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)

	// Get all network policies
	policies, err := server.GetNetworkPolicies(nil)
	assert.NoError(t, err)
	assert.NotNil(t, policies)

	policies, err = server.GetNetworkPolicies([]string{"40"})
	assert.NoError(t, err)
	assert.NotNil(t, policies)

	policies, err = server.GetNetworkPolicies([]string{"nonexistent"})
	assert.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Len(t, policies, 0)
}

// func TestUseCurrentNetworkPolicy(t *testing.T) {
// 	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
// 	config := adsServerConfig{
// 		envoySocketDir:       t.TempDir(),
// 		policyRestoreTimeout: 30 * time.Second,
// 	}

// 	server := newADSServer(logger, nil, nil, config, nil)
// 	ctx := context.Background()
// 	wg := completion.NewWaitGroup(ctx)

// 	// Create a mock endpoint updater
// 	mockEp := &mockEndpointUpdater{}

// 	// Create a mock policy
// 	mockPolicy := &policy.EndpointPolicy{}

// 	// Should not panic
// 	server.UseCurrentNetworkPolicy(mockEp, mockPolicy, wg)
// }

func TestUpdateNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline())
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &mockEndpointUpdater{}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertFunc)
	}

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 2)
	require.NotNil(t, resources.NetworkPolicies["40"])
	assert.Equal(t, uint64(40), resources.NetworkPolicies["40"].EndpointId)
	require.NotNil(t, resources.NetworkPolicies["1"])
	assert.Equal(t, uint64(1), resources.NetworkPolicies["1"].EndpointId)
}

func TestRemoveNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, nil)

	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 1)

	// Create a mock endpoint info source
	mockEp := &mockEndpointInfoSource{}

	// Should not panic
	server.RemoveNetworkPolicy(ctx, mockEp)

	resources = cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 0)
}

// TestRemoveAllNetworkPolicies verifies that all network policies can be removed
func TestRemoveAllNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := adsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline())
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &mockEndpointUpdater{}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertFunc)
	}

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 2)
	require.NotNil(t, resources.NetworkPolicies["40"])
	require.NotNil(t, resources.NetworkPolicies["1"])

	server.RemoveAllNetworkPolicies()
	resources = cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 0)
}

// Mock types for testing

type mockEndpointUpdater struct{}

func (m *mockEndpointUpdater) GetID() uint64 {
	return 1
}

func (m *mockEndpointUpdater) GetIPv4Address() string {
	return "127.0.0.1"
}

func (m *mockEndpointUpdater) GetIPv6Address() string {
	return ""
}

func (m *mockEndpointUpdater) GetPolicyNames() []string {
	return []string{"127.0.0.1"}
}

func (m *mockEndpointUpdater) GetPolicySelectors() policy.SelectorSnapshot {
	return types.MockSelectorSnapshot()
}

func (m *mockEndpointUpdater) OnProxyPolicyUpdate(revision uint64) {
}

func (m *mockEndpointUpdater) UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool,
	verdict accesslog.FlowVerdict) {
}

func (m *mockEndpointUpdater) GetListenerProxyPort(listener string) uint16 {
	return 0
}

func (m *mockEndpointUpdater) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 0
}

type mockEndpointInfoSource struct{}

func (m *mockEndpointInfoSource) GetID() uint64 {
	return 40
}

func (m *mockEndpointInfoSource) GetIPv4Address() string {
	return "127.0.0.1"
}

func (m *mockEndpointInfoSource) GetIPv6Address() string {
	return ""
}

func (m *mockEndpointInfoSource) GetPolicyNames() []string {
	return []string{"40"}
}

func (m *mockEndpointInfoSource) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 0
}

func testADSServer(t *testing.T) *adsServer {
	logger := hivetest.Logger(t)
	return &adsServer{
		logger:            logger,
		l7RulesTranslator: envoypolicy.NewEnvoyL7RulesTranslator(logger, nil),
	}
}
