// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

func GetLocalEndpointStoreForTest() *LocalEndpointStore {
	return &LocalEndpointStore{
		networkPolicyEndpoints: make(map[string]endpoint.EndpointUpdater),
	}
}

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
							TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
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

func adsTestListener(primaryPort uint32, additionalPorts ...uint32) *envoy_config_listener.Listener {
	ports := append([]uint32{primaryPort}, additionalPorts...)
	listener := testListenerWithPorts(ports...)
	listener.Name = "listener1"
	listener.EnableReusePort = wrapperspb.Bool(false)
	listener.FilterChains = []*envoy_config_listener.FilterChain{{
		Filters: []*envoy_config_listener.Filter{{
			Name: "envoy.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
					StatPrefix: "http_proxy",
					RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
						Rds: &envoy_config_http.Rds{RouteConfigName: "routeConfig1"},
					},
				}),
			},
		}},
	}}
	return listener
}

func adsTestResources(listener *envoy_config_listener.Listener) xds.Resources {
	resources := xds.NewResources()
	resources.Listeners[listener.GetName()] = listener
	resources.Routes["routeConfig1"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig1"}
	return resources
}

func ackADSResourceVersion(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL string) string {
	t.Helper()
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(typeURL)
	require.NotEmpty(t, version)

	req := &envoy_service_discovery.DiscoveryRequest{
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl: typeURL,
	}
	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     typeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(context.Background(), streamID, req, resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(streamID, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: version,
	}))
	return version
}

func nackADSResourceVersion(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL, acceptedVersion, message string) {
	t.Helper()
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	rejectedVersion := snapshot.GetVersion(typeURL)
	require.NotEmpty(t, rejectedVersion)
	require.NotEqual(t, acceptedVersion, rejectedVersion)

	req := &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: acceptedVersion,
	}
	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     typeURL,
		VersionInfo: rejectedVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(context.Background(), streamID, req, resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(streamID, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: acceptedVersion,
		ErrorDetail: &status.Status{Message: message},
	}))
}

func TestNewADSServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		metrics:              nil,
	}

	server := newADSServer(logger, nil, nil, config, nil, nil)

	require.NotNil(t, server)
	require.NotNil(t, server.logger)
	require.NotNil(t, &server.cache)
	assert.NotEmpty(t, server.socketPath)
	assert.NotEmpty(t, server.accessLogPath)
}

func TestAddListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
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

func TestAddListenerCompletesCallbackOnACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)

	var calls atomic.Int32
	callbackErr := make(chan error, 1)
	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		calls.Add(1)
		callbackErr <- err
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), calls.Load())

	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(ListenerTypeURL)
	require.NotEmpty(t, version)

	req := &envoy_service_discovery.DiscoveryRequest{
		TypeUrl: ListenerTypeURL,
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
	}
	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(ctx, 1, req, resp)
	require.Equal(t, int32(0), calls.Load())

	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
	}))
	require.NoError(t, wg.Wait())
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, <-callbackErr)
}

func TestAddListenerDuringRestoreWaitsForACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, restorerPromise)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	var calls atomic.Int32
	require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		require.NoError(t, err)
		calls.Add(1)
	}))

	require.Equal(t, int32(0), calls.Load())
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
	require.NoError(t, wg.Wait())
	require.Equal(t, int32(1), calls.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestAddListenerWithoutWaitGroupCallsCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	var calls atomic.Int32
	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil, func(err error) {
		calls.Add(1)
		require.NoError(t, err)
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestAddAdminListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
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
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
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
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {})
	require.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["test-listener"])

	revertFunc := server.RemoveListener(ctx, "test-listener", wg)
	assert.NotNil(t, revertFunc)

	resources = cache.GetAllResources(localNodeID)
	require.Empty(t, resources.Listeners)
}

// TestUpsertEnvoyResources verifies that Envoy resources can be upserted
func TestUpsertEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
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
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
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
								TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
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
								TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
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

	err := server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	assert.NoError(t, err)
	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.Listeners, 1)
	require.NotNil(t, resources.Listeners["listener1"])
	require.Len(t, resources.Clusters, 1)
	require.NotNil(t, resources.Clusters["cluster1"])
	require.Empty(t, resources.Secrets)
	require.Len(t, resources.Routes, 2)
	require.NotNil(t, resources.Routes["routeConfig1"])
	require.NotNil(t, resources.Routes["routeConfig2"])
	require.Len(t, resources.Endpoints, 1)
	require.NotNil(t, resources.Endpoints["endpoint1"])
	require.Len(t, resources.NetworkPolicies, 1)
	require.NotNil(t, resources.NetworkPolicies["40"])
}

func TestADSListenersRequiringRecreate(t *testing.T) {
	oldListener := adsTestListener(80, 8443)
	newListener := adsTestListener(80, 8444)
	require.Equal(t, []string{"listener1"}, adsListenersRequiringRecreate(
		map[string]*envoy_config_listener.Listener{"listener1": oldListener},
		map[string]*envoy_config_listener.Listener{"listener1": newListener},
	))

	oldListener.EnableReusePort = wrapperspb.Bool(true)
	newListener.EnableReusePort = wrapperspb.Bool(true)
	require.Empty(t, adsListenersRequiringRecreate(
		map[string]*envoy_config_listener.Listener{"listener1": oldListener},
		map[string]*envoy_config_listener.Listener{"listener1": newListener},
	))
}

func TestUpdateEnvoyResourcesRecreatesListenerAfterAddressChange(t *testing.T) {
	tests := []struct {
		name   string
		mode   config.XDSMode
		strict bool
	}{
		{name: "ads", mode: config.EnvoyXDSModeADS},
		{name: "strict ads", mode: config.EnvoyXDSModeStrictADS, strict: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			serverConfig := xdsServerConfig{
				envoySocketDir:       t.TempDir(),
				policyRestoreTimeout: 30 * time.Second,
				envoyXDSMode:         tt.mode,
			}
			cache := xdsnew.NewCache(logger, tt.strict)
			server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

			oldResources := adsTestResources(adsTestListener(80, 8443))
			require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))

			newResources := adsTestResources(adsTestListener(80, 8444))
			var callbackCount atomic.Uint64
			newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
				callbackCount.Add(1)
				return nil
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
			}()

			require.Eventually(t, func() bool {
				resources := cache.GetAllResources(localNodeID)
				return resources != nil && len(resources.Listeners) == 0 &&
					cache.GetCompletionCallbacks().PendingCompletionCount() == 1
			}, time.Second, 10*time.Millisecond)
			require.Equal(t, uint64(0), callbackCount.Load())
			deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

			require.Eventually(t, func() bool {
				resources := cache.GetAllResources(localNodeID)
				listener := resources.Listeners["listener1"]
				return listener != nil && listenerAddressesEqual(listener, newResources.Listeners["listener1"]) &&
					cache.GetCompletionCallbacks().PendingCompletionCount() == 1
			}, time.Second, 10*time.Millisecond)
			require.Equal(t, uint64(0), callbackCount.Load())
			replaceVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
			require.NotEqual(t, deleteVersion, replaceVersion)

			require.NoError(t, <-result)
			require.Equal(t, uint64(0), callbackCount.Load())
			require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
		})
	}
}

func TestUpdateEnvoyResourcesDuringRestoreDoesNotStageListenerDeletion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, false)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, restorerPromise)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(81, 8444))
	var callbackCount atomic.Uint64
	newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	require.NoError(t, server.UpdateEnvoyResources(t.Context(), oldResources, newResources, wg))
	resources := cache.GetAllResources(localNodeID)
	require.Same(t, newResources.Listeners["listener1"], resources.Listeners["listener1"])
	require.Equal(t, uint64(0), callbackCount.Load())
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRestoresListenerWhenDeletionTimesOut(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	resources := cache.GetAllResources(localNodeID)
	require.NotNil(t, resources)
	require.True(t, listenerAddressesEqual(resources.Listeners["listener1"], oldResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRestoresListenerWhenReplacementIsRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources != nil && len(resources.Listeners) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources.Listeners["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, deleteVersion, "rejected listener")
	require.ErrorContains(t, <-result, "rejected listener")

	resources := cache.GetAllResources(localNodeID)
	require.NotNil(t, resources)
	require.True(t, listenerAddressesEqual(resources.Listeners["listener1"], oldResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRetriesReplacementBindFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources != nil && len(resources.Listeners) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources.Listeners["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, deleteVersion, "cannot bind: Address already in use")

	// The rejected desired version is first replaced with the accepted deletion
	// version, then published again after the retry delay.
	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources != nil && len(resources.Listeners) == 0
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		resources := cache.GetAllResources(localNodeID)
		return resources.Listeners["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.NoError(t, <-result)
	resources := cache.GetAllResources(localNodeID)
	require.True(t, listenerAddressesEqual(resources.Listeners["listener1"], newResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithoutExplicitCallbackDoesNotWaitForCDSOrRDS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	oldResources := xds.NewResources()
	oldResources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), oldResources, nil))

	newResources := xds.NewResources()
	newResources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	newResources.Clusters["cluster1"] = DEFAULT_RESOURCES.Clusters["cluster1"]
	newResources.Routes["routeConfig1"] = DEFAULT_RESOURCES.Routes["routeConfig1"]

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, oldResources, newResources, wg))

	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.NoError(t, wg.Wait())
}

func TestUpdateEnvoyResourcesWaitsForListenerACKWithPortAllocationCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resources := xds.NewResources()
	resources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	var callbackCount atomic.Uint64
	resources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), resources, wg))

	require.Eventually(t, func() bool {
		return cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(0), callbackCount.Load())

	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(ListenerTypeURL)
	require.NotEmpty(t, version)

	req := &envoy_service_discovery.DiscoveryRequest{
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl: ListenerTypeURL,
	}
	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(context.Background(), 1, req, resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithPortAllocationWaitsForClusterAndListenerACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resources := DEFAULT_RESOURCES.DeepCopy()
	var callbackCount atomic.Uint64
	resources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), *resources, wg))

	require.Eventually(t, func() bool {
		return cache.GetCompletionCallbacks().PendingCompletionCount() == 2
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(0), callbackCount.Load())

	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	listenerVersion := snapshot.GetVersion(ListenerTypeURL)
	clusterVersion := snapshot.GetVersion(ClusterTypeURL)
	require.NotEmpty(t, listenerVersion)
	require.NotEmpty(t, clusterVersion)
	require.NotEmpty(t, snapshot.GetVersion(RouteTypeURL))

	clusterReq := &envoy_service_discovery.DiscoveryRequest{
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl: ClusterTypeURL,
	}
	clusterResp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ClusterTypeURL,
		VersionInfo: clusterVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(context.Background(), 1, clusterReq, clusterResp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ClusterTypeURL,
		VersionInfo: clusterVersion,
	}))
	require.Equal(t, uint64(0), callbackCount.Load())
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())

	listenerReq := &envoy_service_discovery.DiscoveryRequest{
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl: ListenerTypeURL,
	}
	listenerResp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: listenerVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(context.Background(), 1, listenerReq, listenerResp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: listenerVersion,
	}))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithConfirmedPortAllocationDoesNotWaitForChangedClusters(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	oldResources := DEFAULT_RESOURCES
	require.NoError(t, server.UpsertEnvoyResources(ctx, oldResources, nil))

	newResources := DEFAULT_RESOURCES.DeepCopy()
	newResources.Routes["routeConfig2"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig2"}
	newResources.Clusters["cluster2"] = &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
	}
	var callbackCount atomic.Uint64
	newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, oldResources, *newResources, wg))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(0), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())

	resources := cache.GetAllResources(localNodeID)
	require.Contains(t, resources.Routes, "routeConfig2")
	require.Contains(t, resources.Clusters, "cluster2")
}

func TestUpdateEnvoyResourcesRejectsInconsistentSnapshotInStrictADSMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeStrictADS,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)

	resources := xds.NewResources()
	resources.Listeners["listener1"] = proto.Clone(DEFAULT_RESOURCES.Listeners["listener1"]).(*envoy_config_listener.Listener)

	err := server.UpsertEnvoyResources(context.Background(), resources, nil)
	require.ErrorContains(t, err, "generated ADS snapshot is inconsistent")
}

func TestDeleteEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
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
	err := server.DeleteEnvoyResources(ctx, xdsResources, nil)
	assert.NoError(t, err)
	resources := cache.GetAllResources(localNodeID)
	require.Empty(t, resources.Listeners)
	require.Empty(t, resources.Clusters)
	require.Empty(t, resources.Routes)
	require.Empty(t, resources.Endpoints)
	require.Empty(t, resources.Secrets)
	require.Empty(t, resources.NetworkPolicies)

	// Add some resources and then delete them.
	err = server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
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

	err = server.DeleteEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)
	resources = cache.GetAllResources(localNodeID)
	require.Empty(t, resources.Listeners)
	require.Empty(t, resources.Clusters)
	require.Empty(t, resources.Routes)
	require.Empty(t, resources.Endpoints)
	require.Empty(t, resources.Secrets)
	require.Empty(t, resources.NetworkPolicies)
}

func TestGetNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)

	// Get all network policies — result is keyed by endpoint IP, not endpoint ID.
	policies, err := server.GetNetworkPolicies(nil)
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.NotNil(t, policies["10.0.0.1"], "policy should be keyed by endpoint IP")
	assert.Nil(t, policies["40"], "policy should not be keyed by endpoint ID")
	assert.Equal(t, uint64(40), policies["10.0.0.1"].EndpointId)

	// Filter by resource name (endpoint ID string).
	policies, err = server.GetNetworkPolicies([]string{"40"})
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.NotNil(t, policies["10.0.0.1"], "filtered policy should be keyed by endpoint IP")

	policies, err = server.GetNetworkPolicies([]string{"nonexistent"})
	assert.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Empty(t, policies)
}

func TestUpdateNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertible := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertible)
	}

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 2)
	require.NotNil(t, resources.NetworkPolicies["40"])
	assert.Equal(t, uint64(40), resources.NetworkPolicies["40"].EndpointId)
	require.NotNil(t, resources.NetworkPolicies["1"])
	assert.Equal(t, uint64(1), resources.NetworkPolicies["1"].EndpointId)
}

func TestUpdateNetworkPolicyWithoutNPDSListenersCompletesImmediately(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	require.NoError(t, server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil))
	require.True(t, server.npdsListeners.Empty())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertible := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, wg.Wait())
}

func TestUpdateNetworkPolicyDuringRestoreWaitsForSeededPolicyACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), restorerPromise)

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))
	require.False(t, server.npdsListeners.Empty())

	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	// Initial endpoint restoration seeds the policy without waiting. A later
	// regeneration of the same policy must still be able to wait for Envoy to
	// accept the already-published version.
	err, revertible := server.UpdateNetworkPolicy(t.Context(), mockEp, mockPolicy, nil)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	revertible.Finalize()
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
	seededSnapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	seededVersion := seededSnapshot.GetVersion(NetworkPolicyTypeURL)
	require.NotEmpty(t, seededVersion)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	err, revertible = server.UpdateNetworkPolicy(t.Context(), mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	currentSnapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	require.Equal(t, seededVersion, currentSnapshot.GetVersion(NetworkPolicyTypeURL))
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Equal(t, uint64(1), mockEp.proxyPolicyUpdateCount.Load())

	ackADSResourceVersion(t, cache, 1, NetworkPolicyTypeURL)
	require.NoError(t, wg.Wait())
	revertible.Finalize()
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 2
	}, time.Second, 10*time.Millisecond)
}

func TestUpdateNetworkPolicyWithNPDSListenerWaitsForACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	require.False(t, server.npdsListeners.Empty())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertible := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Equal(t, uint64(0), mockEp.proxyPolicyUpdateCount.Load())

	cache.GetCompletionCallbacks().CancelPendingCompletions(NetworkPolicyTypeURL)
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestNPDSListenerTrackingFromBulkResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	require.False(t, server.npdsListeners.Empty())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	err, _ := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())

	require.NoError(t, server.DeleteEnvoyResources(ctx, resources, nil))
	require.True(t, server.npdsListeners.Empty())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestRemoveNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, nil, nil)

	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 1)

	// Create a mock endpoint info source
	mockEp := &mockEndpointInfoSource{}

	// Should not panic
	server.RemoveNetworkPolicy(ctx, mockEp)

	resources = cache.GetAllResources(localNodeID)
	require.Empty(t, resources.NetworkPolicies)
}

// TestRemoveAllNetworkPolicies verifies that all network policies can be removed
func TestRemoveAllNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertible := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertible)
	}

	resources := cache.GetAllResources(localNodeID)
	require.Len(t, resources.NetworkPolicies, 2)
	require.NotNil(t, resources.NetworkPolicies["40"])
	require.NotNil(t, resources.NetworkPolicies["1"])

	server.RemoveAllNetworkPolicies()
	resources = cache.GetAllResources(localNodeID)
	require.Empty(t, resources.NetworkPolicies)
}

// Mock types for testing

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

func (m *mockEndpointInfoSource) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return 0
}

// testableEndpointUpdater is a configurable mock implementing endpoint.EndpointUpdater.
type testableEndpointUpdater struct {
	id                     uint64
	ipv4                   string
	ipv6                   string
	proxyPolicyRevision    atomic.Uint64
	proxyPolicyUpdateCount atomic.Uint64
}

func (m *testableEndpointUpdater) GetID() uint64          { return m.id }
func (m *testableEndpointUpdater) GetIPv4Address() string { return m.ipv4 }
func (m *testableEndpointUpdater) GetIPv6Address() string { return m.ipv6 }
func (m *testableEndpointUpdater) GetPolicyNames() []string {
	var res []string
	if m.ipv4 != "" {
		res = append(res, m.ipv4)
	}
	if m.ipv6 != "" {
		res = append(res, m.ipv6)
	}
	return res
}
func (m *testableEndpointUpdater) GetIngressNamedPort(string, u8proto.U8proto) uint16 { return 0 }
func (m *testableEndpointUpdater) OnProxyPolicyUpdate(revision uint64) {
	m.proxyPolicyRevision.Store(revision)
	m.proxyPolicyUpdateCount.Add(1)
}
func (m *testableEndpointUpdater) UpdateProxyStatistics(string, string, uint16, uint16, bool, bool, accesslog.FlowVerdict) {
}
func (m *testableEndpointUpdater) GetListenerProxyPort(string) uint16 { return 0 }

// mockRestorer implements endpointstate.Restorer for testing.
type mockRestorer struct {
	waitErr error
}

func (m *mockRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return m.waitErr
}

func (m *mockRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return m.waitErr
}

func (m *mockRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return m.waitErr
}

func TestStartAdsGRPCServerWithRestorerSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve the promise with a restorer that succeeds.
	resolver.Resolve(&mockRestorer{waitErr: nil})

	// Wait briefly for the server to start serving.
	time.Sleep(200 * time.Millisecond)

	// Server should be running; stop it and verify no error.
	require.NotNil(t, server.stopFunc, "stopFunc should be set after gRPC server is created")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerWithRestorerDeadlineExceeded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve with a restorer that returns DeadlineExceeded.
	resolver.Resolve(&mockRestorer{waitErr: context.DeadlineExceeded})

	// Server should still start serving despite the deadline exceeded.
	time.Sleep(200 * time.Millisecond)

	require.NotNil(t, server.stopFunc, "stopFunc should be set even after deadline exceeded")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerWithRestorerCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve with a restorer that returns context.Canceled.
	resolver.Resolve(&mockRestorer{waitErr: context.Canceled})

	err := <-errCh
	assert.ErrorIs(t, err, context.Canceled)
}

func TestStartAdsGRPCServerWithNilRestorerPromise(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil, nil)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// With nil restorerPromise, server should start immediately.
	time.Sleep(200 * time.Millisecond)

	require.NotNil(t, server.stopFunc, "stopFunc should be set when restorerPromise is nil")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerContextCanceledBeforeResolve(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Cancel context before resolving the promise — simulates shutdown during startup.
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-errCh
	assert.ErrorIs(t, err, context.Canceled)
}
