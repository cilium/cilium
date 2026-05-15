// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/cilium/cilium/pkg/completion"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/u8proto"
)

// This test is not run in CI and is meant to be run locally when iterating on the Envoy (xDS) integration.
// It tests the basic functionality of the standalone Envoy proxy, including starting the proxy, adding and removing resources, and handling NACKs from Envoy.
// To run the standalone_envoy_test, the following have to be met:
//
// - Environment variable `CILIUM_ENABLE_ENVOY_UNIT_TEST` must be set
// - `cilium-envoy-starter` and `cilium-envoy` must exist in the PATH
//   - if these were left running from a previous test, these must be killed
//     (`pkill -9 cilium-envoy`)
//   - `cilium-envoy-starter` must have capabilities CAP_NET_ADMIN and CAP_BPF
//     (`sudo setcap 'cap_net_admin,cap_bpf+pe' `which cilium-envoy-starter` `)
//   - note that 'setcap' can fail if the binary is on a filesystem mounted from the host that
//     does not support extended attributes. If running on a VM place the binaries to the native
//     Linux filesystem rather than a mount.
//
// Run the test: 'go test -run=TestEnvoy -timeout 30s -v ./pkg/envoy/.'
type EnvoySuite struct {
	tb        testing.TB
	waitGroup *completion.WaitGroup
}

func setupEnvoySuite(tb testing.TB) *EnvoySuite {
	return &EnvoySuite{
		tb: tb,
	}
}

var ADS_RESOURCES = xds.Resources{
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
			ListenerFilters: []*envoy_config_listener.ListenerFilter{{
				Name: "cilium.bpf_metadata",
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: ToAny(&cilium.BpfMetadata{
						ProxyId:  15,
						IsL7Lb:   true,
						UseNphds: true,
						NpdsConfig: &envoy_config_core_v3.ConfigSource{
							ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
								Ads: &envoy_config_core_v3.AggregatedConfigSource{},
							},
						},
					}),
				},
			}},
			FilterChains: []*envoy_config_listener.FilterChain{
				{
					Filters: []*envoy_config_listener.Filter{{
						Name: "envoy.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
								StatPrefix: "http_proxy",
								RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
									Rds: &envoy_config_http.Rds{
										RouteConfigName: "routeConfig1",
										ConfigSource: &envoy_config_core_v3.ConfigSource{
											ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
												Ads: &envoy_config_core_v3.AggregatedConfigSource{},
											},
										},
									},
								},
							}),
						},
					}},
				},
			},
		},
	},
	Clusters: map[string]*envoy_config_cluster.Cluster{
		"cluster1": {
			Name:                 "cluster1",
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_ORIGINAL_DST},
			ConnectTimeout:       &durationpb.Duration{Seconds: 600, Nanos: 0},
			CleanupInterval:      &durationpb.Duration{Seconds: 1000, Nanos: 500000000},
			LbPolicy:             envoy_config_cluster.Cluster_CLUSTER_PROVIDED,
			TransportSocket: &envoy_config_core_v3.TransportSocket{
				Name: "cluster1.tls_wrapper",
				ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
					TypedConfig: ToAny(
						&envoy_config_tls.UpstreamTlsContext{
							CommonTlsContext: &envoy_config_tls.CommonTlsContext{
								TlsCertificateSdsSecretConfigs: []*envoy_config_tls.SdsSecretConfig{
									{
										Name: "secret1",
										SdsConfig: &envoy_config_core_v3.ConfigSource{
											ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
												Ads: &envoy_config_core_v3.AggregatedConfigSource{},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
	},
	Secrets: map[string]*envoy_config_tls.Secret{
		"secret1": {
			Name: "secret1",
			Type: &envoy_config_tls.Secret_TlsCertificate{
				TlsCertificate: &envoy_config_tls.TlsCertificate{
					CertificateChain: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							InlineBytes: []byte{1, 2, 3},
						},
					},
					PrivateKey: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
							InlineBytes: []byte{4, 5, 6},
						},
					},
				},
			},
		},
	},
	Routes: map[string]*envoy_config_route.RouteConfiguration{
		"routeConfig1": {
			Name: "routeConfig1",
		},
	},
	// Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
	// 	"endpoint1": &DEFAULT_CLA,
	// },
	NetworkPolicies: map[string]*cilium.NetworkPolicy{
		"40": {
			EndpointId:  40,
			EndpointIps: []string{"10.0.0.1"},
		},
		"30": {
			EndpointId:  30,
			EndpointIps: []string{"10.0.0.2"},
		},
	},
}

func (s *EnvoySuite) waitForProxyCompletion() error {
	start := time.Now()
	s.tb.Log("Waiting for proxy updates to complete...")
	err := s.waitGroup.Wait()
	s.tb.Log("Wait time for proxy updates: ", time.Since(start))
	return err
}

func TestEnvoyAds(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()
	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         15,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")

	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	t.Log("adding metrics listener")
	xdsServer.AddMetricsListener(ctx, 9964, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding metrics listener")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("adding listener1")
	xdsServer.AddListener(ctx, "listener1", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("adding listener2")
	xdsServer.AddListener(ctx, "listener2", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("adding listener3")
	xdsServer.AddListener(ctx, "listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("completed adding listener1, listener2, listener3")

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener3
	t.Log("removing listener 3")
	xdsServer.RemoveListener(ctx, "listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	t.Log("adding listener 3")
	xdsServer.AddListener(ctx, "listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup,
		func(err error) {
		})

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("stopping Envoy")
	stopEnvoy()

	time.Sleep(2 * time.Second) // Wait for Envoy to really terminate.

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	t.Log("removing listener 3")
	xdsServer.RemoveListener(ctx, "listener3", s.waitGroup)
	err = s.waitForProxyCompletion()
	require.Error(t, err)
	t.Logf("failed to remove listener 3: %s", err)
}

func TestEnvoyAdsResourcesHandling(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         15,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")

	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	t.Log("adding admin listener")
	xdsServer.AddAdminListener(ctx, 19001, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding metrics listener")

	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("Upserting Envoy resources")
	err = xdsServer.UpsertEnvoyResources(ctx, ADS_RESOURCES, s.waitGroup)
	require.NoError(t, err)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)

	t.Log("Updating Envoy resources")
	s.waitGroup = completion.NewWaitGroup(ctx)
	updatedResources := ADS_RESOURCES.DeepCopy()
	for k := range updatedResources.Secrets {
		delete(updatedResources.Secrets, k)
	}
	updatedResources.NetworkPolicies["40"] = &cilium.NetworkPolicy{
		EndpointId:  40,
		EndpointIps: []string{"10.0.0.9"},
	}
	err = xdsServer.UpdateEnvoyResources(ctx, ADS_RESOURCES, *updatedResources, s.waitGroup)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)

	t.Log("Deleting Envoy resources")
	s.waitGroup = completion.NewWaitGroup(ctx)
	err = xdsServer.DeleteEnvoyResources(ctx, ADS_RESOURCES, s.waitGroup)
	require.NoError(t, err)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)

	t.Log("stopping Envoy")
	stopEnvoy()
}

func TestEnvoyAdsNetworkPoliciesHandling(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         15,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")

	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	// Step 1: Upsert base resources (includes network policies for endpoints 40 and 30)
	t.Log("upserting base ADS resources with network policies")
	err = xdsServer.UpsertEnvoyResources(ctx, ADS_RESOURCES, s.waitGroup)
	require.NoError(t, err)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed upserting base resources")

	// Step 2: GetNetworkPolicies - get all (returned map is keyed by IP address)
	t.Log("getting all network policies")
	policies, err := xdsServer.GetNetworkPolicies(nil)
	require.NoError(t, err)
	require.NotNil(t, policies)
	require.Contains(t, policies, "10.0.0.1")
	require.Contains(t, policies, "10.0.0.2")
	require.Equal(t, uint64(40), policies["10.0.0.1"].EndpointId)
	require.Equal(t, uint64(30), policies["10.0.0.2"].EndpointId)

	// Step 3: GetNetworkPolicies - get specific (filter by endpoint ID, result keyed by IP)
	t.Log("getting specific network policy")
	policies, err = xdsServer.GetNetworkPolicies([]string{"40"})
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.Contains(t, policies, "10.0.0.1")

	// Step 4: GetNetworkPolicies - get nonexistent
	t.Log("getting nonexistent network policy")
	policies, err = xdsServer.GetNetworkPolicies([]string{"nonexistent"})
	require.NoError(t, err)
	require.Empty(t, policies)

	// Step 5: RemoveNetworkPolicy - remove endpoint 40's policy
	t.Log("removing network policy for endpoint 40")
	s.waitGroup = completion.NewWaitGroup(ctx)
	mockEpInfoSource := &standaloneTestEndpointInfoSource{
		id:          40,
		ipv4:        "10.0.0.1",
		policyNames: []string{"40"},
	}
	xdsServer.RemoveNetworkPolicy(ctx, mockEpInfoSource)

	// Verify removal
	policies, err = xdsServer.GetNetworkPolicies(nil)
	require.NoError(t, err)
	require.NotContains(t, policies, "10.0.0.1")
	require.Contains(t, policies, "10.0.0.2")
	t.Log("completed removing network policy for endpoint 40")

	// Step 6: RemoveAllNetworkPolicies
	t.Log("removing all network policies")
	xdsServer.RemoveAllNetworkPolicies()

	policies, err = xdsServer.GetNetworkPolicies(nil)
	require.NoError(t, err)
	require.Empty(t, policies)
	t.Log("completed removing all network policies")

	t.Log("stopping Envoy")
	stopEnvoy()
}

// standaloneTestEndpointInfoSource is a mock for endpoint.EndpointInfoSource used in standalone envoy tests.
type standaloneTestEndpointInfoSource struct {
	id          uint64
	ipv4        string
	ipv6        string
	policyNames []string
}

func (m *standaloneTestEndpointInfoSource) GetID() uint64 {
	return m.id
}

func (m *standaloneTestEndpointInfoSource) GetIPv4Address() string {
	return m.ipv4
}

func (m *standaloneTestEndpointInfoSource) GetIPv6Address() string {
	return m.ipv6
}

func (m *standaloneTestEndpointInfoSource) GetPolicyNames() []string {
	return m.policyNames
}

func (m *standaloneTestEndpointInfoSource) GetNamedPort(ingress bool, name string, proto u8proto.U8proto, idents iter.Seq[identity.NumericIdentity]) uint16 {
	return 0
}

func (m *standaloneTestEndpointInfoSource) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return 0
}

func cleanupStandaloneEnvoy(t *testing.T, envoyProxy *StandaloneEnvoy) func() {
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			require.NoError(t, envoyProxy.Stop())
		})
	}
	t.Cleanup(stop)
	return stop
}

func TestEnvoy(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newXDSServer(logger, nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.run(ctx)
		require.NoError(t, err)
	}()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.run(t.Context())
		require.NoError(t, err)
	}()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         15,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		idleTimeout:                    60,
		maxConcurrentRetries:           128,
		maxConnections:                 1024,
		maxRequests:                    1024,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")

	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	t.Log("adding metrics listener")
	xdsServer.AddMetricsListener(ctx, 9964, s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding metrics listener")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("adding listener1")
	xdsServer.AddListener(ctx, "listener1", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)

	t.Log("adding listener2")
	xdsServer.AddListener(ctx, "listener2", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup, nil)

	t.Log("adding listener3")
	xdsServer.AddListener(ctx, "listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding listener1, listener2, listener3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Remove listener3
	t.Log("removing listener 3")
	xdsServer.RemoveListener(ctx, "listener3", s.waitGroup)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed removing listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	// Add listener3 again
	t.Log("adding listener 3")
	var cbErr error
	cbCalled := false
	xdsServer.AddListener(t.Context(), "listener3", policy.ParserTypeHTTP, 8083, false, false, s.waitGroup,
		func(err error) {
			cbCalled = true
			cbErr = err
		})

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	require.True(t, cbCalled)
	require.NoError(t, cbErr)
	t.Log("completed adding listener 3")
	s.waitGroup = completion.NewWaitGroup(ctx)

	t.Log("stopping Envoy")
	stopEnvoy()

	time.Sleep(2 * time.Second) // Wait for Envoy to really terminate.

	// Remove listener3 again, and wait for timeout after stopping Envoy.
	t.Log("removing listener 3")
	xdsServer.RemoveListener(ctx, "listener3", s.waitGroup)
	err = s.waitForProxyCompletion()
	require.Error(t, err)
	t.Logf("failed to remove listener 3: %s", err)
}

func TestEnvoyNACK(t *testing.T) {
	s := setupEnvoySuite(t)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)

	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()

	logger := hivetest.Logger(t)

	xdsServer := newXDSServer(logger, nil, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		}, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.run(ctx)
		require.NoError(t, err)
	}()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.run(t.Context())
		require.NoError(t, err)
	}()

	// launch debug variant of the Envoy proxy
	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         42,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		idleTimeout:                    60,
		maxConcurrentRetries:           128,
		maxConnections:                 1024,
		maxRequests:                    1024,
		maxPendingRequests:             1024,
	})
	require.NotNil(t, envoyProxy)
	require.NoError(t, err)
	t.Log("started Envoy")

	cleanupStandaloneEnvoy(t, envoyProxy)

	rName := "listener:22"

	t.Log("adding ", rName)
	var cbErr error
	cbCalled := false
	xdsServer.AddListener(ctx, rName, policy.ParserTypeHTTP, 22, true, false, s.waitGroup,
		func(err error) {
			cbCalled = true
			cbErr = err
		})

	err = s.waitForProxyCompletion()
	require.Error(t, err)
	require.True(t, cbCalled)
	require.Equal(t, err, cbErr)
	var proxyErr *xds.ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, xds.ErrNackReceived, proxyErr.Err)
	require.Contains(t, proxyErr.Detail, "listener:22: cannot bind")

	s.waitGroup = completion.NewWaitGroup(ctx)
	// Remove listener1
	t.Log("removing ", rName)
	xdsServer.RemoveListener(ctx, rName, s.waitGroup)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)
}

func TestEnvoyAdsNACKRevert(t *testing.T) {
	s := setupEnvoySuite(t)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	s.waitGroup = completion.NewWaitGroup(ctx)

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)
	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()
	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         42,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")
	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	// Step 1: Add a valid listener so Envoy has a known-good baseline.
	t.Log("adding valid listener on port 8081")
	xdsServer.AddListener(ctx, "good-listener", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("completed adding good-listener")

	// Verify the listener exists in the snapshot.
	resources := xdsServer.cache.GetAllResources(localNodeID)
	require.Contains(t, resources.Listeners, "good-listener")

	// Step 2: Add a listener on port 22 which Envoy cannot bind (privileged port) — should NACK.
	// Wire the cb callback to verify it is invoked with the NACK error.
	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("adding listener on port 22 (expect NACK)")
	var cbErr error
	cbCalled := false
	xdsServer.AddListener(ctx, "bad-listener", policy.ParserTypeHTTP, 22, true, false, s.waitGroup,
		func(err error) {
			cbCalled = true
			cbErr = err
		})

	err = s.waitForProxyCompletion()
	require.Error(t, err)
	t.Logf("NACK received as expected: %s", err)

	// Verify the cb callback was invoked with a non-nil error.
	require.True(t, cbCalled, "cb callback should have been called on NACK")
	require.Error(t, cbErr, "cb callback should have received the NACK error")
	t.Logf("cb callback received error: %s", cbErr)

	// Step 3: Wait briefly for revert to complete (revert runs asynchronously via the callback).
	time.Sleep(3 * time.Second)

	// Step 4: Verify the bad listener was reverted out of the snapshot.
	resources = xdsServer.cache.GetAllResources(localNodeID)
	require.NotContains(t, resources.Listeners, "bad-listener",
		"bad-listener should have been reverted from the snapshot after NACK")
	// The good listener should still be present.
	require.Contains(t, resources.Listeners, "good-listener",
		"good-listener should still exist after NACK revert")
	t.Log("verified snapshot was reverted after NACK")

	// Step 5: Verify we can still add new valid listeners after the revert.
	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("adding another valid listener on port 8082 after NACK revert")
	xdsServer.AddListener(ctx, "post-revert-listener", policy.ParserTypeHTTP, 8082, true, false, s.waitGroup, nil)

	err = s.waitForProxyCompletion()
	require.NoError(t, err)

	resources = xdsServer.cache.GetAllResources(localNodeID)
	require.Contains(t, resources.Listeners, "post-revert-listener")
	require.Contains(t, resources.Listeners, "good-listener")
	t.Log("successfully added listener after NACK revert — xDS server is healthy")

	t.Log("stopping Envoy")
	stopEnvoy()
}

func TestEnvoyAdsMultipleVersionsSentBeforeAckReceived(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)
	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()
	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         15,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")
	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	// Step 1: Add a first listener so Envoy connects and we have a baseline.
	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("adding baseline listener")
	xdsServer.AddListener(ctx, "baseline", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("baseline listener added")

	// Step 2: Rapidly add multiple listeners, each producing a new snapshot version.
	// Use a single WaitGroup that collects all completions — when Envoy ACKs
	// the latest version, the orderedCompletions should complete all earlier versions too.
	s.waitGroup = completion.NewWaitGroup(ctx)
	listenerNames := []string{"rapid-1", "rapid-2", "rapid-3"}
	for i, name := range listenerNames {
		t.Logf("adding listener %s (port %d)", name, 8090+i)
		xdsServer.AddListener(ctx, name, policy.ParserTypeHTTP, uint16(8090+i), true, false, s.waitGroup, nil)
	}

	// Wait for all completions — this will only succeed if the orderedCompletions
	// correctly completes earlier versions when the latest is ACKed.
	err = s.waitForProxyCompletion()
	require.NoError(t, err, "all completions should have been resolved, none stuck")

	// Step 3: Verify no pending completions remain.
	pendingCount := xdsServer.cache.GetCompletionCallbacks().PendingCompletionCount()
	require.Equal(t, 0, pendingCount, "expected no pending completions after ACK of latest version")

	// Verify all listeners exist in the snapshot.
	resources := xdsServer.cache.GetAllResources(localNodeID)
	for _, name := range listenerNames {
		require.Contains(t, resources.Listeners, name)
	}
	t.Log("all rapid listeners present and all completions resolved")

	t.Log("stopping Envoy")
	stopEnvoy()
}

func TestEnvoyAdsMultipleVersionsSentBeforeNackReceived(t *testing.T) {
	s := setupEnvoySuite(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	if os.Getenv("CILIUM_ENABLE_ENVOY_UNIT_TEST") == "" {
		t.Skip("skipping envoy unit test; CILIUM_ENABLE_ENVOY_UNIT_TEST not set")
	}

	logging.SetLogLevel(slog.LevelDebug)
	flowdebug.Enable()

	testRunDir, err := os.MkdirTemp("", "envoy_go_test")
	require.NoError(t, err)
	t.Logf("run directory: %s", testRunDir)

	localEndpointStore := newLocalEndpointStore()
	logger := hivetest.Logger(t)

	xdsServer := newADSServer(logger, testipcache.NewMockIPCache(), localEndpointStore,
		xdsServerConfig{
			envoySocketDir:    util.GetSocketDir(testRunDir),
			proxyGID:          1337,
			httpNormalizePath: true,
			metrics:           xds.NewXDSMetric(),
		},
		nil, nil)
	require.NotNil(t, xdsServer)

	go func() {
		err = xdsServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer xdsServer.stop()

	accessLogServer := newAccessLogServer(logger, &proxyAccessLoggerMock{}, testRunDir, 1337, localEndpointStore, 4096)
	require.NotNil(t, accessLogServer)
	go func() {
		err = accessLogServer.start(t.Context())
		require.NoError(t, err)
	}()
	defer accessLogServer.stop()

	starter := &onDemandXdsStarter{logger: logger}
	envoyProxy, err := starter.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
		adsMode:                        true,
		runDir:                         testRunDir,
		logPath:                        filepath.Join(testRunDir, "cilium-envoy.log"),
		baseID:                         42,
		connectTimeout:                 1,
		maxActiveDownstreamConnections: 100,
		defaultLogLevel:                "debug",
		maxConnections:                 10,
		maxRequests:                    100,
		maxConcurrentRetries:           10,
		maxPendingRequests:             1024,
	})
	require.NoError(t, err)
	require.NotNil(t, envoyProxy)
	t.Log("started Envoy")
	stopEnvoy := cleanupStandaloneEnvoy(t, envoyProxy)

	// Step 1: Add a valid baseline listener.
	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("adding baseline listener")
	xdsServer.AddListener(ctx, "baseline", policy.ParserTypeHTTP, 8081, true, false, s.waitGroup, nil)
	err = s.waitForProxyCompletion()
	require.NoError(t, err)
	t.Log("baseline listener added")

	// Step 2: Rapidly add multiple listeners where the last one will cause a NACK.
	// Port 22 is privileged and Envoy cannot bind it, triggering a NACK.
	// All completions (including earlier valid ones) should complete with error
	// via completeUpTo, which completes the NACKed version and all earlier versions.
	s.waitGroup = completion.NewWaitGroup(ctx)
	t.Log("rapidly adding listeners: valid-1 (8090), valid-2 (8091), bad (22)")
	xdsServer.AddListener(ctx, "valid-1", policy.ParserTypeHTTP, 8090, true, false, s.waitGroup, nil)
	xdsServer.AddListener(ctx, "valid-2", policy.ParserTypeHTTP, 8091, true, false, s.waitGroup, nil)
	xdsServer.AddListener(ctx, "bad", policy.ParserTypeHTTP, 22, true, false, s.waitGroup, nil)

	// All completions should resolve (with error) — none should be stuck.
	err = s.waitForProxyCompletion()
	require.Error(t, err, "expected NACK error from Envoy")
	t.Logf("NACK received as expected: %s", err)

	// Step 3: Wait for revert to complete.
	time.Sleep(3 * time.Second)

	// Step 4: Verify no pending completions remain.
	pendingCount := xdsServer.cache.GetCompletionCallbacks().PendingCompletionCount()
	require.Equal(t, 0, pendingCount, "expected no pending completions after NACK")

	// Step 5: Verify the bad listener was reverted from the snapshot.
	resources := xdsServer.cache.GetAllResources(localNodeID)
	require.NotContains(t, resources.Listeners, "bad",
		"bad listener should have been reverted from snapshot after NACK")
	// The baseline should still be present.
	require.Contains(t, resources.Listeners, "baseline",
		"baseline listener should still exist after NACK revert")
	t.Log("verified snapshot was reverted after NACK, no completions stuck")

	t.Log("stopping Envoy")
	stopEnvoy()
}

type proxyAccessLoggerMock struct{}

func (p *proxyAccessLoggerMock) NewLogRecord(ctx context.Context, t accesslog.FlowType, ingress bool, tags ...accesslog.LogTag) (*accesslog.LogRecord, error) {
	panic("unimplemented")
}

func (p *proxyAccessLoggerMock) Log(lr *accesslog.LogRecord) {}
