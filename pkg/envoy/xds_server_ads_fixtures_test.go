// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"testing"

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
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
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
	xds_cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_stream "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func newTestADSServer(t testing.TB, logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	t.Helper()
	server, err := newADSServer(logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
	require.NoError(t, err)
	return server
}

func newTestADSServerWithCache(t testing.TB, cache xdsnew.Cache, logger *slog.Logger, ipCache IPCacheEventSource, localEndpointStore *LocalEndpointStore, config xdsServerConfig, secretManager certificatemanager.SecretManager, restorerPromise promise.Promise[endpointstate.Restorer]) *adsServer {
	t.Helper()
	server, err := newADSServerWithCache(cache, logger, ipCache, localEndpointStore, config, secretManager, restorerPromise)
	require.NoError(t, err)
	return server
}

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

func ackADSResourceVersionFrom(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL, acceptedVersion string) string {
	t.Helper()
	response := createADSWatchResponse(t, cache, typeURL, acceptedVersion)
	delivered := deliverADSResponse(t, cache, streamID, response)
	replyADSResponse(t, cache, streamID, response, delivered, "")
	return delivered.GetVersionInfo()
}

func nackADSResourceVersion(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL, acceptedVersion, message string) {
	t.Helper()
	response := createADSWatchResponse(t, cache, typeURL, acceptedVersion)
	delivered := deliverADSResponse(t, cache, streamID, response)
	require.NotEqual(t, acceptedVersion, delivered.GetVersionInfo())
	replyADSResponse(t, cache, streamID, response, delivered, message)
}

func createADSWatchResponse(t *testing.T, cache xdsnew.Cache, typeURL, version string) xds_cache.Response {
	t.Helper()
	request := &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: version,
	}
	responses := make(chan xds_cache.Response, 1)
	cancel, err := cache.GetSnapshotCache().CreateWatch(request, envoy_stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ADS watch response")
		return nil
	}
}

// testableEndpointUpdater is a configurable mock implementing endpoint.EndpointUpdater.
type testableEndpointUpdater struct {
	id   uint64
	ipv4 string
	ipv6 string
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

// Fresh maps and protobufs keep mutations local to each test case.
func adsDefaultResources() xds.Resources {
	cla := envoy_config_endpoint.ClusterLoadAssignment{
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
	return xds.Resources{
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
				LoadAssignment: &cla,
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
			"cluster1": &cla,
		},
	}
}

func newADSServerFixture(t *testing.T, restorers ...promise.Promise[endpointstate.Restorer]) (*adsServer, xdsnew.Cache) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	var restorer promise.Promise[endpointstate.Restorer]
	if len(restorers) != 0 {
		restorer = restorers[0]
	}
	server := newTestADSServer(t, logger, nil, newLocalEndpointStore(), xdsServerConfig{
		envoySocketDir: t.TempDir(), policyRestoreTimeout: 30 * time.Second, envoyXDSMode: config.EnvoyXDSModeADS,
	}, certificatemanager.NewMockSecretManagerInline(), restorer)
	t.Cleanup(func() {
		server.cache.GetCompletionCallbacks().OnStreamClosed(1, nil)
		server.cache.GetCompletionCallbacks().OnStreamClosed(2, nil)
	})
	return server, server.cache
}

// Seed through restoration so resources remain unacknowledged until the test
// drives their responses. Subsequent updates use the normal server-owned waits.
func newSeededADSServerFixture(t *testing.T, resources xds.Resources) (*adsServer, xdsnew.Cache) {
	t.Helper()
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources))
	server.markRestoreCompleted()
	return server, cache
}

func waitForADSCompletion(t *testing.T, wg *completion.WaitGroup) <-chan error {
	t.Helper()
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	go func() { done <- wg.Wait() }()
	return done
}

func startADSResourceUpdate(server *adsServer, ctx context.Context, old, next xds.Resources) <-chan error {
	result := make(chan error, 1)
	go func() { result <- server.UpdateEnvoyResources(ctx, old, next) }()
	return result
}

func requireADSCompletionPending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("update completed before its ACK/NACK: %v", err)
	default:
	}
}

var adsResponseNonce atomic.Uint64

func deliverADSResponse(t *testing.T, cache xdsnew.Cache, streamID int64, response xds_cache.Response) *envoy_service_discovery.DiscoveryResponse {
	t.Helper()
	delivered, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	delivered.Nonce = strconv.FormatUint(adsResponseNonce.Add(1), 10)
	cache.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), streamID, response.GetRequest(), delivered)
	return delivered
}

func replyADSResponse(t *testing.T, cache xdsnew.Cache, streamID int64, response xds_cache.Response, delivered *envoy_service_discovery.DiscoveryResponse, rejection string) {
	t.Helper()
	request := proto.Clone(response.GetRequest()).(*envoy_service_discovery.DiscoveryRequest)
	if rejection == "" {
		request.VersionInfo = delivered.GetVersionInfo()
	} else {
		request.ErrorDetail = &status.Status{Message: rejection}
	}
	request.ResponseNonce = delivered.GetNonce()
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(streamID, request))
}

func adsTestEndpoints() []*testableEndpointUpdater {
	return []*testableEndpointUpdater{{id: 40, ipv4: "10.0.0.1"}, {id: 30, ipv4: "10.0.0.2"}}
}

func seedADSNetworkPolicy(t *testing.T, server *adsServer, ep *testableEndpointUpdater) *cilium.NetworkPolicy {
	t.Helper()
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), nil)
	require.NoError(t, err)
	rollback.Finalize()
	return cachedNetworkPolicy(t, server.cache, localNodeID, strconv.FormatUint(ep.id, 10))
}

func newUnixADSClient(t *testing.T, socketPath string) envoy_service_discovery.AggregatedDiscoveryServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return envoy_service_discovery.NewAggregatedDiscoveryServiceClient(conn)
}

// blockingNetworkPolicyADSCache pauses one production call to reproduce the
// listener-NACK/NPDS-registration race. It forwards the update unchanged.
type blockingNetworkPolicyADSCache struct {
	xdsnew.Cache
	upsertStarted  chan struct{}
	continueUpsert chan struct{}
}

func (c *blockingNetworkPolicyADSCache) ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) (xdsnew.Rollback, error) {
	if typeURL == typeurl.NetworkPolicy && resource != nil {
		close(c.upsertStarted)
		select {
		case <-c.continueUpsert:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.Cache.ApplyResourceWithRollback(ctx, nodeID, typeURL, name, resource, wg)
}
