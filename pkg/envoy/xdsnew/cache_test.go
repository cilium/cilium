// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type mockSnapshotCache struct {
	snapshots                map[string]cache.ResourceSnapshot
	setSnapshotErr           error
	storeSnapshotBeforeError bool

	// Call tracking
	setSnapshotCalls   []context.Context
	getSnapshotCalls   []string
	clearSnapshotCalls []string
	createWatchCalls   int
}

type formattingCounter int

func (counter *formattingCounter) String() string {
	(*counter)++
	return "formatted"
}

func TestSnapshotCacheLoggerSkipsDisabledFormatting(t *testing.T) {
	var counter formattingCounter
	var infoOutput strings.Builder
	infoLogger := slog.New(slog.NewTextHandler(&infoOutput, &slog.HandlerOptions{Level: slog.LevelInfo}))
	snapshotCacheLogger(infoLogger).Debugf("value: %s", &counter)
	snapshotCacheLogger(infoLogger).Infof("value: %s", &counter)
	require.Zero(t, counter)

	var output strings.Builder
	debugLogger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	snapshotCacheLogger(debugLogger).Debugf("value: %s", &counter)
	snapshotCacheLogger(debugLogger).Infof("value: %s", &counter)
	require.Equal(t, formattingCounter(2), counter)
}

func newMockSnapshotCache() *mockSnapshotCache {
	return &mockSnapshotCache{
		snapshots: make(map[string]cache.ResourceSnapshot),
	}
}

func (m *mockSnapshotCache) SetSnapshot(ctx context.Context, node string, snapshot cache.ResourceSnapshot) error {
	m.setSnapshotCalls = append(m.setSnapshotCalls, ctx)
	if m.storeSnapshotBeforeError {
		m.snapshots[node] = snapshot
	}
	if m.setSnapshotErr != nil {
		return m.setSnapshotErr
	}
	m.snapshots[node] = snapshot
	return nil
}

func (m *mockSnapshotCache) GetSnapshot(node string) (cache.ResourceSnapshot, error) {
	m.getSnapshotCalls = append(m.getSnapshotCalls, node)
	snap, ok := m.snapshots[node]
	if !ok {
		return nil, fmt.Errorf("no snapshot found for node %s", node)
	}
	return snap, nil
}

func (m *mockSnapshotCache) ClearSnapshot(node string) {
	m.clearSnapshotCalls = append(m.clearSnapshotCalls, node)
	delete(m.snapshots, node)
}

func (m *mockSnapshotCache) GetStatusInfo(node string) cache.StatusInfo {
	return nil
}

func (m *mockSnapshotCache) GetStatusKeys() []string {
	keys := make([]string, 0, len(m.snapshots))
	for k := range m.snapshots {
		keys = append(keys, k)
	}
	return keys
}

func (m *mockSnapshotCache) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	m.createWatchCalls++
	return func() {}, nil
}

func (m *mockSnapshotCache) CreateDeltaWatch(request *cache.DeltaRequest, sub cache.Subscription, respChan chan cache.DeltaResponse) (cancel func(), err error) {
	return func() {}, nil
}

func (m *mockSnapshotCache) Fetch(ctx context.Context, request *cache.Request) (cache.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

func newInitializedTestCache(mock *mockSnapshotCache) *cacheImpl {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), false, WithNodeIDs("node1")).(*cacheImpl)
	c.SnapshotCache = mock
	return c
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	require.NoError(t, err)
	return any
}

// publishedResponseForTest obtains a real, filtered go-control-plane response
// for tests which drive stream callbacks explicitly. Freeze its cache inverse
// exactly as watch collection does, rather than pretending that a TypeURL
// version alone proves delivery of all resources.
func publishedResponseForTest(t *testing.T, c *cacheImpl, node *envoy_config_core.Node, index typeurl.Index) cache.Response {
	t.Helper()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	snapshot := mustSnapshot(t, c, node.Id)
	responder := c.SnapshotCache
	if _, mocked := responder.(*mockSnapshotCache); mocked {
		// Publication-failure tests intentionally replace the transport cache.
		responder = cache.NewSnapshotCache(false, cache.IDHash{}, nil)
		require.NoError(t, responder.SetSnapshot(t.Context(), node.Id, snapshot))
	}
	response, err := responder.Fetch(t.Context(), &cache.Request{Node: node, TypeUrl: index.URL()})
	require.NoError(t, err)
	response = callbacks.WithResponseCoverage(response, c.getNodeState(node.Id).snapshotGeneration, snapshot)
	state := c.getNodeState(node.Id)
	state.rollbacks.claimResponseLocked(c, state, index, response)
	return response
}

func ackNetworkPolicyVersion(t *testing.T, c *cacheImpl, nodeID, version string) {
	t.Helper()
	node := &envoy_config_core.Node{Id: nodeID}
	response := publishedResponseForTest(t, c, node, typeurl.NetworkPolicy)
	require.Equal(t, version, response.GetResponseVersion())
	acknowledgeResponse(t, c, 1, response, "policy-ack")
}

func acknowledgeResponse(t *testing.T, c *cacheImpl, streamID int64, response cache.Response, nonce string) {
	t.Helper()
	request := response.GetRequest()
	c.completionCbs.OnStreamResponse(response.GetContext(), streamID, request, &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     request.GetTypeUrl(),
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, &discovery.DiscoveryRequest{
		Node:          request.GetNode(),
		TypeUrl:       request.GetTypeUrl(),
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: nonce,
	}))
}

func acceptPublishedSnapshotVersions(t *testing.T, c *cacheImpl, streamID int64, node *envoy_config_core.Node, snapshot cache.ResourceSnapshot) {
	t.Helper()
	for typeURL := range typeurl.Indices() {
		// A version-only named RDS/EDS request does not prove that every
		// resource was delivered. Explicitly send and ACK this test baseline.
		response := publishedResponseForTest(t, c, node, typeURL)
		require.Equal(t, snapshot.GetVersion(typeURL.URL()), response.GetResponseVersion())
		acknowledgeResponse(t, c, streamID, response, "baseline")
	}
}

func TestGenerateSnapshotEndpointVersionChangesWhenEDSClusterReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	state.seedResource(typeurl.Cluster, "cluster2", &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotEndpointVersionChangesWhenQualifiedEDSClusterReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	state.seedResource(typeurl.Cluster, "cec-a/shared-cluster", &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	state.seedResource(typeurl.Cluster, "cec-b/shared-cluster", &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotRouteVersionChangesWhenRDSListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Route, "route1", &envoy_config_route.RouteConfiguration{Name: "route1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
						RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
							Rds: &envoy_config_http.Rds{RouteConfigName: "route1"},
						},
					}),
				},
			}},
		}},
	}
	state.seedResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
}

func TestGenerateSnapshotSecretVersionChangesWhenSDSListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			TransportSocket: &envoy_config_core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_tls.DownstreamTlsContext{
						CommonTlsContext: &envoy_config_tls.CommonTlsContext{
							TlsCertificateSdsSecretConfigs: []*envoy_config_tls.SdsSecretConfig{{
								Name: "secret1",
							}},
						},
					}),
				},
			},
		}},
	}
	state.seedResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.SecretType), after.GetVersion(envoy_resource.SecretType))
}

func TestGenerateSnapshotClusterVersionChangesWhenTCPProxyListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{Name: "cluster1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.tcp_proxy",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_extensions_filters_network_tcp_proxy.TcpProxy{
						ClusterSpecifier: &envoy_extensions_filters_network_tcp_proxy.TcpProxy_Cluster{Cluster: "cluster1"},
					}),
				},
			}},
		}},
	}
	state.seedResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.ClusterType), after.GetVersion(envoy_resource.ClusterType))
}

func TestRemoveNetworkPoliciesKeepsOtherResourceTypes(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx := t.Context()
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "missing", nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.True(t, c.HasNode("node1"))

	listener := &envoy_config_listener.Listener{Name: "listener"}
	err = c.ApplyResource(ctx, "node1", typeurl.Listener, "listener", listener, nil, nil)
	require.NoError(t, err)
	hosts := &cilium.NetworkPolicyHosts{Policy: 1}
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicyHosts, "hosts", hosts, nil, nil)
	require.NoError(t, err)
	for _, name := range []string{"first", "second"} {
		err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, name, &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
		require.NoError(t, err)
	}
	before := c.resourceGeneration
	var removalRollbacks []Rollback
	for _, name := range []string{"first", "second"} {
		rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, name, nil, nil, nil)
		require.NoError(t, err)
		removalRollbacks = append(removalRollbacks, rollback)
	}
	require.Equal(t, before+2, c.resourceGeneration)
	require.Empty(t, maps.Collect(c.NetworkPolicies("node1")))
	resource := c.GetResource("node1", typeurl.Listener, "listener")
	require.NotNil(t, resource)
	require.Same(t, listener, resource)
	resource = c.GetResource("node1", typeurl.NetworkPolicyHosts, "hosts")
	require.NotNil(t, resource)
	require.Same(t, hosts, resource)

	noRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "first", nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, noRollback)
	require.Equal(t, before+2, c.resourceGeneration)
	for i := range slices.Backward(removalRollbacks) {
		require.NoError(t, removalRollbacks[i].Revert())
	}
	require.Len(t, maps.Collect(c.NetworkPolicies("node1")), 2)
}

func TestCheckSnapshotConsistency(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	cluster := &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	}
	state.seedResource(typeurl.Cluster, "cluster1", cluster)
	state.seedResource(typeurl.Endpoint, "cluster1", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))
}

func TestCheckSnapshotConsistencyRejectsMissingEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	generatedSnapshot, ok := snap.(*ciliumSnapshot)
	require.True(t, ok)
	generatedSnapshot[typeurl.Endpoint].resources = cache.Resources{Version: "missing-endpoints"}

	require.ErrorContains(t, CheckSnapshotConsistency(snap), envoy_resource.EndpointType)
}

func TestCiliumSnapshotIndexedResourceVersionMaps(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	state.seedResource(typeurl.NetworkPolicy, "np1", policy)

	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.Equal(t, policy, snapshot.GetResources(NetworkPolicyTypeURL)["np1"])
	require.Empty(t, snapshot.GetVersion("type.googleapis.com/unknown.Resource"))
	require.Nil(t, snapshot.GetResourcesAndTTL("type.googleapis.com/unknown.Resource"))

	marshaled, err := cache.MarshalResource(policy)
	require.NoError(t, err)
	// Content versions are ready before the snapshot is published. The
	// go-control-plane hook must not marshal resources or mutate this state.
	require.Equal(t, cache.HashResource(marshaled), snapshot.GetVersionMap(NetworkPolicyTypeURL)["np1"])
	require.Nil(t, snapshot.GetVersionMap(envoy_resource.EndpointType))
	require.Nil(t, snapshot.GetVersionMap("type.googleapis.com/unknown.Resource"))
	require.NoError(t, snapshot.ConstructVersionMap())
	require.NoError(t, snapshot.ConstructVersionMap())
	require.Equal(t, cache.HashResource(marshaled), snapshot.GetVersionMap(NetworkPolicyTypeURL)["np1"])
}

func TestGenerateSnapshotContentVersionMapsMatchPublishedResources(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"})
	state.seedResource(typeurl.Route, "route", &envoy_config_route.RouteConfiguration{Name: "route"})
	state.seedResource(typeurl.Cluster, "cluster", &envoy_config_cluster.Cluster{
		Name:                 "cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})
	state.seedResource(typeurl.Secret, "secret", &envoy_config_tls.Secret{Name: "secret"})
	state.seedResource(typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1})
	state.seedResource(typeurl.NetworkPolicyHosts, "hosts", &cilium.NetworkPolicyHosts{Policy: 1})

	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	for typeURL := range typeurl.Indices() {
		published := snapshot.GetResourcesAndTTL(typeURL.URL())
		versions := snapshot.GetVersionMap(typeURL.URL())
		require.Len(t, published, 1, "resource type %s", typeURL.URL())
		require.Len(t, versions, len(published), "resource type %s", typeURL.URL())
		for name, resource := range published {
			marshaled, err := cache.MarshalResource(resource.Resource)
			require.NoError(t, err)
			require.Equal(t, cache.HashResource(marshaled), versions[name])
			require.Same(t, resource.Resource, snapshot.GetResources(typeURL.URL())[name])
			if desired := state.getResource(typeURL, name); desired != nil {
				require.Same(t, desired, resource.Resource, "snapshot generation must reuse immutable protobufs")
			}
		}
	}
	// The generated empty CLA is versioned without changing the authoritative
	// desired resource state.
	require.Contains(t, snapshot.GetVersionMap(envoy_resource.EndpointType), "cluster")
	require.Nil(t, state.getResource(typeurl.Endpoint, "cluster"))

	emptySnapshot, err := c.generateSnapshotFromState(&nodeState{})
	require.NoError(t, err)
	for typeURL := range typeurl.Indices() {
		require.Nil(t, emptySnapshot.GetResourcesAndTTL(typeURL.URL()))
		require.Nil(t, emptySnapshot.GetVersionMap(typeURL.URL()))
	}
}

func TestGenerateSnapshotRejectsInvalidResourceContent(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	// Protobuf binary encoding rejects invalid UTF-8. Report the failure during
	// snapshot construction.
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "\xff"})
	snapshot, err := c.generateSnapshotFromState(state)
	require.Error(t, err)
	require.Nil(t, snapshot)
}

func TestApplyResourcesPublicationFailureCleansUnchangedWait(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	const nodeID = "node1"
	listener := &envoy_config_listener.Listener{Name: "listener"}
	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}

	err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpoint.ClusterName: endpoint},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	var callbackErr error
	var waits TypeURLCallbacks
	waits.Set(typeurl.Listener, nil)
	waits.Set(typeurl.Endpoint, func(err error) { callbackErr = err })
	publicationErr := errors.New("snapshot publication failed")
	mock.setSnapshotErr = publicationErr
	rollback, err := c.ApplyResourcesWithRollback(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			listener.Name: {Name: listener.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND},
		},
		// The identical endpoint waits for its already published EDS version.
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpoint.ClusterName: endpoint},
	}}, wg, waits)
	require.ErrorIs(t, err, publicationErr)
	require.Nil(t, rollback)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.ErrorIs(t, wg.Wait(), publicationErr)
	require.ErrorIs(t, callbackErr, publicationErr)
	current := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.NotNil(t, current)
	require.Same(t, listener, current)
	current = c.GetResource(nodeID, typeurl.Endpoint, endpoint.ClusterName)
	require.NotNil(t, current)
	require.Same(t, endpoint, current)
}

func TestPublicationInstallationRequiresSnapshotIdentity(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed=%t", installed), func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(mock)
			const nodeID = "node1"
			assignment := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters: map[string]*envoy_config_cluster.Cluster{"cluster": {
					Name: "cluster", ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
				}},
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"cluster": assignment},
			}}, nil, TypeURLCallbacks{}))
			baseline := mustSnapshot(t, c, nodeID)
			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			mock.storeSnapshotBeforeError = installed
			// Removing an explicit empty CLA replaces it with an identical
			// synthesized CLA. Equal versions do not prove SetSnapshot installed it.
			rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Endpoint, "cluster", nil, nil, nil)
			published := mustSnapshot(t, c, nodeID)
			if installed {
				require.NoError(t, err, "an error after installation must not undo committed state")
				require.NotNil(t, rollback)
				t.Cleanup(rollback.Finalize)
				require.NotSame(t, baseline, published)
				require.NotSame(t, assignment, published.GetResources(typeurl.Endpoint.URL())["cluster"])
			} else {
				require.ErrorIs(t, err, publicationErr)
				require.Nil(t, rollback)
				require.Same(t, baseline, published)
			}
			for index := range typeurl.Indices() {
				require.Equal(t, baseline.GetVersion(index.URL()), published.GetVersion(index.URL()))
			}
			current := c.GetResource(nodeID, typeurl.Endpoint, "cluster")
			if installed {
				require.Nil(t, current, "the synthesized CLA belongs only to the snapshot")
			} else {
				require.Same(t, assignment, current, "failed installation must restore desired state")
			}
		})
	}
}

func TestResourceMutationPublicationFailureRestoresPreviousEntries(t *testing.T) {
	for _, mode := range []string{"mutation", "caller-revert", "response-revert"} {
		t.Run(mode, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(mock)
			const nodeID = "node1"
			node := &envoy_config_core.Node{Id: nodeID}
			initial := xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
				"replaced": {Name: "replaced"},
				"removed":  {Name: "removed"},
			}}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))
			baseline := mustSnapshot(t, c, nodeID)
			acceptPublishedSnapshotVersions(t, c, 1, node, baseline)
			// Keep a watch available to exercise response delivery as well as
			// desired-state recovery when publication fails.
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: node, TypeUrl: envoy_resource.RouteType, ResourceNames: []string{"replaced", "removed"},
				VersionInfo: baseline.GetVersion(envoy_resource.RouteType),
			}, stream.NewSotwSubscription([]string{"replaced", "removed"}, false), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			before := maps.Clone(c.getNodeState(nodeID).resourceEntries(typeurl.Route))
			previousGeneration := c.getNodeState(nodeID).resourceGeneration
			previousRevertGeneration := c.getNodeState(nodeID).typeStates[typeurl.Route].revertGeneration
			publicationErr := errors.New("snapshot publication failed")
			if mode == "mutation" {
				mock.setSnapshotErr = publicationErr
			}
			rollback, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{
				Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"removed": nil}},
				Upserted: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
					"replaced": {Name: "replaced", IgnorePortInHostMatching: true},
					"added":    {Name: "added"},
				}},
			}, nil, TypeURLCallbacks{})
			if mode == "mutation" {
				require.ErrorIs(t, err, publicationErr)
				require.Nil(t, rollback)
			} else {
				require.NoError(t, err)
				require.NotNil(t, rollback)
				before = maps.Clone(c.getNodeState(nodeID).resourceEntries(typeurl.Route))
				previousGeneration = c.getNodeState(nodeID).resourceGeneration
				mock.setSnapshotErr = publicationErr
				if mode == "caller-revert" {
					require.ErrorIs(t, rollback.Revert(), publicationErr)
				} else {
					t.Cleanup(rollback.Finalize)
					response := publishedResponseForTest(t, c, node, typeurl.Route)
					c.completionCbs.OnStreamResponse(response.GetContext(), 1,
						response.GetRequest(),
						&discovery.DiscoveryResponse{
							TypeUrl: envoy_resource.RouteType, VersionInfo: response.GetResponseVersion(), Nonce: "rejected-routes",
						})
					require.ErrorIs(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
						Node: node, TypeUrl: envoy_resource.RouteType,
						VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "rejected-routes",
						ErrorDetail: &status.Status{Message: "rejected routes"},
					}), publicationErr)
				}
			}
			// Failure restores complete entries, not just protobufs. This covers
			// prior absence, removal tombstones, and replacement generations even
			// when a revert has no separately constructed inverse maps.
			require.Equal(t, before, c.getNodeState(nodeID).resourceEntries(typeurl.Route))
			require.Equal(t, previousGeneration, c.getNodeState(nodeID).resourceGeneration)
			require.Equal(t, previousRevertGeneration, c.getNodeState(nodeID).typeStates[typeurl.Route].revertGeneration,
				"failed publication must not change the corrective version or ACK fence")
			require.Greater(t, c.resourceGeneration, previousGeneration, "global generations are never rewound")
			if mode == "mutation" {
				return
			}

			// A caller's revert is terminal even on failure; fixing publication
			// must not make a duplicate call mutate desired state. Response-owned
			// recovery is independent and survives the failed stream.
			mock.setSnapshotErr = nil
			if mode == "caller-revert" {
				generation := c.resourceGeneration
				require.NoError(t, rollback.Revert())
				rollback.Finalize()
				require.Equal(t, generation, c.resourceGeneration)
				require.Equal(t, before, c.getNodeState(nodeID).resourceEntries(typeurl.Route))
				// The failed caller revert must not consume the separately owned
				// response inverse. Envoy can still reject the unchanged snapshot.
				response := publishedResponseForTest(t, c, node, typeurl.Route)
				c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
					&discovery.DiscoveryResponse{
						TypeUrl: envoy_resource.RouteType, VersionInfo: response.GetResponseVersion(), Nonce: "rejected-after-caller-revert",
					})
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: envoy_resource.RouteType,
					VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "rejected-after-caller-revert",
					ErrorDetail: &status.Status{Message: "rejected routes"},
				}))
			} else {
				c.completionCbs.OnStreamClosed(1, node)
				request := &discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.RouteType}
				require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
				snapshot := mustSnapshot(t, c, nodeID)
				c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(t.Context(), c.getNodeState(nodeID).snapshotGeneration),
					2, request, &discovery.DiscoveryResponse{
						TypeUrl: envoy_resource.RouteType, VersionInfo: snapshot.GetVersion(envoy_resource.RouteType), Nonce: "retry-routes",
					})
				require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: envoy_resource.RouteType,
					VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "retry-routes",
					ErrorDetail: &status.Status{Message: "rejected routes again"},
				}))
			}
			require.Equal(t, initial.Routes, maps.Collect(c.Routes(nodeID)),
				"successful recovery must restore replaced and removed resources and delete additions")
		})
	}
}

func TestNewCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)

	assert.NotNil(t, c.SnapshotCache)
	assert.NotNil(t, c.logger)
	require.True(t, c.HasNode("node1"))
	require.False(t, c.HasNode("unknown"))
	_, err := c.GetSnapshot("node1")
	require.Error(t, err, "known-node initialization must not build snapshots")
}

func TestCacheRejectsUnknownNodes(t *testing.T) {
	for _, nodeID := range []string{"unknown", ""} {
		for _, operation := range []string{"resource", "resource-with-rollback", "resources", "resources-with-rollback", "snapshot", "watch", "empty-secret-watch", "unknown-type-watch"} {
			t.Run(fmt.Sprintf("node=%q/%s", nodeID, operation), func(t *testing.T) {
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1"))
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				callbackCalls := 0
				callback := func(error) { callbackCalls++ }
				var waits TypeURLCallbacks
				waits.Set(typeurl.Listener, callback)
				listener := &envoy_config_listener.Listener{Name: "listener"}
				mutations := ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
				}}
				var err error
				switch operation {
				case "resource":
					err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, wg, callback)
				case "resource-with-rollback":
					var rollback Rollback
					rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, wg, callback)
					require.Nil(t, rollback)
				case "resources":
					err = c.ApplyResources(t.Context(), nodeID, mutations, wg, waits)
				case "resources-with-rollback":
					var rollback Rollback
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, mutations, wg, waits)
					require.Nil(t, rollback)
				case "snapshot":
					err = c.SetSnapshot(t.Context(), nodeID, &cache.Snapshot{})
				default:
					typeURL := typeurl.Listener.URL()
					if operation == "empty-secret-watch" {
						typeURL = typeurl.Secret.URL()
					} else if operation == "unknown-type-watch" {
						typeURL = "type.googleapis.com/example.Unknown"
					}
					var cancel func()
					cancel, err = c.CreateWatch(&cache.Request{
						Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeURL,
					}, stream.NewSotwSubscription(nil, operation == "watch"), make(chan cache.Response, 1))
					require.Nil(t, cancel)
				}
				require.ErrorContains(t, err, "unknown xDS node")
				require.False(t, c.HasNode(nodeID))
				require.True(t, c.HasNode("node1"))
				require.Nil(t, c.GetResource(nodeID, typeurl.Listener, listener.Name))
				require.Nil(t, c.GetStatusInfo(nodeID), "unknown requests must not establish watches")
				_, err = c.GetSnapshot(nodeID)
				require.Error(t, err)
				require.Zero(t, c.GetCompletionCallbacks().PendingCompletionCount())
				require.Zero(t, callbackCalls)
				require.NoError(t, wg.Wait(), "rejected mutations must not register waits")
			})
		}
	}
}

func TestCreateWatchRepublishesDesiredStateAfterClear(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict-ads=%t", strictADS), func(t *testing.T) {
			c := NewCache(slog.New(slog.DiscardHandler), strictADS, WithNodeIDs("node1"))
			listener := &envoy_config_listener.Listener{Name: "listener"}
			require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, listener.Name, listener, nil, nil))
			c.ClearSnapshot("node1")
			require.True(t, c.HasNode("node1"))
			responses := make(chan cache.Response, 1)
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Listener.URL(),
			}, stream.NewSotwSubscription(nil, true), responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			select {
			case response := <-responses:
				require.Contains(t, response.GetReturnedResources(), listener.Name,
					"missing delivery state must not synthesize an empty response over desired resources")
			case <-time.After(time.Second):
				t.Fatal("expected an immediate response with the desired listener")
			}
			current := c.GetResource("node1", typeurl.Listener, listener.Name)
			require.NotNil(t, current)
			require.Same(t, listener, current)
		})
	}
}

func TestWithNodeIDsPreservesIndependentNodeState(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1", "node2"), WithNodeIDs("node1"))
	for _, nodeID := range []string{"node1", "node2"} {
		listener := &envoy_config_listener.Listener{Name: nodeID}
		require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
		current := c.GetResource(nodeID, typeurl.Listener, listener.Name)
		require.NotNil(t, current)
		require.Same(t, listener, current)
	}
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "node1", nil, nil, nil))
	c.ClearSnapshot("node1")
	require.True(t, c.HasNode("node1"), "empty desired and delivery state must not forget the consumer")
	require.True(t, c.HasNode("node2"))
	require.Nil(t, c.GetResource("node1", typeurl.Listener, "node1"))
	require.NotNil(t, c.GetResource("node2", typeurl.Listener, "node2"), "clearing one node must not affect another node's resources")
}

func TestSetSnapshot_Error(t *testing.T) {
	mock := newMockSnapshotCache()
	mock.setSnapshotErr = fmt.Errorf("set snapshot failed")
	c := newInitializedTestCache(mock)

	snap := &cache.Snapshot{}
	err := c.SetSnapshot(context.Background(), "node1", snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set snapshot failed")

	require.Len(t, mock.setSnapshotCalls, 1)
}

func TestUntrackedPublicationPreservesEarlierWait(t *testing.T) {
	for _, mode := range []string{"before-store", "after-store"} {
		t.Run(mode, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(mock)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			done := make(chan error, 1)
			first := &cilium.NetworkPolicy{EndpointId: 1}
			require.NoError(t, c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy", first, wg,
				func(err error) { done <- err }))
			previous := mustSnapshot(t, c, "node1")

			mock.storeSnapshotBeforeError = mode == "after-store"
			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			replacement := &cilium.NetworkPolicy{EndpointId: 2}
			err := c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy", replacement, nil, nil)
			current := c.GetResource("node1", typeurl.NetworkPolicy, "policy")
			require.NotNil(t, current)
			if mode == "before-store" {
				require.ErrorIs(t, err, publicationErr)
				require.Same(t, first, current)
				require.Same(t, previous, mustSnapshot(t, c, "node1"))
			} else {
				// go-control-plane can report a delivery error after installing
				// the snapshot. That update must remain committed and ACKable.
				require.NoError(t, err)
				require.Same(t, replacement, current)
				require.NotSame(t, previous, mustSnapshot(t, c, "node1"))
			}
			requireCoveragePending(t, done)
			mock.setSnapshotErr = nil
			published := mustSnapshot(t, c, "node1")
			ackNetworkPolicyVersion(t, c, "node1", published.GetVersion(NetworkPolicyTypeURL))
			require.NoError(t, wg.Wait())
			require.NoError(t, <-done)
			require.Empty(t, done)
			require.Zero(t, c.completionCbs.PendingCompletionCount())
		})
	}
}

func TestGenerateSnapshotProjectsEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name           string
		clusterType    envoy_config_cluster.Cluster_DiscoveryType
		serviceName    string
		assignment     *envoy_config_endpoint.ClusterLoadAssignment
		assignmentName string
	}{
		{name: "cluster-name", clusterType: envoy_config_cluster.Cluster_EDS, assignmentName: "cluster1"},
		{name: "service-name", clusterType: envoy_config_cluster.Cluster_EDS, serviceName: "service1", assignmentName: "service1"},
		{name: "explicit", clusterType: envoy_config_cluster.Cluster_EDS, assignmentName: "cluster1",
			assignment: &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}},
		{name: "static", clusterType: envoy_config_cluster.Cluster_STATIC},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(slog.New(slog.DiscardHandler), true, WithNodeIDs("node1"))
			upserted := xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{"cluster1": {
				Name: "cluster1", ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: tt.clusterType},
				EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: tt.serviceName},
			}}}
			if tt.assignment != nil {
				upserted.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{tt.assignmentName: tt.assignment}
			}
			require.NoError(t, c.ApplyResources(t.Context(), "node1", ResourceMutations{Upserted: upserted}, nil, TypeURLCallbacks{}))
			snapshot, err := c.GetSnapshot("node1")
			require.NoError(t, err)
			require.NoError(t, CheckSnapshotConsistency(snapshot))
			endpoints := snapshot.GetResources(typeurl.Endpoint.URL())
			if tt.assignmentName == "" {
				require.Empty(t, endpoints)
			} else {
				require.Len(t, endpoints, 1)
				assignment := endpoints[tt.assignmentName].(*envoy_config_endpoint.ClusterLoadAssignment)
				require.Equal(t, tt.assignmentName, assignment.ClusterName)
				require.Empty(t, assignment.Endpoints)
				if tt.assignment != nil {
					require.Same(t, tt.assignment, assignment)
				}
			}
			desired := c.GetResource("node1", typeurl.Endpoint, tt.assignmentName)
			if tt.assignment != nil {
				require.Same(t, tt.assignment, desired)
			} else {
				require.Nil(t, desired)
			}
		})
	}
}

func TestSnapshotContentVersions(t *testing.T) {
	for _, tt := range []struct {
		name      string
		listeners []string
		equal     bool
	}{
		{"same-contents", []string{"l1", "l2"}, true},
		{"reversed-order", []string{"l2", "l1"}, true},
		{"different-contents", []string{"l1", "l3"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
			var snapshots [2]cache.ResourceSnapshot
			for i, names := range [][]string{{"l1", "l2"}, tt.listeners} {
				state := &nodeState{}
				for _, name := range names {
					state.seedResource(typeurl.Listener, name, &envoy_config_listener.Listener{Name: name})
				}
				var err error
				snapshots[i], err = c.generateSnapshotFromState(state)
				require.NoError(t, err)
			}
			first, second := snapshots[0].GetVersion(typeurl.Listener.URL()), snapshots[1].GetVersion(typeurl.Listener.URL())
			require.NotEmpty(t, first)
			require.NotEmpty(t, second)
			if tt.equal {
				require.Equal(t, first, second)
			} else {
				require.NotEqual(t, first, second)
			}
			for index := range typeurl.Indices() {
				if index != typeurl.Listener {
					require.Equal(t, snapshots[0].GetVersion(index.URL()), snapshots[1].GetVersion(index.URL()))
				}
			}
		})
	}
}

func TestGetResourceByTypeAndName(t *testing.T) {
	c := newInitializedTestCache(newMockSnapshotCache())
	state := c.getNodeState("node1")
	resources := []struct {
		typeURL typeurl.Index
		name    string
		want    cache_types.Resource
	}{
		{typeurl.Endpoint, "endpoint", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}},
		{typeurl.Cluster, "cluster", &envoy_config_cluster.Cluster{Name: "cluster"}},
		{typeurl.Route, "route", &envoy_config_route.RouteConfiguration{Name: "route"}},
		{typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}},
		{typeurl.Secret, "secret", &envoy_config_tls.Secret{Name: "secret"}},
		{typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1}},
		{typeurl.NetworkPolicyHosts, "hosts", &cilium.NetworkPolicyHosts{}},
	}
	for _, resource := range resources {
		state.seedResource(resource.typeURL, resource.name, resource.want)
	}
	state.resources[typeurl.Listener]["removed"] = resourceEntry{revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()}

	for _, tt := range resources {
		got := c.GetResource("node1", tt.typeURL, tt.name)
		require.NotNil(t, got, "%s %s", tt.typeURL.URL(), tt.name)
		require.Same(t, tt.want, got)
	}
	for _, tt := range []struct {
		nodeID  string
		typeURL typeurl.Index
		name    string
	}{
		{"unknown", typeurl.Listener, "listener"},
		{"node1", typeurl.Listener, "missing"},
		{"node1", typeurl.Listener, "removed"},
		{"node1", typeurl.Route, "listener"},
		{"node1", typeurl.Count, "listener"},
	} {
		got := c.GetResource(tt.nodeID, tt.typeURL, tt.name)
		require.Nil(t, got)
	}
}

func TestResourceIterators(t *testing.T) {
	c := newInitializedTestCache(newMockSnapshotCache())
	state := c.getNodeState("node1")
	listener := &envoy_config_listener.Listener{Name: "listener"}
	route := &envoy_config_route.RouteConfiguration{Name: "route"}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	state.seedResource(typeurl.Listener, "listener", listener)
	state.seedResource(typeurl.Route, "route", route)
	state.seedResource(typeurl.NetworkPolicy, "policy", policy)

	for name, got := range c.Listeners("node1") {
		require.Equal(t, "listener", name)
		require.Same(t, listener, got)
		break
	}
	// Early termination must release the read lock before another update.
	c.mutex.Lock()
	c.mutex.Unlock()
	for name, got := range c.Routes("node1") {
		require.Equal(t, "route", name)
		require.Same(t, route, got)
	}
	for name, got := range c.NetworkPolicies("node1") {
		require.Equal(t, "policy", name)
		require.Same(t, policy, got)
	}
	for range c.Listeners("unknown") {
		t.Fatal("unknown node must have no resources")
	}
}
func TestClearSnapshot(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	listener := &envoy_config_listener.Listener{Name: "l1"}
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "l1", listener, nil, nil))
	c.ClearSnapshot("node1")
	require.Equal(t, []string{"node1"}, mock.clearSnapshotCalls)
	_, err := c.GetSnapshot("node1")
	require.Error(t, err)

	// Clearing delivery state must not forget desired resources or the node.
	current := c.GetResource("node1", typeurl.Listener, "l1")
	require.NotNil(t, current)
	require.Same(t, listener, current)
	require.True(t, c.HasNode("node1"))
}
func TestGenerateSnapshotProjectsSharedEDSAssignmentsWithoutChangingDesiredState(t *testing.T) {
	for _, mode := range []string{"missing", "explicit", "removed"} {
		t.Run(mode, func(t *testing.T) {
			c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1"))
			clusters := map[string]*envoy_config_cluster.Cluster{
				"static": {Name: "static"},
			}
			for _, name := range []string{"cluster1", "cluster2"} {
				clusters[name] = &envoy_config_cluster.Cluster{
					Name:                 name,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
					EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "shared"},
				}
			}
			explicit := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "shared"}
			upserted := xds.Resources{Clusters: clusters}
			if mode != "missing" {
				upserted.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{"shared": explicit}
			}
			require.NoError(t, c.ApplyResources(t.Context(), "node1", ResourceMutations{Upserted: upserted}, nil, TypeURLCallbacks{}))
			if mode == "removed" {
				require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Endpoint, "shared", nil, nil, nil))
			}
			snapshot, err := c.GetSnapshot("node1")
			require.NoError(t, err)
			require.NoError(t, CheckSnapshotConsistency(snapshot))
			endpoints := snapshot.GetResources(typeurl.Endpoint.URL())
			require.Len(t, endpoints, 1, "shared service names need just one CLA; static Clusters need none")
			require.True(t, proto.Equal(explicit, endpoints["shared"]))
			desired := c.GetResource("node1", typeurl.Endpoint, "shared")
			if mode == "explicit" {
				require.Same(t, explicit, desired)
				require.Same(t, explicit, endpoints["shared"])
			} else {
				require.Nil(t, desired, "synthesized assignments must never enter desired state")
			}
			version, err := resourceContentVersion(explicit)
			require.NoError(t, err)
			require.Equal(t, map[string]string{"shared": version}, snapshot.GetVersionMap(typeurl.Endpoint.URL()),
				"explicit and synthesized assignments retain the same content versions")
		})
	}
}

func TestGenerateSnapshot_PreservesEndpointNames(t *testing.T) {
	for _, name := range []string{"service1", "namespace/service1"} {
		t.Run(name, func(t *testing.T) {
			c := newInitializedTestCache(newMockSnapshotCache())
			state := c.getNodeState("node1")
			cla := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
			state.seedResource(typeurl.Endpoint, name, cla)

			// Orphan Endpoints remain visible to the ordinary consistency check;
			// their names must not cause snapshot generation to silently drop them.
			snap, err := c.generateSnapshotFromState(state)
			require.NoError(t, err)
			require.Contains(t, snap.GetResources(envoy_resource.EndpointType), name)
			require.Same(t, cla, snap.GetResources(envoy_resource.EndpointType)[name])
			require.ErrorContains(t, CheckSnapshotConsistency(snap), envoy_resource.EndpointType)

			// An EDS service name may differ from its Cluster's name. Preserve the
			// referenced CLA under the service name, not the Cluster's name.
			state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
				Name:                 "cluster1",
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
				EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: name},
			})
			snap, err = c.generateSnapshotFromState(state)
			require.NoError(t, err)
			require.Contains(t, snap.GetResources(envoy_resource.EndpointType), name)
			require.Same(t, cla, snap.GetResources(envoy_resource.EndpointType)[name])
			require.NoError(t, CheckSnapshotConsistency(snap))
		})
	}
}

func mustSnapshot(t *testing.T, c *cacheImpl, nodeID string) cache.ResourceSnapshot {
	t.Helper()
	snapshot, err := c.SnapshotCache.GetSnapshot(nodeID)
	require.NoError(t, err)
	return snapshot
}

type testNPDSListenerObserver struct {
	nodeID  string
	matches func(*envoy_config_listener.Listener) bool
	count   int
}

func (o *testNPDSListenerObserver) ApplyCommittedChanges(nodeID string, changes []ListenerChange) bool {
	if nodeID != o.nodeID {
		return false
	}
	before := o.count
	for _, change := range changes {
		if o.matches(change.Previous) {
			o.count--
		}
		if o.matches(change.Current) {
			o.count++
		}
	}
	return before > 0 && o.count == 0
}

func (o *testNPDSListenerObserver) HasNPDSListeners(nodeID string) bool {
	return nodeID != o.nodeID || o.count > 0
}

func TestNPDSListenerCountTracksCommittedTransitions(t *testing.T) {
	observer := &testNPDSListenerObserver{
		nodeID: "node1",
		matches: func(listener *envoy_config_listener.Listener) bool {
			return strings.HasPrefix(listener.GetName(), "npds-")
		},
	}
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false,
		WithListenerObserver(observer), WithNodeIDs("node1")).(*cacheImpl)

	listenerA := &envoy_config_listener.Listener{Name: "npds-a"}
	listenerB := &envoy_config_listener.Listener{Name: "npds-b"}
	err := c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: listenerA,
			listenerB.Name: listenerB,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 2, observer.count)

	listenerB2 := &envoy_config_listener.Listener{Name: listenerB.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND}
	rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node1", ResourceMutations{
		Removed: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: nil,
		}},
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerB2.Name: listenerB2,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)

	require.NoError(t, rollback.Revert())
	require.Equal(t, 2, observer.count)

	rollback, err = c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, listenerB.Name, proto.Clone(listenerB).(*envoy_config_listener.Listener), nil, nil)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.Equal(t, 2, observer.count)

	listenerC := &envoy_config_listener.Listener{Name: "non-npds-c"}
	err = c.ApplyResource(t.Context(), "node1", typeurl.Listener, listenerC.Name, listenerC, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, observer.count)
}

func TestNetworkPolicyWaitsCompleteWhenLastNPDSListenerIsRemoved(t *testing.T) {
	observer := &testNPDSListenerObserver{
		nodeID: "node1",
		matches: func(listener *envoy_config_listener.Listener) bool {
			return strings.HasPrefix(listener.GetName(), "npds-")
		},
	}
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false,
		WithListenerObserver(observer), WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	listener1 := &envoy_config_listener.Listener{Name: "npds-1"}
	other := &envoy_config_listener.Listener{Name: "other"}
	err := c.ApplyResources(ctx, "node1", ResourceMutations{
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listener1.Name: listener1, other.Name: other,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	firstWG := completion.NewWaitGroup(ctx)
	defer firstWG.Cancel()
	callbacks := 0
	callback := func(err error) {
		require.NoError(t, err)
		// Completion must run without the cache lock.
		c.GetResource("node1", typeurl.NetworkPolicy, "policy")
		callbacks++
	}
	policyRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, firstWG, callback)
	require.NoError(t, err)
	require.NotNil(t, policyRollback)

	noOpWG := completion.NewWaitGroup(ctx)
	defer noOpWG.Cancel()
	noOpRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, noOpWG, callback)
	require.NoError(t, err)
	require.Nil(t, noOpRollback)
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())

	// Replacing one NPDS listener with another in one transaction must not
	// release either wait, even though the old listener disappears.
	listener2 := &envoy_config_listener.Listener{Name: "npds-2"}
	err = c.ApplyResources(ctx, "node1", ResourceMutations{
		Removed:  xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener1.Name: nil}},
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener2.Name: listener2}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())

	err = c.ApplyResource(ctx, "node1", typeurl.Listener, listener2.Name, nil, nil, nil)
	require.NoError(t, err)
	require.Zero(t, observer.count)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, firstWG.Wait())
	require.NoError(t, noOpWG.Wait())
	require.Equal(t, 2, callbacks)
	require.NotNil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"), "releasing the wait must not revert the policy")

	// The caller's rollback remains usable after its ACK wait was released.
	require.NoError(t, policyRollback.Revert())
	require.Nil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"))

	noListenerWG := completion.NewWaitGroup(ctx)
	defer noListenerWG.Cancel()
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, noListenerWG, callback)
	require.NoError(t, err)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, noListenerWG.Wait())
	require.Equal(t, 3, callbacks)
}

func TestApplyResourcesAttachesNoOpDuringResponseDelivery(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, true)
	responses := make(chan cache.Response, 1)
	request := &cache.Request{Node: node, TypeUrl: envoy_resource.ListenerType}

	// Establish the LDS watch before publishing the listener so that its
	// response retains the exact generation propagated by SetSnapshot.
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	emptyResponse := <-responses
	subscription.SetReturnedResources(emptyResponse.GetReturnedResources())
	acknowledgeResponse(t, c, 1, emptyResponse, "empty-listener")
	request.VersionInfo = emptyResponse.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	listener := &envoy_config_listener.Listener{Name: "listener"}
	wg1 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg1.Cancel)
	err = c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": listener},
	}}, wg1, TypeURLCallbacks{})
	require.NoError(t, err)

	response := <-responses
	subscription.SetReturnedResources(response.GetReturnedResources())

	// Advance the node-wide generation with an unrelated NetworkPolicy response.
	// The listener itself still belongs to the generation carried by response.
	policyResponses := make(chan cache.Response, 1)
	policySubscription := stream.NewSotwSubscription(nil, true)
	currentSnapshot := mustSnapshot(t, c, node.GetId())
	listenerGeneration := c.getNodeState(node.GetId()).snapshotGeneration
	cancel, err = c.CreateWatch(&cache.Request{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: currentSnapshot.GetVersion(NetworkPolicyTypeURL),
	}, policySubscription, policyResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	err = c.ApplyResource(ctx, node.GetId(), typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	policyResponse := <-policyResponses
	policySubscription.SetReturnedResources(policyResponse.GetReturnedResources())
	require.Greater(t, c.getNodeState(node.GetId()).snapshotGeneration, listenerGeneration)

	// The response has left the cache, but deliberately delay OnStreamResponse.
	// A semantic no-op for the same listener must attach to that response while
	// it is in the handoff window, even though an unrelated resource type has
	// advanced the node-wide generation in the meantime.
	wg2 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg2.Cancel)
	err = c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener": proto.Clone(listener).(*envoy_config_listener.Listener),
		},
	}}, wg2, TypeURLCallbacks{})
	require.NoError(t, err)
	typedWG := completion.NewWaitGroup(ctx)
	t.Cleanup(typedWG.Cancel)
	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(),
		proto.Clone(listener).(*envoy_config_listener.Listener), typedWG, nil)

	require.NoError(t, err)
	request.VersionInfo = response.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case <-responses:
		t.Fatal("unexpected second response for unchanged listener contents")
	default:
	}

	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: response.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "nonce-1",
		})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: "nonce-1",
	}))
	acknowledgeResponse(t, c, 1, policyResponse, "policy")

	require.NoError(t, wg1.Wait())
	require.NoError(t, wg2.Wait())
	require.NoError(t, typedWG.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestListenerMutationReleasesUnchangedDependencies(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, true)

	listener := &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), listener, nil, nil)
	require.NoError(t, err)

	listenerResponses := make(chan cache.Response, 1)
	cancelListener, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
	}, subscription, listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancelListener)
	initialResponse := <-listenerResponses
	acknowledgeResponse(t, c, 1, initialResponse, "initial-listener")

	// Establish an accepted baseline for every type affected by initial full
	// snapshot generation. This leaves no cold-start rollback to obscure the
	// lifetime of the listener removal below.
	initialSnapshot := mustSnapshot(t, c, node.GetId())
	acceptPublishedSnapshotVersions(t, c, 1, node, initialSnapshot)
	c.getNodeState(node.GetId()).requireNoUnsentRollbacks(t)

	// This RDS watch is idle: removing a listener with no RDS reference does
	// not change the RDS version and must not consume this watch.
	routeResponses := make(chan cache.Response, 1)
	cancelRoute, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.RouteType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.RouteType),
	}, subscription, routeResponses)
	require.NoError(t, err)
	t.Cleanup(cancelRoute)
	initialGeneration := c.getNodeState(node.GetId()).snapshotGeneration

	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), nil, nil, nil)
	require.NoError(t, err)
	require.Greater(t, c.getNodeState(node.GetId()).snapshotGeneration, initialGeneration)
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly consumed the listener update")
	default:
	}

	// A listener watch now consumes the published removal. Only LDS has a changed
	// version, so its ACK must release the last response rollback and tombstone.
	listenerResponses = make(chan cache.Response, 1)
	cancelListener, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.ListenerType),
	}, subscription, listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancelListener)
	removalResponse := <-listenerResponses
	acknowledgeResponse(t, c, 1, removalResponse, "listener-removal")

	state := c.getNodeState(node.GetId())
	state.requireNoUnsentRollbacks(t)
	state.requireNoRollbackOwners(t)
	require.Empty(t, state.resources[typeurl.Listener],
		"an ACKed removal must not retain a tombstone for unchanged dependent types")
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly received the listener update")
	default:
	}
}

func TestUpsertNetworkPolicyCompletesCoalescedABAWithoutAnotherResponse(t *testing.T) {
	for _, mode := range []string{"tracked-final-update", "untracked-final-update"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			policyA := &cilium.NetworkPolicy{EndpointId: 1}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policyA, nil, nil))
			s := coverageStream{cache: c, id: 1, typeURL: NetworkPolicyTypeURL}
			responseA := s.receive(t)
			s.reply(t, responseA, "")

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wgB := completion.NewWaitGroup(ctx)
			t.Cleanup(wgB.Cancel)
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
				&cilium.NetworkPolicy{EndpointId: 2}, wgB, nil))
			var wgA *completion.WaitGroup
			if mode == "tracked-final-update" {
				wgA = completion.NewWaitGroup(ctx)
				t.Cleanup(wgA.Cancel)
			}
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy", policyA, wgA, nil))
			// Returning to accepted A resolves every intermediate wait, even
			// when the last update has no caller WaitGroup.
			require.NoError(t, wgB.Wait())
			if wgA != nil {
				require.NoError(t, wgA.Wait())
			}
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			published := mustSnapshot(t, c, "coverage-node")
			require.Equal(t, responseA.VersionInfo, published.GetVersion(NetworkPolicyTypeURL))

			responses := make(chan cache.Response, 1)
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: "coverage-node"}, TypeUrl: NetworkPolicyTypeURL, VersionInfo: responseA.VersionInfo,
			}, s.sub, responses)
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			require.Same(t, published, mustSnapshot(t, c, "coverage-node"), "CreateWatch must not publish again")
			select {
			case <-responses:
				t.Fatal("unexpected response for already accepted contents")
			default:
			}
		})
	}
}
func TestCreateWatchPublishesEmptyPolicySnapshotForKnownNode(t *testing.T) {
	nodeID := "node-without-resources"
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs(nodeID)).(*cacheImpl)
	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: nodeID},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: "stale-version",
	}
	subscription := stream.NewSotwSubscription(nil, true)
	responses := make(chan cache.Response, 1)

	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	var emptyResponse cache.Response
	select {
	case emptyResponse = <-responses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial empty snapshot")
	}
	require.Empty(t, emptyResponse.GetReturnedResources())
	require.NotEmpty(t, emptyResponse.GetResponseVersion())
	require.Empty(t, mustSnapshot(t, c, nodeID).GetResources(NetworkPolicyTypeURL))
	require.True(t, c.HasNode(nodeID))

	// Envoy's follow-up request acknowledges the empty version and establishes
	// the watch which will consume the node's first resource.
	subscription.SetReturnedResources(emptyResponse.GetReturnedResources())
	request = proto.Clone(request).(*cache.Request)
	request.VersionInfo = emptyResponse.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case <-responses:
		t.Fatal("unexpected response before the first resource update")
	default:
	}
	require.True(t, c.HasNode(nodeID))

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	err = c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	require.True(t, c.HasNode(nodeID))

	select {
	case response := <-responses:
		require.Contains(t, response.GetReturnedResources(), "policy")
		require.Same(t, policy, mustSnapshot(t, c, nodeID).GetResources(NetworkPolicyTypeURL)["policy"])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first resource update")
	}
}

func TestCreateWatchForUnknownTypeURLBypassesCiliumTracking(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: "type.googleapis.com/example.Unknown",
	}

	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), make(chan cache.Response, 1))
	require.NoError(t, err)
	require.NotNil(t, cancel)
	t.Cleanup(cancel)
	require.Equal(t, 1, mock.createWatchCalls)
	require.Empty(t, mock.setSnapshotCalls)
	require.True(t, c.HasNode("node1"))
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.Empty(t, c.watchRelays)
}

func TestRemoveNetworkPolicyFromEmptyKnownNodeIsNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	callbackCalls := 0

	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "missing-policy", nil, wg, func(err error) {
		require.NoError(t, err)
		callbackCalls++
	})

	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NoError(t, wg.Wait())
	require.Equal(t, 1, callbackCalls)
	require.True(t, c.HasNode("node1"))
}

func TestApplyResourceValidatesTypeURL(t *testing.T) {
	tests := []struct {
		name     string
		typeURL  typeurl.Index
		resource proto.Message
	}{
		{name: "mismatched type", typeURL: typeurl.NetworkPolicy, resource: &envoy_config_listener.Listener{}},
		{name: "mismatched listener", typeURL: typeurl.Listener, resource: &cilium.NetworkPolicy{}},
		{name: "unsupported protobuf", typeURL: typeurl.Listener, resource: &anypb.Any{}},
		{name: "mismatched cluster", typeURL: typeurl.Cluster, resource: &envoy_config_listener.Listener{}},
		{name: "invalid index", typeURL: typeurl.Count, resource: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
			rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.Error(t, err)
			require.Nil(t, rollback)
			require.Empty(t, c.getNodeState("node1").resources)
		})
	}
}

func TestApplyResourceSupportsAllResourceTypes(t *testing.T) {
	tests := []struct {
		typeURL  typeurl.Index
		resource proto.Message
		removed  proto.Message // typed nil exercises removal through an interface
	}{
		{typeurl.Endpoint, &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "resource"}, (*envoy_config_endpoint.ClusterLoadAssignment)(nil)},
		{typeurl.Cluster, &envoy_config_cluster.Cluster{Name: "resource"}, (*envoy_config_cluster.Cluster)(nil)},
		{typeurl.Route, &envoy_config_route.RouteConfiguration{Name: "resource"}, (*envoy_config_route.RouteConfiguration)(nil)},
		{typeurl.Listener, &envoy_config_listener.Listener{Name: "resource"}, (*envoy_config_listener.Listener)(nil)},
		{typeurl.Secret, &envoy_config_tls.Secret{Name: "resource"}, (*envoy_config_tls.Secret)(nil)},
		{typeurl.NetworkPolicy, &cilium.NetworkPolicy{EndpointId: 1}, (*cilium.NetworkPolicy)(nil)},
		{typeurl.NetworkPolicyHosts, &cilium.NetworkPolicyHosts{}, (*cilium.NetworkPolicyHosts)(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.typeURL.URL(), func(t *testing.T) {
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
			err := c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.NoError(t, err)
			actual := c.GetResource("node1", tt.typeURL, "resource")
			require.NotNil(t, actual)
			require.Same(t, tt.resource, actual)

			err = c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.removed, nil, nil)
			require.NoError(t, err)
			require.Nil(t, c.GetResource("node1", tt.typeURL, "resource"))
		})
	}
}

func TestCacheRejectsEmptyResourceNames(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*cacheImpl) (Rollback, error)
	}{
		{
			name: "listener upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, "", &envoy_config_listener.Listener{}, nil, nil)
			},
		},
		{
			name: "listener removal",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, "", nil, nil, nil)
			},
		},
		{
			name: "network policy upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicy, "", &cilium.NetworkPolicy{}, nil, nil)
			},
		},
		{
			name: "network policy hosts upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicyHosts, "", &cilium.NetworkPolicyHosts{}, nil, nil)
			},
		},
	}

	genericResources := []struct {
		name      string
		resources xds.Resources
	}{
		{name: "listener", resources: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"": {}}}},
		{name: "route", resources: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"": {}}}},
		{name: "cluster", resources: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{"": {}}}},
		{name: "endpoint", resources: xds.Resources{Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"": {}}}},
		{name: "secret", resources: xds.Resources{Secrets: map[string]*envoy_config_tls.Secret{"": {}}}},
	}
	for _, tt := range genericResources {
		tests = append(tests, struct {
			name  string
			apply func(*cacheImpl) (Rollback, error)
		}{
			name: "generic " + tt.name,
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourcesWithRollback(t.Context(), "node1", ResourceMutations{Upserted: tt.resources}, nil, TypeURLCallbacks{})
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
			rollback, err := tt.apply(c)
			require.ErrorContains(t, err, "resource name must not be empty")
			require.Nil(t, rollback)
			require.Empty(t, c.getNodeState("node1").resources)
		})
	}
}

func TestApplyResourcesRemovalsFromEmptyKnownNodeAreNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	callbackCalls := 0
	callback := func(err error) {
		require.NoError(t, err)
		callbackCalls++
	}

	var waits TypeURLCallbacks
	waits.Set(typeurl.Listener, callback)
	rollback, err := c.ApplyResourcesWithRollback(ctx, "node1", ResourceMutations{
		Removed: xds.Resources{
			Listeners: map[string]*envoy_config_listener.Listener{"listener": nil},
		},
	}, wg, waits)
	require.NoError(t, err)
	require.Nil(t, rollback)
	rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", nil, wg, callback)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NoError(t, wg.Wait())
	require.Equal(t, 2, callbackCalls)
	require.True(t, c.HasNode("node1"))
}

func TestApplyResourcesNilUpsertFromEmptyKnownNodeIsNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{
			Routes: map[string]*envoy_config_route.RouteConfiguration{"route": nil},
		},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.True(t, c.HasNode("node1"))
}

func TestCreateWatch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	respChan := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: envoy_resource.ListenerType}, nil, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)

	assert.Equal(t, 1, mock.createWatchCalls)
}

func TestCreateWatchPublishesKnownNodeState(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		for _, clientVersion := range []string{"", "stale-version"} {
			t.Run(fmt.Sprintf("strict-ads=%t/client-version=%q", strictADS, clientVersion), func(t *testing.T) {
				logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
				const nodeID = "node-without-resources"
				c := NewCache(logger, strictADS, WithNodeIDs(nodeID)).(*cacheImpl)
				node := &envoy_config_core.Node{Id: nodeID}
				subscription := stream.NewSotwSubscription(nil, true)
				responses := make(chan cache.Response, 1)

				firstRequest := &cache.Request{
					Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: clientVersion,
				}
				cancel, err := c.CreateWatch(firstRequest, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				firstResponse := <-responses
				require.Empty(t, firstResponse.GetReturnedResources())
				snapshot, err := c.GetSnapshot(nodeID)
				require.NoError(t, err)
				require.Equal(t, snapshot.GetVersion(envoy_resource.ListenerType), firstResponse.GetResponseVersion())
				require.True(t, c.HasNode(nodeID))

				subscription.SetReturnedResources(firstResponse.GetReturnedResources())
				secondRequest := &cache.Request{
					Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: firstResponse.GetResponseVersion(),
				}
				cancel, err = c.CreateWatch(secondRequest, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				require.Equal(t, 1, c.GetStatusInfo(nodeID).GetNumWatches())
				select {
				case <-responses:
					t.Fatal("current version must establish a watch, not send another response")
				default:
				}

				err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}, nil, nil)
				require.NoError(t, err)
				require.Equal(t, mustSnapshot(t, c, nodeID).GetVersion(envoy_resource.ListenerType), (<-responses).GetResponseVersion())
			})
		}
	}
}

func TestCreateWatchPreservesExistingNonemptySnapshot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	const nodeID = "node-with-listener"
	c := NewCache(logger, false, WithNodeIDs(nodeID)).(*cacheImpl)
	listener := &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil)
	require.NoError(t, err)
	snapshot := mustSnapshot(t, c, nodeID)

	responses := make(chan cache.Response, 1)
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		require.Contains(t, response.GetReturnedResources(), "listener")
		require.Equal(t, snapshot.GetVersion(envoy_resource.ListenerType), response.GetResponseVersion())
	default:
		t.Fatal("expected an immediate response containing the existing listener")
	}

	storedSnapshot, err := c.GetSnapshot(nodeID)
	require.NoError(t, err)
	require.Same(t, snapshot, storedSnapshot, "the watch must not replace the published snapshot")
	storedListener := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.NotNil(t, storedListener)
	require.Same(t, listener, storedListener, "the watch must not replace desired resources")
}

func TestCreateWatchInitialSnapshotPublicationError(t *testing.T) {
	for _, stored := range []bool{false, true} {
		t.Run(fmt.Sprintf("stored=%t", stored), func(t *testing.T) {
			mock := newMockSnapshotCache()
			mock.setSnapshotErr = errors.New("response delivery failed")
			mock.storeSnapshotBeforeError = stored
			c := newInitializedTestCache(mock)
			request := &cache.Request{
				Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: envoy_resource.ListenerType,
			}
			cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			if cancel != nil {
				t.Cleanup(cancel)
			}
			if stored {
				require.NoError(t, err, "a stored snapshot is committed despite a delivery error")
			} else {
				require.ErrorContains(t, err, "response delivery failed")
			}
			require.True(t, c.HasNode("node1"))
		})
	}
}

func TestWithNodeIDsIgnoresEmptyID(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("", "node1", "node1"))
	require.False(t, c.HasNode(""))
	require.True(t, c.HasNode("node1"))
	_, err := c.GetSnapshot("node1")
	require.Error(t, err, "registration must not generate a snapshot")
}

func TestCreateWatchRejectsNilRequest(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	cancel, err := c.CreateWatch(nil, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.ErrorContains(t, err, "nil xDS request")
	require.Nil(t, cancel)
	require.Zero(t, mock.createWatchCalls)
	require.Empty(t, mock.getSnapshotCalls)
	require.Empty(t, mock.setSnapshotCalls)
	require.True(t, c.getNodeState("node1").openWatches.Empty())
}

func TestCreateWatchEmptyNamedSubscription(t *testing.T) {
	resources := typeurl.Slots[proto.Message]{
		typeurl.Endpoint:           &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "resource"},
		typeurl.Cluster:            &envoy_config_cluster.Cluster{Name: "resource"},
		typeurl.Route:              &envoy_config_route.RouteConfiguration{Name: "resource"},
		typeurl.Listener:           &envoy_config_listener.Listener{Name: "resource"},
		typeurl.Secret:             &envoy_config_tls.Secret{Name: "resource"},
		typeurl.NetworkPolicy:      &cilium.NetworkPolicy{EndpointId: 1},
		typeurl.NetworkPolicyHosts: &cilium.NetworkPolicyHosts{Policy: 1},
	}
	for typeURL, resource := range resources {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/populated=%t", typeurl.Index(typeURL).URL(), populated), func(t *testing.T) {
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
				if populated {
					require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Index(typeURL), "resource", resource, nil, nil))
				}
				before, beforeErr := c.GetSnapshot("node1")
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Index(typeURL).URL(),
				}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
				require.NoError(t, err)
				require.NotNil(t, cancel)
				cancel()
				cancel()
				require.Empty(t, responses, "an empty subscription must not receive full state")
				require.True(t, c.getNodeState("node1").openWatches.Empty())
				require.Empty(t, c.watchRelays)
				after, err := c.GetSnapshot("node1")
				if beforeErr != nil {
					require.Error(t, err, "an empty subscription must not trigger snapshot publication")
				} else {
					require.NoError(t, err)
					require.Same(t, before, after)
				}

				// A named subscription must still be answered, even when its
				// resource does not exist yet. A following current-version watch
				// can then consume the resource's first update.
				request.ResourceNames = []string{"resource"}
				subscription := stream.NewSotwSubscription(request.ResourceNames, false)
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				response := <-responses
				require.Equal(t, populated, len(response.GetReturnedResources()) == 1)
				request.VersionInfo = response.GetResponseVersion()
				subscription.SetReturnedResources(response.GetReturnedResources())
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				require.Equal(t, 1, c.GetStatusInfo("node1").GetNumWatches())
				if !populated {
					require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Index(typeURL), "resource", resource, nil, nil))
					require.Contains(t, (<-responses).GetReturnedResources(), "resource")
				}
				cancel()

				// After an explicit subscription, empty names are an unsubscribe,
				// not a request to fall back to wildcard mode.
				subscription.SetResourceSubscription(nil)
				request.ResourceNames = nil
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				require.Empty(t, responses)
				require.True(t, c.getNodeState("node1").openWatches.Empty())
				require.Zero(t, c.GetStatusInfo("node1").GetNumWatches())
			})
		}
	}
}

func TestCreateWatchPreservesWildcardSubscriptions(t *testing.T) {
	resources := typeurl.Slots[proto.Message]{
		typeurl.Endpoint: &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "resource"},
		typeurl.Cluster: &envoy_config_cluster.Cluster{
			Name:                 "resource",
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		},
		typeurl.Route:              &envoy_config_route.RouteConfiguration{Name: "resource"},
		typeurl.Listener:           &envoy_config_listener.Listener{Name: "resource"},
		typeurl.Secret:             &envoy_config_tls.Secret{Name: "resource"},
		typeurl.NetworkPolicy:      &cilium.NetworkPolicy{EndpointId: 1},
		typeurl.NetworkPolicyHosts: &cilium.NetworkPolicyHosts{Policy: 1},
	}
	// Keep CDS/EDS and LDS/RDS references consistent so explicit wildcard
	// handling is also exercised with go-control-plane's ADS coverage check.
	resources[typeurl.Listener].(*envoy_config_listener.Listener).FilterChains = []*envoy_config_listener.FilterChain{{
		Filters: []*envoy_config_listener.Filter{{
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
				RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
					Rds: &envoy_config_http.Rds{RouteConfigName: "resource"},
				},
			})},
		}},
	}}
	mutations := ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"resource": resources[typeurl.Listener].(*envoy_config_listener.Listener)},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"resource": resources[typeurl.Route].(*envoy_config_route.RouteConfiguration)},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"resource": resources[typeurl.Cluster].(*envoy_config_cluster.Cluster)},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"resource": resources[typeurl.Endpoint].(*envoy_config_endpoint.ClusterLoadAssignment)},
		Secrets:   map[string]*envoy_config_tls.Secret{"resource": resources[typeurl.Secret].(*envoy_config_tls.Secret)},
	}}
	for typeURL, resource := range resources {
		for _, strict := range []bool{false, true} {
			for _, subscription := range []struct {
				name  string
				names []string
			}{
				{name: "implicit"},
				{name: "explicit", names: []string{"*"}},
				{name: "mixed", names: []string{"missing", "*"}},
			} {
				t.Run(fmt.Sprintf("%s/strict=%t/%s", typeurl.Index(typeURL).URL(), strict, subscription.name), func(t *testing.T) {
					logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
					c := NewCache(logger, strict, WithNodeIDs("node1"))
					require.NoError(t, c.ApplyResources(t.Context(), "node1", mutations, nil, NewTypeURLCallbacks()))
					require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Index(typeURL), "resource", resource, nil, nil))
					request := &cache.Request{
						Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Index(typeURL).URL(), ResourceNames: subscription.names,
					}
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(subscription.names, len(subscription.names) == 0), responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case response := <-responses:
						require.Contains(t, response.GetReturnedResources(), "resource")
						require.Empty(t, response.GetRequest().ResourceNames)
						if len(subscription.names) == 0 {
							require.Same(t, request, response.GetRequest(), "implicit wildcards need no copy")
						} else {
							require.NotSame(t, request, response.GetRequest())
						}
					default:
						t.Fatal("expected an immediate wildcard response")
					}
					require.Equal(t, subscription.names, request.ResourceNames, "wildcard normalization must not mutate the caller's request")
				})
			}
		}
	}
}

func TestCreateWatchWildcardNormalizationPreservesRequestFields(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1"))
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}, nil, nil))
	request := &cache.Request{
		VersionInfo:   "client-version",
		Node:          &envoy_config_core.Node{Id: "node1", Cluster: "cluster", Locality: &envoy_config_core.Locality{Zone: "zone"}},
		ResourceNames: []string{"*"},
		ResourceLocators: []*discovery.ResourceLocator{{
			Name: "locator", DynamicParameters: map[string]string{"key": "value"},
		}},
		TypeUrl:       envoy_resource.ListenerType,
		ResponseNonce: "nonce",
		ErrorDetail:   &status.Status{Code: 3, Message: "diagnostic"},
	}
	original := proto.Clone(request).(*cache.Request)
	expected := proto.Clone(request).(*cache.Request)
	expected.ResourceNames = nil
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.ResourceNames, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		normalized := response.GetRequest()
		require.True(t, proto.Equal(expected, normalized), "only resource names may change")
		require.True(t, proto.Equal(original, request), "the caller's protobuf must remain unchanged")
		require.Same(t, request.Node, normalized.Node)
		require.Same(t, request.ErrorDetail, normalized.ErrorDetail)
		require.Same(t, request.ResourceLocators[0], normalized.ResourceLocators[0])
	default:
		t.Fatal("expected an immediate wildcard response")
	}
}

func TestSetAndGetSnapshotRoundTrip(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state.seedResource(typeurl.Cluster, "c1", &envoy_config_cluster.Cluster{Name: "c1"})
	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, c.SetSnapshot(t.Context(), "node1", snapshot))
	retrieved, err := c.GetSnapshot("node1")
	require.NoError(t, err)
	require.Same(t, snapshot, retrieved)
}
