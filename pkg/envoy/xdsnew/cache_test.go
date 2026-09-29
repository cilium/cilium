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
	"strconv"
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
	"github.com/cilium/cilium/pkg/lock"
)

// seedResource sets up desired state for snapshot-generation tests without
// staging a mutation or marking a resource name as changed.
func (state *nodeState) seedResource(typeURL typeurl.Index, name string, resource cache_types.Resource) {
	resources := &state.resources[typeURL]
	if resources.entries == nil {
		resources.entries = make(map[string]resourceEntry)
	}
	resources.entries[name] = resourceEntry{resource: resource}
}

type mockSnapshotCache struct {
	snapshots                map[string]cache.ResourceSnapshot
	setSnapshotErr           error
	storeSnapshotBeforeError bool
	clearCalled              map[string]bool

	// Call tracking
	setSnapshotCalls   []setSnapshotCall
	getSnapshotCalls   []string
	clearSnapshotCalls []string
	getStatusInfoCalls []string
	getStatusKeysCalls int
	createWatchCalls   int
	createDeltaCalls   int
	fetchCalls         int
}

type setSnapshotCall struct {
	ctx      context.Context
	nodeID   string
	snapshot cache.ResourceSnapshot
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
		snapshots:   make(map[string]cache.ResourceSnapshot),
		clearCalled: make(map[string]bool),
	}
}

func (m *mockSnapshotCache) SetSnapshot(ctx context.Context, node string, snapshot cache.ResourceSnapshot) error {
	m.setSnapshotCalls = append(m.setSnapshotCalls, setSnapshotCall{ctx: ctx, nodeID: node, snapshot: snapshot})
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
	m.clearCalled[node] = true
	delete(m.snapshots, node)
}

func (m *mockSnapshotCache) GetStatusInfo(node string) cache.StatusInfo {
	m.getStatusInfoCalls = append(m.getStatusInfoCalls, node)
	return nil
}

func (m *mockSnapshotCache) GetStatusKeys() []string {
	m.getStatusKeysCalls++
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
	m.createDeltaCalls++
	return func() {}, nil
}

func (m *mockSnapshotCache) Fetch(ctx context.Context, request *cache.Request) (cache.Response, error) {
	m.fetchCalls++
	return nil, fmt.Errorf("not implemented")
}

// helper to build a Cache with a mocked snapshotCache
func newTestCache(mockedCache *mockSnapshotCache) cacheImpl {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return cacheImpl{
		SnapshotCache: mockedCache,
		mutex:         &lock.RWMutex{},
		nodeStates:    make(map[string]*nodeState),
		openWatches:   make(map[string]*nodeWatchState),
		watchRelays:   make(map[chan cache.Response]*watchRelay),
		logger:        logger,
		completionCbs: callbacks.NewCompletionCallbacks(logger),
	}
}

func newInitializedTestCache(mock *mockSnapshotCache) *cacheImpl {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), false).(*cacheImpl)
	c.SnapshotCache = mock
	c.nodeStates = make(map[string]*nodeState)
	return c
}

func indexedTypeURLCallbacks(callbacks map[string]func(error)) TypeURLCallbacks {
	var result TypeURLCallbacks
	for typeURLString, callback := range callbacks {
		if typeURL, ok := typeurl.FromURL(typeURLString); ok {
			result.Set(typeURL, callback)
		}
	}
	return result
}

func (c *cacheImpl) awaitCurrentVersion(nodeID string, wg *completion.WaitGroup, callbacks map[string]func(error)) error {
	tx := c.beginResourceTransaction(context.Background(), nodeID)
	var waits typeURLWaits
	for typeURL, callback := range indexedTypeURLCallbacks(callbacks).All() {
		waits.Set(typeURL, generationWait{
			callback:   callback,
			generation: tx.state.generationForType(typeURL),
		})
	}
	var err error
	if wg != nil && !waits.Empty() {
		err = tx.awaitCurrentVersionLocked(wg, waits)
	}
	tx.complete()
	return err
}

// changesToSnapshot constructs test mutations for the supplied snapshot. The
// completion callback tests can then exercise production snapshot generation
// and publication without a replaceable generator in the cache.
func (state *nodeState) changesToSnapshot(snapshot cache.ResourceSnapshot, generation uint64) resourceChanges {
	var changes resourceChanges
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		desired := snapshot.GetResources(typeURL.URL())
		for name, previous := range current {
			if previous.resource == nil {
				continue
			}
			if _, exists := desired[name]; !exists {
				changes.add(typeURL, name, previous, resourceEntry{generation: generation})
			}
		}
		for name, resource := range desired {
			previous := current[name]
			if previous.resource == nil || !xds.ResourceEqual(previous.resource, resource) {
				changes.add(typeURL, name, previous, resourceEntry{resource: resource, generation: generation})
			}
		}
	}
	return changes
}

// UpdateSnapshot preserves the eager publication shape used by the completion
// callback tests below. It seeds desired state from the requested snapshot but
// uses the same snapshot construction and publication path as production updates.
func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, generation uint64, snapshot cache.ResourceSnapshot, wg *completion.WaitGroup, typeURLs map[string]func(error)) error {
	var changedTypeURLs typeurl.Set
	if typeURLs != nil {
		changedTypeURLs = typeurl.NewSet()
	}
	var waits typeURLWaits
	for typeURLString, callback := range typeURLs {
		if typeURL, ok := typeurl.FromURL(typeURLString); ok {
			changedTypeURLs.Insert(typeURL)
			waits.Set(typeURL, generationWait{callback: callback, generation: generation})
		}
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	changes := tx.state.changesToSnapshot(snapshot, generation)
	tx.generation = generation
	err := tx.updateResourceChangesLocked(changes, inverseResources{}, snapshotTypesChangedBy(changedTypeURLs), changes.typeURLs(),
		wg, waits, noRollbackTracking)
	tx.complete()
	return err
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	require.NoError(t, err)
	return any
}

func networkPolicySnapshot(t *testing.T, c *cacheImpl, endpointID uint64) cache.ResourceSnapshot {
	t.Helper()
	state := &nodeState{}
	state.seedResource(typeurl.NetworkPolicy, "np1", &cilium.NetworkPolicy{EndpointId: endpointID})
	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	return snap
}

func listenerSnapshot(t *testing.T, c *cacheImpl, name string) cache.ResourceSnapshot {
	t.Helper()
	state := &nodeState{}
	state.seedResource(typeurl.Listener, name, &envoy_config_listener.Listener{Name: name})
	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	return snap
}

func ackNetworkPolicyVersion(t *testing.T, c *cacheImpl, nodeID, version string) {
	t.Helper()

	node := &envoy_config_core.Node{Id: nodeID}
	c.mutex.RLock()
	generation := c.nodeStates[nodeID].snapshotGeneration
	c.mutex.RUnlock()
	c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(context.Background(), generation), 1,
		&discovery.DiscoveryRequest{
			Node:    node,
			TypeUrl: NetworkPolicyTypeURL,
		},
		&discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     NetworkPolicyTypeURL,
		})
	err := c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: version,
	})
	require.NoError(t, err)
}

func ackListenerVersion(t *testing.T, c *cacheImpl, nodeID, version string) {
	t.Helper()

	node := &envoy_config_core.Node{Id: nodeID}
	c.mutex.RLock()
	generation := c.nodeStates[nodeID].snapshotGeneration
	c.mutex.RUnlock()
	c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(context.Background(), generation), 1,
		&discovery.DiscoveryRequest{
			Node:    node,
			TypeUrl: envoy_resource.ListenerType,
		},
		&discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     envoy_resource.ListenerType,
		})
	err := c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     envoy_resource.ListenerType,
		VersionInfo: version,
	})
	require.NoError(t, err)
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
		require.NoError(t, c.completionCbs.OnStreamRequest(streamID, &discovery.DiscoveryRequest{
			Node:        node,
			TypeUrl:     typeURL.URL(),
			VersionInfo: snapshot.GetVersion(typeURL.URL()),
		}))
	}
}

func TestGenerateSnapshotEndpointVersionChangesWhenEDSClusterReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(logger, false).(*cacheImpl)
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

func TestNodeStateUsesSemanticEqualityAndTracksChangedNames(t *testing.T) {
	current := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": {Name: "listener"}},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"route": {Name: "route"}},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster": {Name: "cluster"}},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"endpoint": {ClusterName: "endpoint"}},
		Secrets:   map[string]*envoy_config_tls.Secret{"secret": {Name: "secret"}},
	}

	equal := xds.Resources{
		Listeners: make(map[string]*envoy_config_listener.Listener),
		Routes:    make(map[string]*envoy_config_route.RouteConfiguration),
		Clusters:  make(map[string]*envoy_config_cluster.Cluster),
		Endpoints: make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:   make(map[string]*envoy_config_tls.Secret),
	}
	equal.Listeners["listener"] = proto.Clone(current.Listeners["listener"]).(*envoy_config_listener.Listener)
	equal.Routes["route"] = proto.Clone(current.Routes["route"]).(*envoy_config_route.RouteConfiguration)
	equal.Clusters["cluster"] = proto.Clone(current.Clusters["cluster"]).(*envoy_config_cluster.Cluster)
	equal.Endpoints["endpoint"] = proto.Clone(current.Endpoints["endpoint"]).(*envoy_config_endpoint.ClusterLoadAssignment)
	equal.Secrets["secret"] = proto.Clone(current.Secrets["secret"]).(*envoy_config_tls.Secret)

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", current.Listeners["listener"])
	state.seedResource(typeurl.Route, "route", current.Routes["route"])
	state.seedResource(typeurl.Cluster, "cluster", current.Clusters["cluster"])
	state.seedResource(typeurl.Endpoint, "endpoint", current.Endpoints["endpoint"])
	state.seedResource(typeurl.Secret, "secret", current.Secrets["secret"])
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(ResourceMutations{Upserted: equal}, 1)
	require.True(t, changedTypeURLs.Empty())
	require.True(t, inverse.empty())
	require.True(t, changes.empty())
	for _, resource := range []struct {
		typeURL typeurl.Index
		value   cache_types.Resource
		name    string
	}{
		{typeurl.Listener, current.Listeners["listener"], "listener"},
		{typeurl.Route, current.Routes["route"], "route"},
		{typeurl.Cluster, current.Clusters["cluster"], "cluster"},
		{typeurl.Endpoint, current.Endpoints["endpoint"], "endpoint"},
		{typeurl.Secret, current.Secrets["secret"], "secret"},
	} {
		actual, found := state.getResource(resource.typeURL, resource.name)
		require.True(t, found)
		require.Same(t, resource.value, actual)
	}

	removed := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": current.Listeners["listener"]},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster": current.Clusters["cluster"]},
	}
	upserted := xds.Resources{Secrets: map[string]*envoy_config_tls.Secret{
		"new-secret": {Name: "new-secret"},
	}}

	changes, changedTypeURLs, inverse = state.prepareResourceMutation(ResourceMutations{Removed: removed, Upserted: upserted}, 1)
	require.Len(t, changes.more, 2, "three changed resources should share one overflow slice")
	state.commitResourceMutation(changes)
	require.Equal(t, typeurl.NewSet(
		typeurl.Listener,
		typeurl.Cluster,
		typeurl.Secret,
	), changedTypeURLs)
	inverseListener, _ := inverse.get(typeurl.Listener, "listener")
	inverseCluster, _ := inverse.get(typeurl.Cluster, "cluster")
	inverseSecret, _ := inverse.get(typeurl.Secret, "new-secret")
	require.Equal(t, current.Listeners["listener"], inverseListener.resource)
	require.Equal(t, current.Clusters["cluster"], inverseCluster.resource)
	require.Nil(t, inverseSecret.resource)
	_, found := state.getResource(typeurl.Listener, "listener")
	require.False(t, found)
	_, found = state.getResource(typeurl.Cluster, "cluster")
	require.False(t, found)
	_, found = state.getResource(typeurl.Secret, "secret")
	require.True(t, found)
	_, found = state.getResource(typeurl.Secret, "new-secret")
	require.True(t, found)

	// The previously published generation remains immutable.
	require.Contains(t, current.Listeners, "listener")
	require.Contains(t, current.Clusters, "cluster")
	require.NotContains(t, current.Secrets, "new-secret")
}

func TestPreparedResourceChangesKeepSinglePolicyInline(t *testing.T) {
	state := &nodeState{}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	var changes resourceChanges
	changes.add(typeurl.NetworkPolicy, "policy", resourceEntry{}, resourceEntry{resource: policy, generation: 1})
	types, inverse := changes.typeURLs(), changes.inverse()
	require.Equal(t, typeurl.NewSet(typeurl.NetworkPolicy), types)
	require.Equal(t, "policy", changes.first.name)
	require.Equal(t, typeurl.NetworkPolicy, changes.first.typeURL)
	require.Same(t, policy, changes.first.next.resource)
	require.Equal(t, uint64(1), changes.first.next.generation)
	require.Nil(t, changes.first.previous.resource)
	require.Empty(t, changes.more)
	require.True(t, inverse.hasSingleton())

	state.commitResourceMutation(changes)
	changes = resourceChanges{}
	changes.add(typeurl.NetworkPolicy, "policy", state.resourceEntries(typeurl.NetworkPolicy)["policy"], resourceEntry{generation: 2})
	types, inverse = changes.typeURLs(), changes.inverse()
	require.Equal(t, typeurl.NewSet(typeurl.NetworkPolicy), types)
	require.Equal(t, "policy", changes.first.name)
	require.Nil(t, changes.first.next.resource)
	require.Equal(t, uint64(2), changes.first.next.generation)
	require.Same(t, policy, changes.first.previous.resource)
	require.Empty(t, changes.more)
	require.True(t, inverse.hasSingleton())
	require.Equal(t, uint64(1), changes.first.previous.generation)
}

func TestPreparedResourceRevertsCarryTargetEntries(t *testing.T) {
	for _, mode := range []string{"caller", "response"} {
		t.Run(mode, func(t *testing.T) {
			targets := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 1}, generation: 3},
				"removed":    {resource: &cilium.NetworkPolicy{EndpointId: 2}, generation: 5},
				"added":      {},
				"tombstone":  {generation: 2},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 3}, generation: 4},
			}
			current := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 10}, generation: 10},
				"removed":    {generation: 10},
				"added":      {resource: &cilium.NetworkPolicy{EndpointId: 11}, generation: 10},
				"tombstone":  {resource: &cilium.NetworkPolicy{EndpointId: 12}, generation: 10},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 13}, generation: 11},
			}
			state := &nodeState{}
			state.resources[typeurl.NetworkPolicy].entries = maps.Clone(current)
			var changes resourceChanges
			if mode == "caller" {
				var inverse inverseResources
				inverse.entries[typeurl.NetworkPolicy] = targets
				changes = state.resourceRevertInverse(10, inverse)
			} else {
				var rollback rollbackResources
				rollback[typeurl.NetworkPolicy] = make(map[string]rollbackEntry)
				for name, entry := range targets {
					rollback[typeurl.NetworkPolicy][name] = rollbackEntry{previous: entry, expectedGeneration: 10}
				}
				changes = state.resourceRevert(rollback)
			}
			require.Len(t, changes.more, 3)
			require.Equal(t, current, state.resourceEntries(typeurl.NetworkPolicy), "preparation must not mutate entries")
			state.commitResourceMutation(changes)
			entries := state.resourceEntries(typeurl.NetworkPolicy)
			for name, target := range targets {
				if name == "superseded" {
					require.Equal(t, current[name], entries[name], "a newer generation must not be reverted")
				} else {
					require.Equal(t, target, entries[name], "restore the complete original entry for %s", name)
				}
			}
			require.NotContains(t, entries, "added", "generation zero must restore absence, not create a tombstone")
			require.Contains(t, entries, "tombstone", "a nonzero removal generation must survive restoration")
		})
	}
}

func TestRemoveNetworkPoliciesKeepsOtherResourceTypes(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx := t.Context()
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "missing", nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NotContains(t, c.nodeStates, "node1")

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
	resource, exists := c.GetResource("node1", typeurl.Listener, "listener")
	require.True(t, exists)
	require.Same(t, listener, resource)
	resource, exists = c.GetResource("node1", typeurl.NetworkPolicyHosts, "hosts")
	require.True(t, exists)
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
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(logger, false).(*cacheImpl)
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
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
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
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"})
	state.seedResource(typeurl.Route, "route", &envoy_config_route.RouteConfiguration{Name: "route"})
	state.seedResource(typeurl.Cluster, "cluster", &envoy_config_cluster.Cluster{
		Name:                 "cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})
	state.seedResource(typeurl.Endpoint, "orphan:*", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan:*"})
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
		}
	}
	// The generated empty CLA is versioned, but neither it nor the filtered
	// wildcard endpoint changes the authoritative desired resource state.
	require.Contains(t, snapshot.GetVersionMap(envoy_resource.EndpointType), "cluster")
	require.NotContains(t, snapshot.GetVersionMap(envoy_resource.EndpointType), "orphan:*")
	_, exists := state.getResource(typeurl.Endpoint, "cluster")
	require.False(t, exists)
	_, exists = state.getResource(typeurl.Endpoint, "orphan:*")
	require.True(t, exists)

	emptySnapshot, err := c.generateSnapshotFromState(&nodeState{})
	require.NoError(t, err)
	for typeURL := range typeurl.Indices() {
		require.Nil(t, emptySnapshot.GetResourcesAndTTL(typeURL.URL()))
		require.Nil(t, emptySnapshot.GetVersionMap(typeURL.URL()))
	}
}

func TestGenerateSnapshotRejectsInvalidResourceContent(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	state := &nodeState{}
	// Protobuf binary encoding rejects invalid UTF-8. The failure must be
	// reported during construction, not later when a watch consumes the snapshot.
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
	current, exists := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.True(t, exists)
	require.Same(t, listener, current)
	current, exists = c.GetResource(nodeID, typeurl.Endpoint, endpoint.ClusterName)
	require.True(t, exists)
	require.Same(t, endpoint, current)
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
			before := maps.Clone(c.nodeStates[nodeID].resourceEntries(typeurl.Route))
			previousGeneration := c.nodeStates[nodeID].resourceGeneration
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
				before = maps.Clone(c.nodeStates[nodeID].resourceEntries(typeurl.Route))
				previousGeneration = c.nodeStates[nodeID].resourceGeneration
				mock.setSnapshotErr = publicationErr
				if mode == "caller-revert" {
					require.NoError(t, rollback.Revert())
				} else {
					t.Cleanup(rollback.Finalize)
					snapshot := mustSnapshot(t, c, nodeID)
					c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(t.Context(), c.resourceGeneration), 1,
						&discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.RouteType},
						&discovery.DiscoveryResponse{
							TypeUrl: envoy_resource.RouteType, VersionInfo: snapshot.GetVersion(envoy_resource.RouteType), Nonce: "rejected-routes",
						})
					require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
						Node: node, TypeUrl: envoy_resource.RouteType,
						VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "rejected-routes",
						ErrorDetail: &status.Status{Message: "rejected routes"},
					}))
				}
			}
			// Failure restores complete entries, not just protobufs. This covers
			// prior absence, removal tombstones, and replacement generations even
			// when a revert has no separately constructed inverse maps.
			require.Equal(t, before, c.nodeStates[nodeID].resourceEntries(typeurl.Route))
			require.Equal(t, previousGeneration, c.nodeStates[nodeID].resourceGeneration)
			require.Greater(t, c.resourceGeneration, previousGeneration, "global generations are never rewound")
		})
	}
}

func TestNewCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)

	assert.NotNil(t, c.SnapshotCache)
	assert.NotNil(t, c.logger)
}

func TestGetSnapshot_ExistingNode(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	// Pre-populate a snapshot in the mock
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "test-listener", &envoy_config_listener.Listener{Name: "test-listener"})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listenersInSnapshot := snap.GetResources(envoy_resource.ListenerType)
	assert.NotNil(t, listenersInSnapshot)
	assert.Len(t, listenersInSnapshot, 1)

	endpointsInSnapshot := snap.GetResources(envoy_resource.EndpointType)
	assert.Empty(t, endpointsInSnapshot)

	clustersInSnapshot := snap.GetResources(envoy_resource.ClusterType)
	assert.Empty(t, clustersInSnapshot)

	routesInSnapshot := snap.GetResources(envoy_resource.RouteType)
	assert.Empty(t, routesInSnapshot)

	secretsInSnapshot := snap.GetResources(envoy_resource.SecretType)
	assert.Empty(t, secretsInSnapshot)

	networkPoliciesInSnapshot := snap.GetResources(NetworkPolicyTypeURL)
	assert.Empty(t, networkPoliciesInSnapshot)

	err = c.SetSnapshot(context.Background(), "node1", snap)
	require.NoError(t, err)
	require.Len(t, mock.setSnapshotCalls, 1)

	result, err := c.GetSnapshot("node1")
	require.NoError(t, err)
	assert.NotNil(t, result)

	require.Len(t, mock.getSnapshotCalls, 1)

	assert.False(t, c.areDifferentSnapshots(snap, result))
}

func TestGetSnapshot_NonExistingNode(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	result, err := c.GetSnapshot("nonexistent")
	require.Error(t, err)
	assert.Nil(t, result)

	require.Len(t, mock.getSnapshotCalls, 1)
	assert.Equal(t, "nonexistent", mock.getSnapshotCalls[0])
}

func TestSetSnapshot_Success(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	snap, err := c.generateSnapshotFromState(&nodeState{})
	require.NoError(t, err)

	ctx := context.Background()
	err = c.SetSnapshot(ctx, "node1", snap)
	require.NoError(t, err)

	// Verify SetSnapshot was called on the mock
	require.Len(t, mock.setSnapshotCalls, 1)
	assert.Equal(t, "node1", mock.setSnapshotCalls[0].nodeID)
	assert.Equal(t, snap, mock.setSnapshotCalls[0].snapshot)
}

func TestSetSnapshot_Error(t *testing.T) {
	mock := newMockSnapshotCache()
	mock.setSnapshotErr = fmt.Errorf("set snapshot failed")
	c := newTestCache(mock)

	snap := &cache.Snapshot{}
	err := c.SetSnapshot(context.Background(), "node1", snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set snapshot failed")

	require.Len(t, mock.setSnapshotCalls, 1)
}

func TestGetResourceByTypeAndName(t *testing.T) {
	c := newInitializedTestCache(newMockSnapshotCache())
	state := &nodeState{}
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
	c.nodeStates["node1"] = state

	for _, tt := range resources {
		got, ok := c.GetResource("node1", tt.typeURL, tt.name)
		require.True(t, ok, "%s %s", tt.typeURL.URL(), tt.name)
		require.Same(t, tt.want, got)
	}
	for _, tt := range []struct {
		nodeID  string
		typeURL typeurl.Index
		name    string
	}{
		{"unknown", typeurl.Listener, "listener"},
		{"node1", typeurl.Listener, "missing"},
		{"node1", typeurl.Route, "listener"},
		{"node1", typeurl.Count, "listener"},
	} {
		got, ok := c.GetResource(tt.nodeID, tt.typeURL, tt.name)
		require.False(t, ok)
		require.Nil(t, got)
	}
}

func TestResourceIterators(t *testing.T) {
	c := newInitializedTestCache(newMockSnapshotCache())
	state := &nodeState{}
	listener := &envoy_config_listener.Listener{Name: "listener"}
	route := &envoy_config_route.RouteConfiguration{Name: "route"}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	state.seedResource(typeurl.Listener, "listener", listener)
	state.seedResource(typeurl.Route, "route", route)
	state.seedResource(typeurl.NetworkPolicy, "policy", policy)
	c.nodeStates["node1"] = state

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

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	c.nodeStates["node1"] = state

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	_ = mock.SetSnapshot(context.Background(), "node1", snap)
	mock.setSnapshotCalls = nil // reset

	c.ClearSnapshot("node1")

	// Verify ClearSnapshot was called on the mock
	require.Len(t, mock.clearSnapshotCalls, 1)
	assert.Equal(t, "node1", mock.clearSnapshotCalls[0])

	// Verify desired resources were reset to empty.
	_, exists := c.GetResource("node1", typeurl.Listener, "l1")
	require.False(t, exists)
}

func TestGenerateSnapshot_WithAllResourceTypes(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "cluster1", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"})
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})
	state.seedResource(typeurl.Listener, "listener1", &envoy_config_listener.Listener{Name: "listener1"})
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})
	state.seedResource(typeurl.NetworkPolicy, "np1", &cilium.NetworkPolicy{EndpointId: 1})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NotNil(t, snap)

	assert.Len(t, snap.GetResources(envoy_resource.ListenerType), 1)
	assert.Len(t, snap.GetResources(envoy_resource.ClusterType), 1)
	assert.Empty(t, snap.GetResources(envoy_resource.RouteType))
	assert.Len(t, snap.GetResources(envoy_resource.EndpointType), 1)
	assert.Len(t, snap.GetResources(envoy_resource.SecretType), 1)
}

func TestGenerateSnapshot_AddsEmptyClusterLoadAssignmentForEDSCluster(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	require.Contains(t, endpoints, "cluster1")

	cla, ok := endpoints["cluster1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Equal(t, "cluster1", cla.ClusterName)
	assert.Empty(t, cla.Endpoints)
	assert.Empty(t, state.resources[typeurl.Endpoint].entries)
}

func TestGenerateSnapshot_AddsEmptyClusterLoadAssignmentForEDSServiceName(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			ServiceName: "service1",
		},
	})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	require.Contains(t, endpoints, "service1")
	require.NotContains(t, endpoints, "cluster1")

	cla, ok := endpoints["service1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Equal(t, "service1", cla.ClusterName)
	assert.Empty(t, state.resources[typeurl.Endpoint].entries)
}

func TestGenerateSnapshot_DoesNotOverwriteExistingClusterLoadAssignment(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	existingCLA := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}
	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})
	state.seedResource(typeurl.Endpoint, "cluster1", existingCLA)

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	cla, ok := endpoints["cluster1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Same(t, existingCLA, cla)
}

func TestGenerateSnapshot_DoesNotAddClusterLoadAssignmentForNonEDSCluster(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
	})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))
	assert.Empty(t, snap.GetResources(envoy_resource.EndpointType))
	assert.Empty(t, state.resources[typeurl.Endpoint].entries)
}

func TestUpdateSnapshot_RegistersNetworkPolicyCompletionForPolicyChange(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	snap := networkPolicySnapshot(t, c, 1)

	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err := c.UpdateSnapshot(context.Background(), "node1", 1, snap, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)

	assert.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	c.completionCbs.CancelPendingCompletions(typeurl.NetworkPolicy)
}

func TestUpdateSnapshot_CompletesAlreadyAckedNetworkPolicyVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snap := networkPolicySnapshot(t, c, 1)

	err := c.UpdateSnapshot(context.Background(), nodeID, 1, snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)
	ackNetworkPolicyVersion(t, c, nodeID, snap.GetVersion(NetworkPolicyTypeURL))

	var callbackErrs []error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), nodeID, 2, snap, wg,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			callbackErrs = append(callbackErrs, err)
		}})
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wg.Wait())
	require.Len(t, callbackErrs, 1)
	assert.NoError(t, callbackErrs[0])
}

func TestUpdateSnapshot_CompletesAlreadyAckedListenerVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snap := listenerSnapshot(t, c, "listener1")

	err := c.UpdateSnapshot(context.Background(), nodeID, 1, snap, nil, nil)
	require.NoError(t, err)
	ackListenerVersion(t, c, nodeID, snap.GetVersion(envoy_resource.ListenerType))

	var callbackErrs []error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), nodeID, 2, snap, wg,
		map[string]func(error){envoy_resource.ListenerType: func(err error) {
			callbackErrs = append(callbackErrs, err)
		}})
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wg.Wait())
	require.Len(t, callbackErrs, 1)
	assert.NoError(t, callbackErrs[0])
}

func TestUpdateSnapshot_CompletesUnsentCoalescedNetworkPolicyUpdates(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)
	require.NotEqual(t, snapA.GetVersion(NetworkPolicyTypeURL), snapB.GetVersion(NetworkPolicyTypeURL))

	err := c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)
	ackNetworkPolicyVersion(t, c, nodeID, snapA.GetVersion(NetworkPolicyTypeURL))

	var bCallbackErrs []error
	wgB := completion.NewWaitGroup(context.Background())
	defer wgB.Cancel()
	err = c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, wgB,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			bCallbackErrs = append(bCallbackErrs, err)
		}})
	require.NoError(t, err)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	var aCallbackErrs []error
	wgA := completion.NewWaitGroup(context.Background())
	defer wgA.Cancel()
	err = c.UpdateSnapshot(context.Background(), nodeID, 3, snapA, wgA,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			aCallbackErrs = append(aCallbackErrs, err)
		}})
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA.Wait())
	require.Len(t, bCallbackErrs, 1)
	assert.NoError(t, bCallbackErrs[0])
	require.Len(t, aCallbackErrs, 1)
	assert.NoError(t, aCallbackErrs[0])
}

func TestUpdateSnapshot_TrackedCompletionFollowsUntrackedGeneration(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))
	// The newer generation deliberately has no WaitGroup.
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, nil, nil))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(mock.setSnapshotCalls[1].ctx, 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL), TypeUrl: NetworkPolicyTypeURL})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL),
	}))

	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateSnapshot_ImmediateWatchRecoversUntrackedGeneration(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, nil, nil))

	// CreateWatch uses context.Background when Envoy connects after both
	// snapshots were published. The current published snapshot supplies gen 2.
	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL), TypeUrl: NetworkPolicyTypeURL})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL),
	}))

	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateSnapshot_UntrackedAcceptedGenerationCompletesPending(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, nil, nil))
	ackNetworkPolicyVersion(t, c, nodeID, snapA.GetVersion(NetworkPolicyTypeURL))

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	// Envoy already accepted A, so returning to A without a WaitGroup will not
	// produce another response. Successful publication still supersedes B.
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 3, snapA, nil, nil))
	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateSnapshot_FailedUntrackedGenerationIsNotObserved(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	mock.setSnapshotErr = errors.New("snapshot publication failed")
	require.Error(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, nil, nil))
	mock.setSnapshotErr = nil

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL), TypeUrl: NetworkPolicyTypeURL})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: snapB.GetVersion(NetworkPolicyTypeURL),
	}))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	ackNetworkPolicyVersion(t, c, nodeID, snapA.GetVersion(NetworkPolicyTypeURL))
	require.NoError(t, wg.Wait())
}

func TestUpdateSnapshot_ErrorAfterStoreCommitsGeneration(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	mock.storeSnapshotBeforeError = true
	mock.setSnapshotErr = errors.New("watch delivery failed after store")
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, nil, nil))

	ackNetworkPolicyVersion(t, c, nodeID, snapB.GetVersion(NetworkPolicyTypeURL))
	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateSnapshot_ResponseContextDisambiguatesABAGeneration(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snapA := networkPolicySnapshot(t, c, 1)
	snapB := networkPolicySnapshot(t, c, 2)

	wgA1 := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgA1.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snapA, wgA1,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	wgB := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgB.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, snapB, wgB,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	wgA2 := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgA2.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 3, snapA, wgA2,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	// Deliver the response constructed by the first SetSnapshot only after the
	// later A generation has been published. The response context, rather than
	// the repeated version hash, identifies which completion it can ACK.
	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(mock.setSnapshotCalls[0].ctx, 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: snapA.GetVersion(NetworkPolicyTypeURL), TypeUrl: NetworkPolicyTypeURL})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: snapA.GetVersion(NetworkPolicyTypeURL),
	}))

	require.NoError(t, wgA1.Wait())
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
}

func TestAwaitCurrentVersion_AttachesToPendingNetworkPolicyResponse(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snap := networkPolicySnapshot(t, c, 1)
	version := snap.GetVersion(NetworkPolicyTypeURL)

	firstWG := completion.NewWaitGroup(context.Background())
	defer firstWG.Cancel()
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snap, firstWG,
		map[string]func(error){NetworkPolicyTypeURL: nil}))

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: version, TypeUrl: NetworkPolicyTypeURL})

	callbackCalled := false
	var callbackErr error
	secondWG := completion.NewWaitGroup(context.Background())
	defer secondWG.Cancel()
	require.NoError(t, c.awaitCurrentVersion(nodeID, secondWG,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			callbackCalled = true
			callbackErr = err
		}}))

	require.Len(t, mock.setSnapshotCalls, 1)
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: version,
	}))
	require.NoError(t, firstWG.Wait())
	require.NoError(t, secondWG.Wait())
	require.True(t, callbackCalled)
	require.NoError(t, callbackErr)
}

func TestGenerationZeroCompletionAttachesToResponse(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	const nodeID = "node1"
	snapshot := listenerSnapshot(t, c, "listener")
	version := snapshot.GetVersion(envoy_resource.ListenerType)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	registered, immediate := c.registerGenerationCompletions(
		nodeID, snapshot, wg, func() typeURLWaits {
			var waits typeURLWaits
			waits.Set(typeurl.Listener, generationWait{generation: 0})
			return waits
		}())
	require.Equal(t, 1, registered.Len())
	require.Empty(t, immediate)

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(ctx, 1), 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.ListenerType},
		&discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "nonce",
		})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		VersionInfo:   version,
		ResponseNonce: "nonce",
	}))
	require.NoError(t, wg.Wait())
}

func TestAwaitCurrentVersion_CompletesAlreadyAckedNetworkPolicyVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	snap := networkPolicySnapshot(t, c, 1)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, snap, nil, nil))
	ackNetworkPolicyVersion(t, c, nodeID, snap.GetVersion(NetworkPolicyTypeURL))

	callbackCalled := false
	var callbackErr error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()
	require.NoError(t, c.awaitCurrentVersion(nodeID, wg,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			callbackCalled = true
			callbackErr = err
		}}))

	require.Len(t, mock.setSnapshotCalls, 1)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wg.Wait())
	require.True(t, callbackCalled)
	require.NoError(t, callbackErr)
}

func TestAwaitCurrentVersion_CompletesAlreadyNackedNetworkPolicyVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	acceptedSnapshot := networkPolicySnapshot(t, c, 1)
	rejectedSnapshot := networkPolicySnapshot(t, c, 2)
	acceptedVersion := acceptedSnapshot.GetVersion(NetworkPolicyTypeURL)
	rejectedVersion := rejectedSnapshot.GetVersion(NetworkPolicyTypeURL)
	require.NotEqual(t, acceptedVersion, rejectedVersion)

	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, acceptedSnapshot, nil, nil))
	ackNetworkPolicyVersion(t, c, nodeID, acceptedVersion)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, rejectedSnapshot, nil, nil))

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: rejectedVersion, TypeUrl: NetworkPolicyTypeURL})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: acceptedVersion,
		ErrorDetail: &status.Status{Message: "rejected policy"},
	}))

	var callbackErr error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()
	require.NoError(t, c.awaitCurrentVersion(nodeID, wg,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) { callbackErr = err }}))

	require.Len(t, mock.setSnapshotCalls, 2)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.ErrorContains(t, wg.Wait(), "rejected policy")
	require.ErrorContains(t, callbackErr, "rejected policy")
}

// --- Snapshot versions ---

func TestSnapshotVersion_DifferentResourcesProduceDifferentVersions(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state1 := &nodeState{}
	state1.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state2 := &nodeState{}
	state2.seedResource(typeurl.Listener, "l2", &envoy_config_listener.Listener{Name: "l2"})

	snapshot1, err := c.generateSnapshotFromState(state1)
	require.NoError(t, err)
	snapshot2, err := c.generateSnapshotFromState(state2)
	require.NoError(t, err)
	v1 := snapshot1.GetVersion(envoy_resource.ListenerType)
	v2 := snapshot2.GetVersion(envoy_resource.ListenerType)

	assert.NotEmpty(t, v1)
	assert.NotEmpty(t, v2)
	assert.NotEqual(t, v1, v2)
}

func TestSnapshotVersion_SameResourcesProduceSameVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state1 := &nodeState{}
	state1.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state2 := &nodeState{}
	state2.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})

	snapshot1, err := c.generateSnapshotFromState(state1)
	require.NoError(t, err)
	snapshot2, err := c.generateSnapshotFromState(state2)
	require.NoError(t, err)
	v1 := snapshot1.GetVersion(envoy_resource.ListenerType)
	v2 := snapshot2.GetVersion(envoy_resource.ListenerType)

	assert.Equal(t, v1, v2)
}

// --- AreDifferentSnapshots ---

func TestAreDifferentSnapshots_Identical(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})

	snap1, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	snap2, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	assert.False(t, c.areDifferentSnapshots(snap1, snap2))
}

func TestAreDifferentSnapshots_Different(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state1 := &nodeState{}
	state1.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state2 := &nodeState{}
	state2.seedResource(typeurl.Listener, "l2", &envoy_config_listener.Listener{Name: "l2"})

	snap1, err := c.generateSnapshotFromState(state1)
	require.NoError(t, err)
	snap2, err := c.generateSnapshotFromState(state2)
	require.NoError(t, err)

	assert.True(t, c.areDifferentSnapshots(snap1, snap2))
}

// --- CreateWatch ---

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
		WithListenerObserver(observer)).(*cacheImpl)

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
		WithListenerObserver(observer)).(*cacheImpl)
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
		_, _ = c.GetResource("node1", typeurl.NetworkPolicy, "policy")
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
	_, exists := c.GetResource("node1", typeurl.NetworkPolicy, "policy")
	require.True(t, exists, "releasing the wait must not revert the policy")

	// The caller's rollback remains usable after its ACK wait was released.
	require.NoError(t, policyRollback.Revert())
	_, exists = c.GetResource("node1", typeurl.NetworkPolicy, "policy")
	require.False(t, exists)

	noListenerWG := completion.NewWaitGroup(ctx)
	defer noListenerWG.Cancel()
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, noListenerWG, callback)
	require.NoError(t, err)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, noListenerWG.Wait())
	require.Equal(t, 3, callbacks)
}

func TestNetworkPolicyWaitCompletesWhenLastListenerIsReverted(t *testing.T) {
	observer := &testNPDSListenerObserver{
		nodeID: "node1",
		matches: func(listener *envoy_config_listener.Listener) bool {
			return listener.GetName() == "npds-listener"
		},
	}
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false,
		WithListenerObserver(observer)).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	listenerRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.Listener, "npds-listener",
		&envoy_config_listener.Listener{Name: "npds-listener"}, nil, nil)

	require.NoError(t, err)
	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, wg, nil)

	require.NoError(t, err)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	require.NoError(t, listenerRollback.Revert())
	require.Zero(t, observer.count)
	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	_, exists := c.GetResource("node1", typeurl.NetworkPolicy, "policy")
	require.True(t, exists)
}

func TestFirstUntrackedSnapshotNACKRevertsColdStartResources(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	// Initial endpoint policies are populated before Envoy connects and do not
	// have WaitGroups. Caller finalization must leave the coalesced response
	// rollback intact so the first response can still be NACKed safely.
	for id := uint64(1); id <= 2; id++ {
		name := strconv.FormatUint(id, 10)
		rollback, err := c.ApplyResourceWithRollback(
			ctx, "node1", typeurl.NetworkPolicy,
			name, &cilium.NetworkPolicy{EndpointId: id}, nil, nil)

		require.NoError(t, err)
		require.NotNil(t, rollback)
		rollback.Finalize()
	}

	state := c.nodeStates["node1"]
	policyRollback, exists := state.unsentRollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.NotNil(t, policyRollback.resources)
	coldStartRollback := (*policyRollback.resources)[typeurl.NetworkPolicy]
	require.Len(t, coldStartRollback, 2)
	for _, rollback := range coldStartRollback {
		require.Nil(t, rollback.previous.resource,
			"cold-start rollback must not retain a protobuf that did not exist")
		require.Zero(t, rollback.previous.generation)
	}

	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	response := <-responses

	const nonce = "cold-start-response"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected initial policies"},
	}))

	require.Empty(t, maps.Collect(c.NetworkPolicies("node1")),
		"a NACK of the first response must restore the empty cache baseline")
}

func TestAcceptedRemovalsReleaseTombstones(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	const resources = 100

	for id := range resources {
		name := strconv.Itoa(id)
		rollback, err := c.ApplyResourceWithRollback(
			t.Context(), "node1", typeurl.NetworkPolicy,
			name, &cilium.NetworkPolicy{EndpointId: uint64(id)}, nil, nil)

		require.NoError(t, err)
		rollback.Finalize()
	}
	initial := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	for id := range resources {
		name := strconv.Itoa(id)
		rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicy, name, nil, nil, nil)
		require.NoError(t, err)
		rollback.Finalize()
	}
	removed := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", removed.GetVersion(NetworkPolicyTypeURL))

	state := c.nodeStates["node1"]
	require.Empty(t, state.resources[typeurl.NetworkPolicy].entries,
		"finalized removals must not leave generation tombstones behind")
	require.True(t, state.rollbackOwners.Empty())
}

func TestAcceptedRemovalReleasesResponseTombstone(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	rollback, err := c.ApplyResourceWithRollback(
		ctx, "node1", typeurl.NetworkPolicy,
		"policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	rollback.Finalize()
	initial := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initial.GetVersion(NetworkPolicyTypeURL),
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)

	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", nil, wg, nil)
	require.NoError(t, err)
	rollback.Finalize()
	tombstone := c.nodeStates["node1"].resources[typeurl.NetworkPolicy].entries["policy"]
	require.Nil(t, tombstone.resource)
	require.False(t, c.nodeStates["node1"].rollbackOwners.Empty(),
		"caller finalization must leave the response-owned removal rollback live")
	response := <-responses
	const nonce = "removal"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: nonce,
	}))
	require.NoError(t, wg.Wait())
	require.Empty(t, c.nodeStates["node1"].resources[typeurl.NetworkPolicy])
	require.True(t, c.nodeStates["node1"].rollbackOwners.Empty())
}

func TestNACKedRemovalRestoresResourceAfterCallerCompletion(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
	initial := mustSnapshot(t, c, "node1")
	initialVersion := initial.GetVersion(NetworkPolicyTypeURL)
	ackNetworkPolicyVersion(t, c, "node1", initialVersion)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initialVersion,
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)

	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", nil, wg, nil)
	require.NoError(t, err)
	rollback.Finalize()
	response := <-responses

	const nonce = "rejected-removal"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   initialVersion,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected removal"},
	}))
	require.Same(t, policy, c.nodeStates["node1"].resources[typeurl.NetworkPolicy].entries["policy"].resource,
		"completing the caller early must not make a sent removal irreversible")
}

func TestNACKRevertsAfterWaitCancellationAndCallerFinalize(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policyA, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
	initial := mustSnapshot(t, c, "node1")
	initialVersion := initial.GetVersion(NetworkPolicyTypeURL)
	ackNetworkPolicyVersion(t, c, "node1", initialVersion)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initialVersion,
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)

	waitCtx, cancelWait := context.WithCancel(ctx)
	wg := completion.NewWaitGroup(waitCtx)
	t.Cleanup(wg.Cancel)
	policyB := &cilium.NetworkPolicy{EndpointId: 2}
	rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policyB, wg, nil)
	require.NoError(t, err)
	response := <-responses

	const nonce = "timed-out-response"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	cancelWait()
	require.ErrorIs(t, wg.Wait(), context.Canceled)
	rollback.Finalize()
	require.Same(t, policyB, c.nodeStates["node1"].resources[typeurl.NetworkPolicy].entries["policy"].resource)

	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   initialVersion,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected after timeout"},
	}))
	require.Same(t, policyA, c.nodeStates["node1"].resources[typeurl.NetworkPolicy].entries["policy"].resource,
		"caller timeout and finalization must not disable the response-owned NACK revert")
}

func TestResourceUpdateRevertibleIsNoOpAfterFirstCall(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	initialRollback, err := c.ApplyResourceWithRollback(
		t.Context(), "node1", typeurl.NetworkPolicy,
		"policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	initialRollback.Finalize()

	rollback, err := c.ApplyResourceWithRollback(
		t.Context(), "node1", typeurl.NetworkPolicy,
		"policy", &cilium.NetworkPolicy{EndpointId: 2}, nil, nil)

	require.NoError(t, err)
	rollback.Finalize()
	generation := c.resourceGeneration
	require.NoError(t, rollback.Revert())
	rollback.Finalize()
	require.Equal(t, generation, c.resourceGeneration, "duplicate resolution must not publish an update")
	policy := c.nodeStates["node1"].resources[typeurl.NetworkPolicy].entries["policy"].resource.(*cilium.NetworkPolicy)
	require.Equal(t, uint64(2), policy.EndpointId)
}

func TestApplyResourcesOwnsGlobalGenerationAndPerNodeReverts(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	apply := func(nodeID string, endpointID uint64) Rollback {
		t.Helper()
		rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)
		require.NoError(t, err)
		return rollback
	}
	applyPlain := func(nodeID string, endpointID uint64) {
		t.Helper()
		err := c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)
		require.NoError(t, err)
	}

	applyPlain("node-a", 1)           // global generation 1
	applyPlain("node-b", 1)           // global generation 2
	revertNodeA := apply("node-a", 2) // global generation 3
	applyPlain("node-b", 2)           // global generation 4
	require.Equal(t, uint64(4), c.resourceGeneration)
	require.Equal(t, uint64(3), c.nodeStates["node-a"].resourceGeneration)
	require.Equal(t, uint64(4), c.nodeStates["node-b"].resourceGeneration)

	require.NoError(t, revertNodeA.Revert())
	require.Equal(t, uint64(5), c.resourceGeneration)
	require.Equal(t, uint64(5), c.nodeStates["node-a"].resourceGeneration)
	require.Equal(t, uint64(4), c.nodeStates["node-b"].resourceGeneration)
	require.Equal(t, uint64(1), c.nodeStates["node-a"].resources[typeurl.NetworkPolicy].entries["policy"].generation,
		"reverting must restore the resource's original generation, not the new publication generation")
	resource, exists := c.GetResource("node-a", typeurl.NetworkPolicy, "policy")
	require.True(t, exists)
	require.Equal(t, uint64(1), resource.(*cilium.NetworkPolicy).EndpointId)
}

func TestApplyResourcesRevertOnlyRestoresOwnedResourceVersions(t *testing.T) {
	newCache := func(t *testing.T) *cacheImpl {
		t.Helper()
		return NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	}
	routes := func(values map[string]uint64) ResourceMutations {
		resources := make(map[string]*envoy_config_route.RouteConfiguration, len(values))
		for name, endpointID := range values {
			resources[name] = &envoy_config_route.RouteConfiguration{Name: strconv.FormatUint(endpointID, 10)}
		}
		return ResourceMutations{Upserted: xds.Resources{Routes: resources}}
	}
	apply := func(t *testing.T, c *cacheImpl, mutations ResourceMutations) Rollback {
		t.Helper()
		rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node-a", mutations, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		require.NotNil(t, rollback)
		return rollback
	}
	applyPlain := func(t *testing.T, c *cacheImpl, mutations ResourceMutations) {
		t.Helper()
		err := c.ApplyResources(t.Context(), "node-a", mutations, nil, TypeURLCallbacks{})
		require.NoError(t, err)
	}

	for _, mode := range []string{"NACK-driven", "caller-driven"} {
		t.Run(mode, func(t *testing.T) {
			c := newCache(t)
			applyPlain(t, c, routes(map[string]uint64{"newer": 1, "unchanged": 1}))
			node := &envoy_config_core.Node{Id: "node-a"}
			baseline := mustSnapshot(t, c, node.Id)
			acceptPublishedSnapshotVersions(t, c, 1, node, baseline)
			rollback := apply(t, c, routes(map[string]uint64{"newer": 2, "unchanged": 2}))
			if mode == "NACK-driven" {
				defer rollback.Finalize()
			}
			// Bind the response before the newer resource is changed, so its
			// NACK must not include the later update.
			snapshot := mustSnapshot(t, c, node.Id)
			c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(t.Context(), c.resourceGeneration), 1,
				&discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.RouteType},
				&discovery.DiscoveryResponse{
					VersionInfo: snapshot.GetVersion(envoy_resource.RouteType),
					TypeUrl:     envoy_resource.RouteType,
					Nonce:       "rejected-routes",
				})
			applyPlain(t, c, routes(map[string]uint64{"newer": 3}))

			if mode == "NACK-driven" {
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node:          node,
					TypeUrl:       envoy_resource.RouteType,
					VersionInfo:   baseline.GetVersion(envoy_resource.RouteType),
					ResponseNonce: "rejected-routes",
					ErrorDetail:   &status.Status{Message: "rejected routes"},
				}))
			} else {
				require.NoError(t, rollback.Revert())
			}
			resources := maps.Collect(c.Routes("node-a"))
			require.Equal(t, "3", resources["newer"].Name,
				"a revert must not overwrite a resource changed by a newer generation")
			require.Equal(t, "1", resources["unchanged"].Name,
				"the same revert must still restore resources untouched by newer generations")
			entries := c.nodeStates[node.Id].resources[typeurl.Route].entries
			require.Equal(t, uint64(3), entries["newer"].generation)
			require.Equal(t, uint64(1), entries["unchanged"].generation)
		})
	}

	t.Run("removed resource ABA", func(t *testing.T) {
		c := newCache(t)
		applyPlain(t, c, routes(map[string]uint64{"newer": 1, "unchanged": 1}))
		removed := xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
			"newer": nil, "unchanged": nil,
		}}
		rollback := apply(t, c, ResourceMutations{Removed: removed})
		applyPlain(t, c, routes(map[string]uint64{"newer": 3}))
		applyPlain(t, c, ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"newer": nil}}})

		require.NoError(t, rollback.Revert())
		resources := maps.Collect(c.Routes("node-a"))
		require.NotContains(t, resources, "newer",
			"a newer removal must not be mistaken for the removal being reverted")
		require.Equal(t, "1", resources["unchanged"].Name)
	})
}

func TestApplyResourcesRevertCoversEnvoyResourceTypes(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	resources := func(version uint64, names ...string) xds.Resources {
		resources := xds.NewResources()
		for _, name := range names {
			versionedName := fmt.Sprintf("%s-%d", name, version)
			resources.Listeners[name] = &envoy_config_listener.Listener{Name: versionedName}
			resources.Routes[name] = &envoy_config_route.RouteConfiguration{Name: versionedName}
			resources.Clusters[name] = &envoy_config_cluster.Cluster{Name: versionedName}
			resources.Endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: versionedName}
			resources.Secrets[name] = &envoy_config_tls.Secret{Name: versionedName}
		}
		return resources
	}
	apply := func(resources xds.Resources) Rollback {
		t.Helper()
		rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node-a", ResourceMutations{Upserted: resources}, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		return rollback
	}
	applyPlain := func(resources xds.Resources) {
		t.Helper()
		err := c.ApplyResources(t.Context(), "node-a", ResourceMutations{Upserted: resources}, nil, TypeURLCallbacks{})
		require.NoError(t, err)
	}

	baseline := resources(1, "newer", "unchanged")
	applyPlain(baseline)
	revert := apply(resources(2, "newer", "unchanged"))
	newer := resources(3, "newer")
	applyPlain(newer)

	require.NoError(t, revert.Revert())
	for _, resource := range []struct {
		typeURL typeurl.Index
		newer   cache_types.Resource
		older   cache_types.Resource
	}{
		{typeurl.Listener, newer.Listeners["newer"], baseline.Listeners["unchanged"]},
		{typeurl.Route, newer.Routes["newer"], baseline.Routes["unchanged"]},
		{typeurl.Cluster, newer.Clusters["newer"], baseline.Clusters["unchanged"]},
		{typeurl.Endpoint, newer.Endpoints["newer"], baseline.Endpoints["unchanged"]},
		{typeurl.Secret, newer.Secrets["newer"], baseline.Secrets["unchanged"]},
	} {
		actual, found := c.GetResource("node-a", resource.typeURL, "newer")
		require.True(t, found)
		require.Same(t, resource.newer, actual)
		actual, found = c.GetResource("node-a", resource.typeURL, "unchanged")
		require.True(t, found)
		require.Same(t, resource.older, actual)
	}
}

func TestApplyResourcesAttachesNoOpDuringResponseDelivery(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, false)
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
	policySubscription := stream.NewSotwSubscription(nil, false)
	currentSnapshot := mustSnapshot(t, c, node.GetId())
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
	require.Greater(t, c.nodeStates[node.GetId()].snapshotGeneration,
		c.nodeStates[node.GetId()].resources[typeurl.Listener].entries[listener.GetName()].generation)

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
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, false)

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
	require.True(t, c.nodeStates[node.GetId()].unsentRollbacks.Empty())

	// This RDS watch is idle: removing a listener with no RDS reference does
	// not change the RDS version and must not consume this watch.
	routeResponses := make(chan cache.Response, 1)
	cancelRoute, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.RouteType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.RouteType),
	}, subscription, routeResponses)
	require.NoError(t, err)
	t.Cleanup(cancelRoute)
	initialGeneration := c.nodeStates[node.GetId()].snapshotGeneration

	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), nil, nil, nil)
	require.NoError(t, err)
	require.Greater(t, c.nodeStates[node.GetId()].snapshotGeneration, initialGeneration)
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

	state := c.nodeStates[node.GetId()]
	require.True(t, state.unsentRollbacks.Empty())
	require.True(t, state.rollbackOwners.Empty())
	require.Empty(t, state.resources[typeurl.Listener].entries,
		"an ACKed removal must not retain a tombstone for unchanged dependent types")
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly received the listener update")
	default:
	}
}

func TestPublishedUnsentRollbackDropsAddedThenRemovedEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}

	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan"}
	cluster := &envoy_config_cluster.Cluster{Name: "unrelated-cluster"}
	err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Clusters:  map[string]*envoy_config_cluster.Cluster{"unrelated-cluster": cluster},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"orphan": endpoint},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	clusterResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ClusterType,
	}, stream.NewSotwSubscription(nil, false), clusterResponses)
	require.NoError(t, err)
	response := <-clusterResponses
	cancel()
	acknowledgeResponse(t, c, 1, response, "initial-cluster")
	_, exists := c.nodeStates[nodeID].unsentRollbacks.Get(typeurl.Endpoint)
	require.True(t, exists, "EDS rollback remains unsent without an EDS subscription")

	previous := mustSnapshot(t, c, nodeID)
	clusterResponses = make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ClusterType,
		VersionInfo: previous.GetVersion(envoy_resource.ClusterType),
	}, stream.NewSotwSubscription(nil, false), clusterResponses)
	require.NoError(t, err)
	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Removed: xds.Resources{Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"orphan": endpoint}},
		Upserted: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{
			"another-cluster": {Name: "another-cluster"},
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	response = <-clusterResponses
	cancel()
	acknowledgeResponse(t, c, 1, response, "updated-cluster")

	state := c.nodeStates[nodeID]
	require.NotNil(t, state)
	require.True(t, state.unsentRollbacks.Empty(), "the net-zero EDS rollback must be discarded")
	require.True(t, state.rollbackOwners.Empty())
	require.Empty(t, state.resources[typeurl.Endpoint].entries)
}

func TestPublishedUnsentRollbackCoalescesUntilResponse(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}

	baselineListener := &envoy_config_listener.Listener{Name: "listener-0"}
	baselinePolicy := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", baselinePolicy, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": baselineListener},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	listenerResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, false), listenerResponses)
	require.NoError(t, err)
	initialResponse := <-listenerResponses
	cancel()
	acknowledgeResponse(t, c, 1, initialResponse, "initial-listener")
	baselineSnapshot := mustSnapshot(t, c, nodeID)
	acceptPublishedSnapshotVersions(t, c, 1, node, baselineSnapshot)
	require.True(t, c.nodeStates[nodeID].unsentRollbacks.Empty())

	var policyRollback *rollbackLifecycle
	var latestListener *envoy_config_listener.Listener
	for update := uint64(2); update <= 9; update++ {
		previousSnapshot := mustSnapshot(t, c, nodeID)
		listenerResponses = make(chan cache.Response, 1)
		cancel, err = c.CreateWatch(&cache.Request{
			Node: node, TypeUrl: envoy_resource.ListenerType,
			VersionInfo: previousSnapshot.GetVersion(envoy_resource.ListenerType),
		}, stream.NewSotwSubscription(nil, false), listenerResponses)
		require.NoError(t, err)

		var policy *cilium.NetworkPolicy
		if update%2 == 0 {
			policy = &cilium.NetworkPolicy{EndpointId: update}
		}
		err = c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", policy, nil, nil)
		require.NoError(t, err)
		latestListener = &envoy_config_listener.Listener{Name: fmt.Sprintf("listener-%d", update)}
		err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
			Listeners: map[string]*envoy_config_listener.Listener{"listener": latestListener},
		}}, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		response := <-listenerResponses
		cancel()
		acknowledgeResponse(t, c, 1, response, fmt.Sprintf("listener-%d", update))

		current, exists := c.nodeStates[nodeID].unsentRollbacks.Get(typeurl.NetworkPolicy)
		require.True(t, exists)
		require.NotNil(t, current)
		if policyRollback == nil {
			policyRollback = current
		} else {
			require.Same(t, policyRollback, current,
				"published NetworkPolicy updates must reuse one unsent rollback lifecycle")
		}
		require.Len(t, current.resources[typeurl.NetworkPolicy], 1)
		require.Same(t, baselinePolicy, current.resources[typeurl.NetworkPolicy]["policy"].previous.resource)
		require.Empty(t, current.resources[typeurl.Listener],
			"NetworkPolicy rollback state must not retain Listener updates")
	}
	owners, exists := c.nodeStates[nodeID].rollbackOwners.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.Len(t, owners, 1,
		"the final unsent removal must retain exactly one coalesced tombstone owner")

	latestSnapshot := mustSnapshot(t, c, nodeID)
	policyResponses := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: NetworkPolicyTypeURL,
		VersionInfo: baselineSnapshot.GetVersion(NetworkPolicyTypeURL),
	}, stream.NewSotwSubscription(nil, false), policyResponses)
	require.NoError(t, err)
	policyResponse := <-policyResponses
	cancel()
	require.Equal(t, latestSnapshot.GetVersion(NetworkPolicyTypeURL), policyResponse.GetResponseVersion())
	require.True(t, c.nodeStates[nodeID].unsentRollbacks.Empty(),
		"producing the response must transfer rollback ownership to its ACK/NACK lifecycle")

	const policyNonce = "coalesced-policy"
	c.completionCbs.OnStreamResponse(policyResponse.GetContext(), 2, policyResponse.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: policyResponse.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       policyNonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   baselineSnapshot.GetVersion(NetworkPolicyTypeURL),
		ResponseNonce: policyNonce,
		ErrorDetail:   &status.Status{Message: "rejected coalesced policy"},
	}))

	listener, exists := c.GetResource(nodeID, typeurl.Listener, "listener")
	require.True(t, exists)
	require.Same(t, latestListener, listener,
		"a NetworkPolicy NACK must not revert Listener updates from the same transaction")
	policy, exists := c.GetResource(nodeID, typeurl.NetworkPolicy, "policy")
	require.True(t, exists)
	require.Same(t, baselinePolicy, policy)
	require.True(t, c.nodeStates[nodeID].rollbackOwners.Empty())
}

func TestUpsertNetworkPolicyCompletesCoalescedABAWithoutAnotherResponse(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, false)

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policyA, nil, nil)
	require.NoError(t, err)
	responses := make(chan cache.Response, 1)
	_, err = c.CreateWatch(&cache.Request{Node: node, TypeUrl: NetworkPolicyTypeURL}, subscription, responses)
	require.NoError(t, err)
	responseA := <-responses
	subscription.SetReturnedResources(responseA.GetReturnedResources())
	c.completionCbs.OnStreamResponse(responseA.GetContext(), 1, responseA.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: responseA.GetResponseVersion(),
			TypeUrl:     NetworkPolicyTypeURL,
			Nonce:       "nonce-a",
		})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   responseA.GetResponseVersion(),
		ResponseNonce: "nonce-a",
	}))

	wgB := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgB.Cancel)
	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 2}, wgB, nil)
	require.NoError(t, err)
	wgA := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgA.Cancel)
	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policyA, wgA, nil)
	require.NoError(t, err)
	// Returning to the already accepted A completes both intermediate
	// generations without requiring another Envoy response.
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	published, err := c.SnapshotCache.GetSnapshot(node.GetId())
	require.NoError(t, err)
	require.Equal(t, responseA.GetResponseVersion(), published.GetVersion(NetworkPolicyTypeURL))

	// CreateWatch opens a watch without emitting another response.
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: NetworkPolicyTypeURL, VersionInfo: responseA.GetResponseVersion(),
	}, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	afterWatch, err := c.SnapshotCache.GetSnapshot(node.GetId())
	require.NoError(t, err)
	require.Same(t, published, afterWatch, "CreateWatch must not publish another snapshot")
	select {
	case <-responses:
		t.Fatal("unexpected response for already accepted contents")
	default:
	}
}

func TestCreateWatchPublishesEmptySnapshotForUnknownNode(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	nodeID := "node-without-resources"
	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: nodeID},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: "stale-version",
	}
	subscription := stream.NewSotwSubscription(nil, false)
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
	require.NotContains(t, c.nodeStates, nodeID)

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
	require.NotContains(t, c.nodeStates, nodeID)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	err = c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	require.Contains(t, c.nodeStates, nodeID)

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
	require.NotContains(t, c.nodeStates, "node1")
	require.Empty(t, c.openWatches)
	require.Empty(t, c.watchRelays)
}

func TestRemoveNetworkPolicyFromUnknownNodeIsNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	callbackCalls := 0

	rollback, err := c.ApplyResourceWithRollback(ctx, "unknown-node", typeurl.NetworkPolicy, "missing-policy", nil, wg, func(err error) {
		require.NoError(t, err)
		callbackCalls++
	})

	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NoError(t, wg.Wait())
	require.Equal(t, 1, callbackCalls)
	require.NotContains(t, c.nodeStates, "unknown-node")
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
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
			rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.Error(t, err)
			require.Nil(t, rollback)
			require.NotContains(t, c.nodeStates, "node1")
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
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
			err := c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.NoError(t, err)
			actual, exists := c.GetResource("node1", tt.typeURL, "resource")
			require.True(t, exists)
			require.Same(t, tt.resource, actual)

			err = c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.removed, nil, nil)
			require.NoError(t, err)
			_, exists = c.GetResource("node1", tt.typeURL, "resource")
			require.False(t, exists)
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
			c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
			rollback, err := tt.apply(c)
			require.ErrorContains(t, err, "resource name must not be empty")
			require.Nil(t, rollback)
			require.Empty(t, c.nodeStates)
		})
	}
}

func TestApplyResourcesRemovalsFromUnknownNodeAreNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	callbackCalls := 0
	callback := func(err error) {
		require.NoError(t, err)
		callbackCalls++
	}

	rollback, err := c.ApplyResourcesWithRollback(ctx, "unknown-node", ResourceMutations{
		Removed: xds.Resources{
			Listeners: map[string]*envoy_config_listener.Listener{"listener": nil},
		},
	}, wg, indexedTypeURLCallbacks(map[string]func(error){
		envoy_resource.ListenerType: callback,
	}))
	require.NoError(t, err)
	require.Nil(t, rollback)
	rollback, err = c.ApplyResourceWithRollback(ctx, "unknown-node", typeurl.NetworkPolicy, "policy", nil, wg, callback)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NoError(t, wg.Wait())
	require.Equal(t, 2, callbackCalls)
	require.NotContains(t, c.nodeStates, "unknown-node")
}

func TestApplyResourcesNilUpsertFromUnknownNodeIsNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	rollback, err := c.ApplyResourcesWithRollback(t.Context(), "unknown-node", ResourceMutations{
		Upserted: xds.Resources{
			Routes: map[string]*envoy_config_route.RouteConfiguration{"route": nil},
		},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.NotContains(t, c.nodeStates, "unknown-node")
}

func TestCreateWatch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	respChan := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{TypeUrl: envoy_resource.ListenerType}, nil, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)

	assert.Equal(t, 1, mock.createWatchCalls)
}

func TestCreateWatchPublishesEmptyListenerSnapshotForUnknownNode(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		for _, clientVersion := range []string{"", "stale-version"} {
			t.Run(fmt.Sprintf("strict-ads=%t/client-version=%q", strictADS, clientVersion), func(t *testing.T) {
				logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
				c := NewCache(logger, strictADS).(*cacheImpl)
				const nodeID = "node-without-resources"
				node := &envoy_config_core.Node{Id: nodeID}
				subscription := stream.NewSotwSubscription(nil, false)
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
				require.NotContains(t, c.nodeStates, nodeID, "connecting must not create desired resource state")

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
	c := NewCache(logger, false).(*cacheImpl)
	const nodeID = "node-with-listener"
	listener := &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil)
	require.NoError(t, err)
	snapshot := mustSnapshot(t, c, nodeID)

	responses := make(chan cache.Response, 1)
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
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
	storedListener, exists := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.True(t, exists)
	require.Same(t, listener, storedListener, "the watch must not replace desired resources")
}

func TestCreateWatchUnknownNodeSnapshotPublicationError(t *testing.T) {
	for _, stored := range []bool{false, true} {
		t.Run(fmt.Sprintf("stored=%t", stored), func(t *testing.T) {
			mock := newMockSnapshotCache()
			mock.setSnapshotErr = errors.New("response delivery failed")
			mock.storeSnapshotBeforeError = stored
			c := newTestCache(mock)
			request := &cache.Request{
				Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: envoy_resource.ListenerType,
			}
			cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), make(chan cache.Response, 1))
			if stored {
				require.NoError(t, err, "a stored snapshot is committed despite a delivery error")
				require.NotNil(t, cancel)
				require.Equal(t, 1, mock.createWatchCalls)
			} else {
				require.ErrorContains(t, err, "response delivery failed")
				require.Nil(t, cancel)
				require.Zero(t, mock.createWatchCalls)
			}
			require.NotContains(t, c.nodeStates, "node1")
		})
	}
}

func TestCreateWatch_IgnoresEmptySecretSubscription(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, c.SetSnapshot(context.Background(), "node1", snap))

	req := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: envoy_resource.SecretType,
	}
	respChan := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(req, stream.NewSotwSubscription(req.GetResourceNames(), false), respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)
	defer cancel()

	select {
	case resp := <-respChan:
		t.Fatalf("unexpected empty SDS subscription response: %#v", resp.GetReturnedResources())
	default:
	}

	namedReq := &cache.Request{
		Node:          &envoy_config_core.Node{Id: "node1"},
		TypeUrl:       envoy_resource.SecretType,
		ResourceNames: []string{"secret1"},
	}
	namedRespChan := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(namedReq, stream.NewSotwSubscription(namedReq.GetResourceNames(), false), namedRespChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)
	defer cancel()

	select {
	case resp := <-namedRespChan:
		require.Contains(t, resp.GetReturnedResources(), "secret1")
	default:
		t.Fatal("expected named SDS subscription response")
	}
}

// --- CreateDeltaWatch ---

func TestCreateDeltaWatch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	cancel, err := c.CreateDeltaWatch(nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, cancel)
	assert.Equal(t, 1, mock.createDeltaCalls)
}

// --- Fetch ---

func TestFetch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	_, err := c.Fetch(context.Background(), &cache.Request{TypeUrl: envoy_resource.ListenerType})
	// Our mock returns an error
	require.Error(t, err)
	assert.Equal(t, 1, mock.fetchCalls)
}

// --- GetStatusInfo ---

func TestGetStatusInfo_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	result := c.GetStatusInfo("node1")
	assert.Nil(t, result) // mock returns nil

	require.Len(t, mock.getStatusInfoCalls, 1)
	assert.Equal(t, "node1", mock.getStatusInfoCalls[0])
}

// --- GetStatusKeys ---

func TestGetStatusKeys_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	keys := c.GetStatusKeys()
	assert.Empty(t, keys)
	assert.Equal(t, 1, mock.getStatusKeysCalls)
}

// --- Integration-style: SetSnapshot + GetSnapshot round-trip ---

func TestSetAndGetSnapshotRoundTrip(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	ctx := context.Background()

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state.seedResource(typeurl.Cluster, "c1", &envoy_config_cluster.Cluster{Name: "c1"})

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	err = c.SetSnapshot(ctx, "node1", snap)
	require.NoError(t, err)

	retrieved, err := c.GetSnapshot("node1")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	// Versions should match
	assert.Equal(t,
		snap.GetVersion(envoy_resource.ListenerType),
		retrieved.GetVersion(envoy_resource.ListenerType),
	)
	assert.Equal(t,
		snap.GetVersion(envoy_resource.ClusterType),
		retrieved.GetVersion(envoy_resource.ClusterType),
	)

	// Verify both SetSnapshot and GetSnapshot were called on the mock
	require.Len(t, mock.setSnapshotCalls, 1)
	require.Len(t, mock.getSnapshotCalls, 1)
}

// --- GenerateSnapshot versions are deterministic ---

func TestGenerateSnapshot_VersionIsDeterministic(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state.seedResource(typeurl.Cluster, "c1", &envoy_config_cluster.Cluster{Name: "c1"})

	snap1, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	snap2, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	for _, rType := range []envoy_resource.Type{
		envoy_resource.EndpointType,
		envoy_resource.ClusterType,
		envoy_resource.RouteType,
		envoy_resource.ListenerType,
		envoy_resource.SecretType,
	} {
		assert.Equal(t, snap1.GetVersion(rType), snap2.GetVersion(rType),
			"version mismatch for resource type %s", rType)
	}
}

// --- GenerateSnapshot populates all resource types correctly ---

func TestGenerateSnapshot_ResourceContents(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	listener := &envoy_config_listener.Listener{Name: "l1"}
	cluster := &envoy_config_cluster.Cluster{
		Name:                 "c1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	}
	ep := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "c1"}
	secret := &envoy_config_tls.Secret{Name: "s1"}

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", listener)
	state.seedResource(typeurl.Cluster, "c1", cluster)
	state.seedResource(typeurl.Endpoint, "c1", ep)
	state.seedResource(typeurl.Secret, "s1", secret)

	snap, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	// Verify each resource type has exactly one entry
	assertResourceCount := func(rType envoy_resource.Type, expected int) {
		t.Helper()
		resources := snap.GetResources(rType)
		assert.Len(t, resources, expected, "unexpected count for %s", rType)
	}

	assertResourceCount(envoy_resource.ListenerType, 1)
	assertResourceCount(envoy_resource.ClusterType, 1)
	assertResourceCount(envoy_resource.RouteType, 0)
	assertResourceCount(envoy_resource.EndpointType, 1)
	assertResourceCount(envoy_resource.SecretType, 1)
}
