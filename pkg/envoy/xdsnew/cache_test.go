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
	"reflect"
	"strconv"
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

func materializeResourceMap[V comparable](current map[string]resourceEntry[V]) map[string]V {
	materialized := make(map[string]V, len(current))
	var zero V
	for name, entry := range current {
		if entry.resource != zero {
			materialized[name] = entry.resource
		}
	}
	if len(materialized) == 0 {
		return nil
	}
	return materialized
}

func (state *nodeState) materializeResources() *xds.Resources {
	if state == nil {
		return nil
	}
	return &xds.Resources{
		Listeners:          materializeResourceMap(state.resources.listeners),
		Routes:             materializeResourceMap(state.resources.routes),
		Clusters:           materializeResourceMap(state.resources.clusters),
		Endpoints:          materializeResourceMap(state.resources.endpoints),
		Secrets:            materializeResourceMap(state.resources.secrets),
		NetworkPolicies:    materializeResourceMap(state.resources.networkPolicies),
		NetworkPolicyHosts: materializeResourceMap(state.resources.networkPolicyHosts),
	}
}

func typeURLWaitsFromCallbacks(callbacks map[string]func(error), generation uint64) typeURLWaits {
	var waits typeURLWaits
	for typeURLString, callback := range callbacks {
		if typeURL, ok := typeurl.FromURL(typeURLString); ok {
			waits.Set(typeURL, generationWait{callback: callback, generation: generation})
		}
	}
	return waits
}

func indexedTypeURLs(typeURLs map[string]struct{}) typeurl.Set {
	if typeURLs == nil {
		return typeurl.Set{}
	}
	result := typeurl.NewSet()
	for typeURLString := range typeURLs {
		if typeURL, ok := typeurl.FromURL(typeURLString); ok {
			result.Insert(typeURL)
		}
	}
	return result
}

func stringTypeURLs(typeURLs typeurl.Set) map[string]struct{} {
	if !typeURLs.Known() {
		return nil
	}
	result := make(map[string]struct{}, typeURLs.Len())
	for typeURL := range typeURLs.Members() {
		result[typeURL.URL()] = struct{}{}
	}
	return result
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
	err := tx.awaitCurrentVersionLocked(wg, waits)
	tx.complete()
	return err
}

type legacySnapshotGenerator func(*nodeState, cache.ResourceSnapshot, map[string]struct{}) (cache.ResourceSnapshot, error)

func indexedSnapshotGenerator(generator legacySnapshotGenerator) snapshotGenerator {
	return func(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
		return generator(state, previous, stringTypeURLs(changedTypeURLs))
	}
}

// getAllResources materializes the complete desired state for cache tests.
// The returned maps are independent, but their cache-owned protobuf values
// remain immutable.
func (c *cacheImpl) getAllResources(nodeID string) *xds.Resources {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.nodeStates[nodeID].materializeResources()
}

func (c *cacheImpl) updateResourceChanges(ctx context.Context, nodeID string, generation uint64, changes ResourceMutations, inverse cacheResources, dirtyTypeURLs map[string]struct{}, generator legacySnapshotGenerator, wg *completion.WaitGroup, updatedTypeURLs map[string]func(err error), restoredEntries *cacheResources) error {
	tx := c.beginResourceTransaction(ctx, nodeID)
	tx.generation = generation
	watchTypeURLs := mutationTypeURLs(changes)
	err := tx.updateResourceChangesLocked(changes, inverse, indexedTypeURLs(dirtyTypeURLs), watchTypeURLs, indexedSnapshotGenerator(generator), wg, typeURLWaitsFromCallbacks(updatedTypeURLs, generation), nil, restoredEntries)
	tx.complete()
	return err
}

// UpdateSnapshot preserves the eager publication shape used by the completion
// callback tests below. Production updates go through UpdateResources; these
// tests provide an already generated snapshot and explicitly finalize it.
func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, generation uint64, snapshot cache.ResourceSnapshot, wg *completion.WaitGroup, typeURLs map[string]func(error)) error {
	resources := emptyResources()
	for name, resource := range snapshot.GetResources(NetworkPolicyTypeURL) {
		if policy, ok := resource.(*cilium.NetworkPolicy); ok {
			resources.NetworkPolicies[name] = policy
		}
	}
	changedTypeURLs := make(map[string]struct{}, len(typeURLs))
	for typeURL := range typeURLs {
		changedTypeURLs[typeURL] = struct{}{}
	}
	if typeURLs == nil {
		changedTypeURLs = nil
	}
	generator := func(*nodeState, cache.ResourceSnapshot, map[string]struct{}) (cache.ResourceSnapshot, error) {
		return snapshot, nil
	}
	removed := xds.Resources{NetworkPolicies: maps.Collect(c.NetworkPolicies(nodeID))}
	mutations := ResourceMutations{Removed: removed, Upserted: xds.Resources{NetworkPolicies: resources.NetworkPolicies}}
	c.mutex.RLock()
	changes, _, inverse := c.nodeStates[nodeID].prepareResourceMutation(mutations)
	c.mutex.RUnlock()
	if err := c.updateResourceChanges(ctx, nodeID, generation, changes, inverse, stringTypeURLs(snapshotTypesChangedBy(indexedTypeURLs(changedTypeURLs))), generator, wg, typeURLs, nil); err != nil {
		return err
	}
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(ctx, nodeID)
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.completeFinalized(nodeID, finalized)
	return err
}

// updateResources preserves the full-state helper used by lazy-finalization
// tests while exercising the production delta application path.
func (c *cacheImpl) updateResources(ctx context.Context, nodeID string, generation uint64, resources *xds.Resources, dirtyTypeURLs map[string]struct{}, generator legacySnapshotGenerator, wg *completion.WaitGroup, updatedTypeURLs map[string]func(error)) error {
	var removed xds.Resources
	if current := c.getAllResources(nodeID); current != nil {
		removed = *current
	}
	var upserted xds.Resources
	if resources != nil {
		upserted = *resources
	}
	mutations := ResourceMutations{Removed: removed, Upserted: upserted}
	c.mutex.RLock()
	changes, _, inverse := c.nodeStates[nodeID].prepareResourceMutation(mutations)
	c.mutex.RUnlock()
	return c.updateResourceChanges(ctx, nodeID, generation, changes, inverse, dirtyTypeURLs, generator, wg, updatedTypeURLs, nil)
}

func emptyResources() *xds.Resources {
	return &xds.Resources{
		Listeners:          make(map[string]*envoy_config_listener.Listener),
		Clusters:           make(map[string]*envoy_config_cluster.Cluster),
		Routes:             make(map[string]*envoy_config_route.RouteConfiguration),
		Endpoints:          make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:            make(map[string]*envoy_config_tls.Secret),
		NetworkPolicies:    make(map[string]*cilium.NetworkPolicy),
		NetworkPolicyHosts: make(map[string]*cilium.NetworkPolicyHosts),
	}
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	require.NoError(t, err)
	return any
}

func networkPolicySnapshot(t *testing.T, c *cacheImpl, endpointID uint64) (*xds.Resources, cache.ResourceSnapshot) {
	t.Helper()

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: endpointID}
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	return resources, snap
}

func listenerSnapshot(t *testing.T, c *cacheImpl, name string) (*xds.Resources, cache.ResourceSnapshot) {
	t.Helper()

	resources := emptyResources()
	resources.Listeners[name] = &envoy_config_listener.Listener{Name: name}
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	return resources, snap
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

func TestNormalizeSnapshotResourcesReturnsOriginalWhenNoMissingClusterLoadAssignment(t *testing.T) {
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	}
	resources.Endpoints["cluster1"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}

	normalized := normalizeSnapshotResources(resources)
	require.Same(t, resources, normalized)
}

func TestNormalizeSnapshotResourcesAddsMissingClusterLoadAssignmentWithoutMutatingOriginal(t *testing.T) {
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	}

	normalized := normalizeSnapshotResources(resources)
	require.NotSame(t, resources, normalized)
	require.NotContains(t, resources.Endpoints, "cluster1")
	require.Contains(t, normalized.Endpoints, "cluster1")
	require.Equal(t, "cluster1", normalized.Endpoints["cluster1"].ClusterName)
}

func TestGenerateSnapshotEndpointVersionChangesWhenEDSClusterReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Endpoints["backend"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"}
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}

	before, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	resources.Clusters["cluster2"] = &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}

	after, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotEndpointVersionChangesWhenQualifiedEDSClusterReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Endpoints["backend"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"}
	resources.Clusters["cec-a/shared-cluster"] = &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}

	before, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	resources.Clusters["cec-b/shared-cluster"] = &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}

	after, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotRouteVersionChangesWhenRDSListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Routes["route1"] = &envoy_config_route.RouteConfiguration{Name: "route1"}

	before, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	resources.Listeners["listener1"] = &envoy_config_listener.Listener{
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

	after, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
}

func TestGenerateSnapshotSecretVersionChangesWhenSDSListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}

	before, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	resources.Listeners["listener1"] = &envoy_config_listener.Listener{
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

	after, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.SecretType), after.GetVersion(envoy_resource.SecretType))
}

func TestGenerateSnapshotClusterVersionChangesWhenTCPProxyListenerReferenceChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{Name: "cluster1"}

	before, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	resources.Listeners["listener1"] = &envoy_config_listener.Listener{
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

	after, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.ClusterType), after.GetVersion(envoy_resource.ClusterType))
}

func TestGenerateSnapshotIncrementallyReusesUnchangedResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Listeners["listener1"] = &envoy_config_listener.Listener{Name: "listener1"}
	resources.NetworkPolicies["changed"] = &cilium.NetworkPolicy{EndpointId: 1}
	resources.NetworkPolicies["equal"] = &cilium.NetworkPolicy{EndpointId: 2}
	resources.NetworkPolicies["removed"] = &cilium.NetworkPolicy{EndpointId: 4}

	previous, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	updated := *resources
	updated.NetworkPolicies = maps.Clone(resources.NetworkPolicies)
	updated.NetworkPolicies["changed"] = &cilium.NetworkPolicy{EndpointId: 3}
	// A different pointer with equal protobuf content must retain the already
	// published object and its cached content version.
	updated.NetworkPolicies["equal"] = proto.Clone(resources.NetworkPolicies["equal"]).(*cilium.NetworkPolicy)
	delete(updated.NetworkPolicies, "removed")
	updated.NetworkPolicies["added"] = &cilium.NetworkPolicy{EndpointId: 5}

	next, err := c.generateSnapshotIncrementally(
		&updated,
		previous,
		typeurl.NewSet(typeurl.NetworkPolicy),
		logger,
	)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)

	for typeURL := range typeurl.Indices() {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot[typeURL].resources.Items).Pointer(),
			"resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Same(t,
		previousSnapshot[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
		nextSnapshot[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
	)
	require.Same(t,
		updated.NetworkPolicies["changed"],
		nextSnapshot[typeurl.NetworkPolicy].resources.Items["changed"].Resource,
	)
	require.NotContains(t, nextSnapshot[typeurl.NetworkPolicy].resources.Items, "removed")
	require.NotContains(t, nextSnapshot[typeurl.NetworkPolicy].versions, "removed")
	require.Same(t,
		updated.NetworkPolicies["added"],
		nextSnapshot[typeurl.NetworkPolicy].resources.Items["added"].Resource,
	)
	require.Contains(t, nextSnapshot[typeurl.NetworkPolicy].versions, "added")
	require.NotEqual(t,
		previousSnapshot[typeurl.NetworkPolicy].versions["changed"],
		nextSnapshot[typeurl.NetworkPolicy].versions["changed"],
	)
	require.Equal(t,
		previousSnapshot[typeurl.NetworkPolicy].versions["equal"],
		nextSnapshot[typeurl.NetworkPolicy].versions["equal"],
	)
	versionMap := reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].versions).Pointer()
	require.NoError(t, next.ConstructVersionMap())
	require.Equal(t, versionMap, reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].versions).Pointer())
	for name, item := range nextSnapshot[typeurl.NetworkPolicy].resources.Items {
		marshaled, err := cache.MarshalResource(item.Resource)
		require.NoError(t, err)
		require.Equal(t, cache.HashResource(marshaled), next.GetVersionMap(NetworkPolicyTypeURL)[name])
	}

	fullyGenerated, err := c.generateSnapshot(&updated, logger)
	require.NoError(t, err)
	require.False(t, c.areDifferentSnapshots(next, fullyGenerated))
}

func TestGenerateSnapshotFromStateIncrementallyUsesPublishedCopyOnWriteMaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	resources.NetworkPolicies["changed"] = &cilium.NetworkPolicy{EndpointId: 1}
	resources.NetworkPolicies["unchanged"] = &cilium.NetworkPolicy{EndpointId: 2}
	resources.NetworkPolicies["removed"] = &cilium.NetworkPolicy{EndpointId: 3}
	state := &nodeState{resources: newCacheResources(resources, 1)}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changedPolicy := &cilium.NetworkPolicy{EndpointId: 4}
	addedPolicy := &cilium.NetworkPolicy{EndpointId: 5}
	mutations := ResourceMutations{
		Removed: xds.Resources{
			NetworkPolicies: map[string]*cilium.NetworkPolicy{"removed": nil},
		},
		Upserted: xds.Resources{
			NetworkPolicies: map[string]*cilium.NetworkPolicy{
				"changed": changedPolicy,
				"added":   addedPolicy,
			},
		},
	}
	changes, changedTypeURLs, _ := state.prepareResourceMutation(mutations)
	state.commitResourceMutation(changes, 2, nil)

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)

	for typeURL := range typeurl.Indices() {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot[typeURL].resources.Items).Pointer(),
			"published resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot[typeurl.NetworkPolicy].versions).Pointer(),
		reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].versions).Pointer(),
	)
	require.Same(t,
		previousSnapshot[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
		nextSnapshot[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
	)
	require.Same(t, changedPolicy, nextSnapshot[typeurl.NetworkPolicy].resources.Items["changed"].Resource)
	require.Same(t, addedPolicy, nextSnapshot[typeurl.NetworkPolicy].resources.Items["added"].Resource)
	require.NotContains(t, nextSnapshot[typeurl.NetworkPolicy].resources.Items, "removed")
	require.Equal(t,
		previousSnapshot[typeurl.NetworkPolicy].versions["unchanged"],
		nextSnapshot[typeurl.NetworkPolicy].versions["unchanged"],
	)

	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.False(t, c.areDifferentSnapshots(next, fullyGenerated))
}

func TestGenerateSnapshotFromStateIncrementallyReusesPublishedMapAfterCoalescedABA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	resources := emptyResources()
	resources.NetworkPolicies["policy"] = policyA
	state := &nodeState{resources: newCacheResources(resources, 1)}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changes, _, _ := state.prepareResourceMutation(ResourceMutations{
		Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"policy": {EndpointId: 2},
		}},
	})
	state.commitResourceMutation(changes, 2, nil)
	changes, changedTypeURLs, _ := state.prepareResourceMutation(ResourceMutations{
		Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"policy": policyA,
		}},
	})
	state.commitResourceMutation(changes, 3, nil)
	require.Equal(t, 1, state.changed.networkPolicies.Len())
	require.True(t, state.changed.networkPolicies.Has("policy"))

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)
	require.Equal(t,
		reflect.ValueOf(previousSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Equal(t,
		reflect.ValueOf(previousSnapshot[typeurl.NetworkPolicy].versions).Pointer(),
		reflect.ValueOf(nextSnapshot[typeurl.NetworkPolicy].versions).Pointer(),
	)
	require.Equal(t, previousSnapshot.GetVersion(NetworkPolicyTypeURL), nextSnapshot.GetVersion(NetworkPolicyTypeURL))
}

func TestNodeStateUsesProtoEqualityAndTracksChangedNames(t *testing.T) {
	current := xds.NewResources()
	current.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	current.Routes["route"] = &envoy_config_route.RouteConfiguration{Name: "route"}
	current.Clusters["cluster"] = &envoy_config_cluster.Cluster{Name: "cluster"}
	current.Endpoints["endpoint"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}
	current.Secrets["secret"] = &envoy_config_tls.Secret{Name: "secret"}
	current.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
	current.NetworkPolicyHosts["hosts"] = &cilium.NetworkPolicyHosts{}
	current.PortAllocationCallbacks["listener"] = func(context.Context) error { return nil }

	equal := xds.NewResources()
	equal.Listeners["listener"] = proto.Clone(current.Listeners["listener"]).(*envoy_config_listener.Listener)
	equal.Routes["route"] = proto.Clone(current.Routes["route"]).(*envoy_config_route.RouteConfiguration)
	equal.Clusters["cluster"] = proto.Clone(current.Clusters["cluster"]).(*envoy_config_cluster.Cluster)
	equal.Endpoints["endpoint"] = proto.Clone(current.Endpoints["endpoint"]).(*envoy_config_endpoint.ClusterLoadAssignment)
	equal.Secrets["secret"] = proto.Clone(current.Secrets["secret"]).(*envoy_config_tls.Secret)
	equal.NetworkPolicies["policy"] = proto.Clone(current.NetworkPolicies["policy"]).(*cilium.NetworkPolicy)
	equal.NetworkPolicyHosts["hosts"] = proto.Clone(current.NetworkPolicyHosts["hosts"]).(*cilium.NetworkPolicyHosts)

	state := &nodeState{
		resources: newCacheResources(&current, 0),
	}
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(ResourceMutations{Upserted: equal})
	require.True(t, changedTypeURLs.Empty())
	require.True(t, cacheResourcesEmpty(inverse))
	require.True(t, resourceMutationsEmpty(changes))
	unchanged := state.materializeResources()
	require.Same(t, current.Listeners["listener"], unchanged.Listeners["listener"])
	require.Same(t, current.Routes["route"], unchanged.Routes["route"])
	require.Same(t, current.Clusters["cluster"], unchanged.Clusters["cluster"])
	require.Same(t, current.Endpoints["endpoint"], unchanged.Endpoints["endpoint"])
	require.Same(t, current.Secrets["secret"], unchanged.Secrets["secret"])
	require.Same(t, current.NetworkPolicies["policy"], unchanged.NetworkPolicies["policy"])
	require.Same(t, current.NetworkPolicyHosts["hosts"], unchanged.NetworkPolicyHosts["hosts"])

	removed := xds.NewResources()
	removed.Listeners["listener"] = current.Listeners["listener"]
	removed.Clusters["cluster"] = current.Clusters["cluster"]
	upserted := xds.NewResources()
	upserted.Secrets["new-secret"] = &envoy_config_tls.Secret{Name: "new-secret"}
	upserted.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 2}

	changes, changedTypeURLs, inverse = state.prepareResourceMutation(ResourceMutations{Removed: removed, Upserted: upserted})
	state.commitResourceMutation(changes, 1, nil)
	updated := state.materializeResources()
	require.Equal(t, typeurl.NewSet(
		typeurl.Listener,
		typeurl.Cluster,
		typeurl.Secret,
		typeurl.NetworkPolicy,
	), changedTypeURLs)
	require.Equal(t, 1, state.changed.listeners.Len())
	require.True(t, state.changed.listeners.Has("listener"))
	require.Equal(t, 1, state.changed.clusters.Len())
	require.True(t, state.changed.clusters.Has("cluster"))
	require.Equal(t, 1, state.changed.secrets.Len())
	require.True(t, state.changed.secrets.Has("new-secret"))
	require.Equal(t, 1, state.changed.networkPolicies.Len())
	require.True(t, state.changed.networkPolicies.Has("policy"))
	require.Empty(t, state.changed.routes)
	require.Empty(t, state.changed.endpoints)
	require.Empty(t, state.changed.networkPolicyHosts)
	require.Equal(t, current.Listeners["listener"], inverse.listeners["listener"].resource)
	require.Equal(t, current.Clusters["cluster"], inverse.clusters["cluster"].resource)
	require.Nil(t, inverse.secrets["new-secret"].resource)
	require.Equal(t, current.NetworkPolicies["policy"], inverse.networkPolicies["policy"].resource)
	require.Nil(t, updated.Listeners)
	require.Nil(t, updated.Clusters)
	require.NotContains(t, updated.Listeners, "listener")
	require.NotContains(t, updated.Clusters, "cluster")
	require.Contains(t, updated.Secrets, "secret")
	require.Contains(t, updated.Secrets, "new-secret")
	require.Equal(t, uint64(2), updated.NetworkPolicies["policy"].GetEndpointId())

	// The previously published generation remains immutable.
	require.Contains(t, current.Listeners, "listener")
	require.Contains(t, current.Clusters, "cluster")
	require.NotContains(t, current.Secrets, "new-secret")
	require.Equal(t, uint64(1), current.NetworkPolicies["policy"].GetEndpointId())
}

func TestGenerateSnapshotIncrementallyUsesContentVersions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resourcesA := emptyResources()
	resourcesA.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}

	snapshotA, err := c.generateSnapshot(resourcesA, logger)
	require.NoError(t, err)

	resourcesB := *resourcesA
	resourcesB.NetworkPolicies = maps.Clone(resourcesA.NetworkPolicies)
	resourcesB.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 2}
	snapshotB, err := c.generateSnapshotIncrementally(
		&resourcesB,
		snapshotA,
		typeurl.NewSet(typeurl.NetworkPolicy),
		logger,
	)
	require.NoError(t, err)
	require.NotEqual(t, snapshotA.GetVersion(NetworkPolicyTypeURL), snapshotB.GetVersion(NetworkPolicyTypeURL))

	snapshotAAgain, err := c.generateSnapshotIncrementally(
		resourcesA,
		snapshotB,
		typeurl.NewSet(typeurl.NetworkPolicy),
		logger,
	)
	require.NoError(t, err)
	require.Equal(t, snapshotA.GetVersion(NetworkPolicyTypeURL), snapshotAAgain.GetVersion(NetworkPolicyTypeURL))
}

func TestGenerateSnapshotIncrementallyReturnsPreviousForKnownNoChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}

	previous, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	next, err := c.generateSnapshotIncrementally(resources, previous, typeurl.NewSet(), logger)
	require.NoError(t, err)
	require.Same(t, previous, next)
}

func TestGenerateSnapshotIncrementallyInvalidatesListenerDependencies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Routes["route1"] = &envoy_config_route.RouteConfiguration{Name: "route1"}
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{Name: "cluster1"}
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}

	previous, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	updated := *resources
	updated.Listeners = maps.Clone(resources.Listeners)
	updated.Listeners["listener1"] = &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			TransportSocket: &envoy_config_core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_tls.DownstreamTlsContext{
						CommonTlsContext: &envoy_config_tls.CommonTlsContext{
							TlsCertificateSdsSecretConfigs: []*envoy_config_tls.SdsSecretConfig{{Name: "secret1"}},
						},
					}),
				},
			},
			Filters: []*envoy_config_listener.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
							RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
								Rds: &envoy_config_http.Rds{RouteConfigName: "route1"},
							},
						}),
					},
				},
				{
					Name: "envoy.filters.network.tcp_proxy",
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: mustAny(t, &envoy_extensions_filters_network_tcp_proxy.TcpProxy{
							ClusterSpecifier: &envoy_extensions_filters_network_tcp_proxy.TcpProxy_Cluster{Cluster: "cluster1"},
						}),
					},
				},
			},
		}},
	}

	incremental, err := c.generateSnapshotIncrementally(
		&updated,
		previous,
		typeurl.NewSet(typeurl.Listener),
		logger,
	)
	require.NoError(t, err)
	fullyGenerated, err := c.generateSnapshot(&updated, logger)
	require.NoError(t, err)

	for typeURL := range typeurl.Indices() {
		require.Equal(t, fullyGenerated.GetVersion(typeURL.URL()), incremental.GetVersion(typeURL.URL()), typeURL.URL())
	}
	for _, typeURL := range []string{
		envoy_resource.ListenerType,
		envoy_resource.RouteType,
		envoy_resource.ClusterType,
		envoy_resource.SecretType,
	} {
		require.NotEqual(t, previous.GetVersion(typeURL), incremental.GetVersion(typeURL), typeURL)
	}
	require.Equal(t, previous.GetVersion(envoy_resource.EndpointType), incremental.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotIncrementallyInvalidatesClusterDependencies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Endpoints["backend"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"}
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{Name: "cluster1"}
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}

	previous, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)

	updated := *resources
	updated.Clusters = maps.Clone(resources.Clusters)
	updated.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
		TransportSocket: &envoy_config_core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: mustAny(t, &envoy_config_tls.UpstreamTlsContext{
					CommonTlsContext: &envoy_config_tls.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: []*envoy_config_tls.SdsSecretConfig{{Name: "secret1"}},
					},
				}),
			},
		},
	}

	incremental, err := c.generateSnapshotIncrementally(
		&updated,
		previous,
		typeurl.NewSet(typeurl.Cluster),
		logger,
	)
	require.NoError(t, err)
	fullyGenerated, err := c.generateSnapshot(&updated, logger)
	require.NoError(t, err)

	for typeURL := range typeurl.Indices() {
		require.Equal(t, fullyGenerated.GetVersion(typeURL.URL()), incremental.GetVersion(typeURL.URL()), typeURL.URL())
	}
	for _, typeURL := range []string{
		envoy_resource.ClusterType,
		envoy_resource.EndpointType,
		envoy_resource.SecretType,
	} {
		require.NotEqual(t, previous.GetVersion(typeURL), incremental.GetVersion(typeURL), typeURL)
	}
	require.Equal(t, previous.GetVersion(envoy_resource.ListenerType), incremental.GetVersion(envoy_resource.ListenerType))
}

func TestCheckSnapshotConsistency(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	}
	resources.Endpoints["cluster1"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}

	snap, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))
}

func TestCheckSnapshotConsistencyRejectsMissingEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: *envoy_config_cluster.Cluster_EDS.Enum(),
		},
	}

	snap, err := c.generateSnapshot(resources, logger)
	require.NoError(t, err)
	generatedSnapshot, ok := snap.(*ciliumSnapshot)
	require.True(t, ok)
	generatedSnapshot[typeurl.Endpoint].resources = cache.Resources{Version: "missing-endpoints"}

	require.ErrorContains(t, CheckSnapshotConsistency(snap), envoy_resource.EndpointType)
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
	resources := emptyResources()
	resources.Listeners["test-listener"] = &envoy_config_listener.Listener{Name: "test-listener"}

	snap, err := c.generateSnapshot(resources, c.logger)
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

	resources := emptyResources()
	snap, err := c.generateSnapshot(resources, c.logger)
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

func TestSetResources(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	resources := emptyResources()
	resources.Listeners["listener1"] = &envoy_config_listener.Listener{Name: "listener1"}

	c.setResources("node1", resources)

	storedListeners := maps.Collect(c.Listeners("node1"))
	assert.Contains(t, storedListeners, "listener1")
}

func TestSetResources_OverwriteExisting(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	res1 := emptyResources()
	res1.Listeners["old-listener"] = &envoy_config_listener.Listener{Name: "old-listener"}
	c.setResources("node1", res1)
	storedListeners := maps.Collect(c.Listeners("node1"))
	assert.Len(t, storedListeners, 1)
	assert.Contains(t, storedListeners, "old-listener")

	res2 := emptyResources()
	res2.Listeners["new-listener"] = &envoy_config_listener.Listener{Name: "new-listener"}
	c.setResources("node1", res2)

	storedListeners = maps.Collect(c.Listeners("node1"))
	assert.Len(t, storedListeners, 1)
	assert.Contains(t, storedListeners, "new-listener")
}

func TestGetAllResources_ExistingNode(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{Name: "cluster1"}
	resources.Listeners["listener1"] = &envoy_config_listener.Listener{Name: "listener1"}
	resources.Routes["route1"] = &envoy_config_route.RouteConfiguration{Name: "route1"}
	resources.Routes["route2"] = &envoy_config_route.RouteConfiguration{Name: "route2"}
	resources.Endpoints["endpoint1"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint1"}
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}
	c.setResources("node1", resources)

	result := c.getAllResources("node1")
	require.NotNil(t, result)
	assert.Contains(t, result.Clusters, "cluster1")
	assert.Len(t, result.Clusters, 1)
	assert.Contains(t, result.Listeners, "listener1")
	assert.Contains(t, result.Routes, "route1")
	assert.Contains(t, result.Routes, "route2")
	assert.Len(t, result.Routes, 2)
	assert.Contains(t, result.Endpoints, "endpoint1")
	assert.Len(t, result.Endpoints, 1)
	assert.Contains(t, result.Secrets, "secret1")
	assert.Len(t, result.Secrets, 1)
	assert.Contains(t, result.NetworkPolicies, "np1")
	assert.Len(t, result.NetworkPolicies, 1)
}

func TestGetAllResources_NonExistingNode(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	result := c.getAllResources("nonexistent")
	assert.Nil(t, result)
}

func TestClearSnapshot(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	c.setResources("node1", resources)

	snap, _ := c.generateSnapshot(resources, c.logger)
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

	resources := emptyResources()
	resources.Endpoints["cluster1"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	}
	resources.Listeners["listener1"] = &envoy_config_listener.Listener{Name: "listener1"}
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}

	snap, err := c.generateSnapshot(resources, c.logger)
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

	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	}

	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	require.Contains(t, endpoints, "cluster1")

	cla, ok := endpoints["cluster1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Equal(t, "cluster1", cla.ClusterName)
	assert.Empty(t, cla.Endpoints)
	assert.Empty(t, resources.Endpoints)
}

func TestGenerateSnapshot_AddsEmptyClusterLoadAssignmentForEDSServiceName(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			ServiceName: "service1",
		},
	}

	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	require.Contains(t, endpoints, "service1")
	require.NotContains(t, endpoints, "cluster1")

	cla, ok := endpoints["service1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Equal(t, "service1", cla.ClusterName)
	assert.Empty(t, resources.Endpoints)
}

func TestGenerateSnapshot_DoesNotOverwriteExistingClusterLoadAssignment(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	existingCLA := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}
	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	}
	resources.Endpoints["cluster1"] = existingCLA

	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	endpoints := snap.GetResources(envoy_resource.EndpointType)
	cla, ok := endpoints["cluster1"].(*envoy_config_endpoint.ClusterLoadAssignment)
	require.True(t, ok)
	assert.Same(t, existingCLA, cla)
}

func TestGenerateSnapshot_DoesNotAddClusterLoadAssignmentForNonEDSCluster(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_STATIC},
	}

	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	require.NoError(t, CheckSnapshotConsistency(snap))
	assert.Empty(t, snap.GetResources(envoy_resource.EndpointType))
	assert.Empty(t, resources.Endpoints)
}

func TestUpdateSnapshot_StoresNetworkPoliciesWhenTypeChanged(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", 1, snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	policies := mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL)
	require.Contains(t, policies, "np1")
	assert.Equal(t, resources.NetworkPolicies["np1"], policies["np1"])
}

func TestUpdateSnapshot_ClearsNetworkPoliciesWhenTypeChangedToEmpty(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", 1, snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	assert.Empty(t, mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL))
}

func TestUpdateSnapshot_StoresNetworkPoliciesWithoutTypeChange(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	resources.NetworkPolicies["np1"] = policy
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", 1, snap, nil, nil)
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	policies := mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL)
	require.Contains(t, policies, "np1")
	assert.Equal(t, policy, policies["np1"])
}

func TestUpdateSnapshot_RegistersNetworkPolicyCompletionForPolicyChange(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}
	snap, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), "node1", 1, snap, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil})
	require.NoError(t, err)

	assert.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	c.completionCbs.CancelPendingCompletions(typeurl.NetworkPolicy)
}

func TestUpdateSnapshot_CompletesAlreadyAckedNetworkPolicyVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	_, snap := networkPolicySnapshot(t, c, 1)

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
	_, snap := listenerSnapshot(t, c, "listener1")

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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)
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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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

func TestUpdateSnapshot_EmptyPolicyGenerationCompletesPending(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	_, nonempty := networkPolicySnapshot(t, c, 1)
	empty, err := c.generateSnapshot(emptyResources(), c.logger)
	require.NoError(t, err)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 1, nonempty, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	// Envoy has nothing to subscribe to or ACK once NPDS becomes empty.
	require.NoError(t, c.UpdateSnapshot(context.Background(), nodeID, 2, empty, nil, nil))
	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateSnapshot_FailedUntrackedGenerationIsNotObserved(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	const nodeID = "node1"
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)

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
	_, snap := networkPolicySnapshot(t, c, 1)
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
	_, snapshot := listenerSnapshot(t, c, "listener")
	version := snapshot.GetVersion(envoy_resource.ListenerType)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	registered, immediate := c.registerGenerationCompletions(
		nodeID, snapshot, snapshot, wg, func() typeURLWaits {
			var waits typeURLWaits
			waits.Set(typeurl.Listener, generationWait{generation: 0})
			return waits
		}(), nil)
	require.Len(t, registered, 1)
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
	_, snap := networkPolicySnapshot(t, c, 1)
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
	_, acceptedSnapshot := networkPolicySnapshot(t, c, 1)
	_, rejectedSnapshot := networkPolicySnapshot(t, c, 2)
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

// --- GetVersion ---

func TestGetVersion_DifferentResourcesProduceDifferentVersions(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l2"] = &envoy_config_listener.Listener{Name: "l2"}

	v1 := c.getVersion(res1)
	v2 := c.getVersion(res2)

	assert.NotEmpty(t, v1)
	assert.NotEmpty(t, v2)
	assert.NotEqual(t, v1, v2)
}

func TestGetVersion_SameResourcesProduceSameVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	v1 := c.getVersion(res1)
	v2 := c.getVersion(res2)

	assert.Equal(t, v1, v2)
}

// --- AreDifferentSnapshots ---

func TestAreDifferentSnapshots_Identical(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	snap1, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	snap2, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)

	assert.False(t, c.areDifferentSnapshots(snap1, snap2))
}

func TestAreDifferentSnapshots_Different(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l2"] = &envoy_config_listener.Listener{Name: "l2"}

	snap1, err := c.generateSnapshot(res1, c.logger)
	require.NoError(t, err)
	snap2, err := c.generateSnapshot(res2, c.logger)
	require.NoError(t, err)

	assert.True(t, c.areDifferentSnapshots(snap1, snap2))
}

// --- CreateWatch ---

func testSnapshotGenerator(c *cacheImpl, generated *int) legacySnapshotGenerator {
	return func(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}) (cache.ResourceSnapshot, error) {
		(*generated)++
		return c.generateSnapshotFromStateIncrementally(state, previous, indexedTypeURLs(changedTypeURLs))
	}
}

func mustSnapshot(t *testing.T, c *cacheImpl, nodeID string) cache.ResourceSnapshot {
	t.Helper()
	snapshot, err := c.SnapshotCache.GetSnapshot(nodeID)
	require.NoError(t, err)
	return snapshot
}

func TestUpdateResourcesFinalizesLatestGenerationOnCreateWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	generated := 0
	generator := testSnapshotGenerator(c, &generated)
	changed := map[string]struct{}{NetworkPolicyTypeURL: {}}

	resourcesA := emptyResources()
	resourcesA.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.updateResources(t.Context(), "node1", 1, resourcesA, changed, generator, nil, nil))
	resourcesB := emptyResources()
	resourcesB.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 2}
	require.NoError(t, c.updateResources(t.Context(), "node1", 2, resourcesB, changed, generator, nil, nil))

	require.Zero(t, generated)
	_, err := c.SnapshotCache.GetSnapshot("node1")
	require.Error(t, err)
	require.Equal(t, resourcesB.NetworkPolicies, maps.Collect(c.NetworkPolicies("node1")))

	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	var response cache.Response
	select {
	case response = <-responses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for finalized snapshot")
	}
	require.Equal(t, 1, generated)
	require.Equal(t, response.GetResponseVersion(), mustSnapshot(t, c, "node1").GetVersion(NetworkPolicyTypeURL))
	policy := mustSnapshot(t, c, "node1").GetResources(NetworkPolicyTypeURL)["policy"].(*cilium.NetworkPolicy)
	require.Equal(t, uint64(2), policy.EndpointId)
}

func TestApplyResourcesKeepsChangedNamesUntilFinalization(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	originalGenerator := c.defaultGenerator
	generated := 0
	c.defaultGenerator = func(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
		generated++
		return originalGenerator(state, previous, changedTypeURLs)
	}

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	updated, _, _, err := c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{"policy": policyA}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	require.Zero(t, generated)
	state := c.nodeStates["node1"]
	require.Same(t, policyA, state.resources.networkPolicies["policy"].resource)
	resourceMap := reflect.ValueOf(state.resources.networkPolicies).Pointer()
	require.Equal(t, 1, state.changed.networkPolicies.Len())
	require.True(t, state.changed.networkPolicies.Has("policy"))

	policyB := &cilium.NetworkPolicy{EndpointId: 2}
	updated, _, _, err = c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{"policy": policyB}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	require.Zero(t, generated)
	require.Equal(t, resourceMap, reflect.ValueOf(state.resources.networkPolicies).Pointer())
	require.Equal(t, 1, state.changed.networkPolicies.Len())
	require.True(t, state.changed.networkPolicies.Has("policy"))
	require.Equal(t, uint64(2), state.resourceGeneration)
	require.Zero(t, state.snapshotGeneration)
	require.NotNil(t, state.staged)
	resource, exists := c.GetResource("node1", typeurl.NetworkPolicy, "policy")
	require.True(t, exists)
	require.Same(t, policyB, resource)

	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	response := <-responses
	require.NotEmpty(t, response.GetResponseVersion())
	require.Equal(t, 1, generated, "all staged updates must be hashed by one finalization")
	require.Equal(t, state.resourceGeneration, state.snapshotGeneration)
	require.Nil(t, state.staged)
	require.Same(t, policyB, state.resources.networkPolicies["policy"].resource)
	require.Empty(t, state.changed.networkPolicies)
}

func TestListenerObserverReceivesCommittedTransitions(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	var observed []map[string]ListenerChange
	unlockedCalls := 0
	notifyAfterUnlock := true
	c.SetListenerObserver("node1", func(changes []ListenerChange) bool {
		byName := make(map[string]ListenerChange, len(changes))
		for _, change := range changes {
			byName[change.Name] = change
		}
		observed = append(observed, byName)
		return notifyAfterUnlock
	}, func() {
		// Reading from the cache here also verifies that this callback runs after
		// the transaction has released the cache lock.
		_, _ = c.GetResource("node1", typeurl.Listener, "listener-a")
		unlockedCalls++
	})

	listenerA := &envoy_config_listener.Listener{Name: "listener-a"}
	listenerB := &envoy_config_listener.Listener{Name: "listener-b"}
	updated, _, finalize, err := c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: listenerA,
			listenerB.Name: listenerB,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	finalize()
	require.Len(t, observed, 1)
	require.Equal(t, ListenerChange{Name: listenerA.Name, Current: listenerA}, observed[0][listenerA.Name])
	require.Equal(t, ListenerChange{Name: listenerB.Name, Current: listenerB}, observed[0][listenerB.Name])
	require.Equal(t, 1, unlockedCalls)

	listenerB2 := &envoy_config_listener.Listener{Name: listenerB.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND}
	updated, revert, _, err := c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Removed: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: nil,
		}},
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerB2.Name: listenerB2,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	require.Len(t, observed, 2)
	require.Equal(t, ListenerChange{Name: listenerA.Name, Previous: listenerA}, observed[1][listenerA.Name])
	require.Equal(t, ListenerChange{Name: listenerB.Name, Previous: listenerB, Current: listenerB2}, observed[1][listenerB.Name])
	require.Equal(t, 2, unlockedCalls)

	_, reverted := revert(0)
	require.True(t, reverted)
	require.Len(t, observed, 3)
	require.Equal(t, ListenerChange{Name: listenerA.Name, Current: listenerA}, observed[2][listenerA.Name])
	require.Equal(t, ListenerChange{Name: listenerB.Name, Previous: listenerB2, Current: listenerB}, observed[2][listenerB.Name])
	require.Equal(t, 3, unlockedCalls)

	updated, _, _, err = c.UpsertListener(t.Context(), "node1", listenerB.Name, proto.Clone(listenerB).(*envoy_config_listener.Listener), nil, nil)
	require.NoError(t, err)
	require.False(t, updated)
	require.Len(t, observed, 3, "semantic no-ops must not notify observers")

	notifyAfterUnlock = false
	listenerC := &envoy_config_listener.Listener{Name: "listener-c"}
	updated, _, finalize, err = c.UpsertListener(t.Context(), "node1", listenerC.Name, listenerC, nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	finalize()
	require.Len(t, observed, 4, "typed updates must notify the matching observer")
	require.Equal(t, ListenerChange{Name: listenerC.Name, Current: listenerC}, observed[3][listenerC.Name])
	require.Equal(t, 3, unlockedCalls, "the locked callback controls the unlocked follow-up")
}

func TestApplyResourcesCoalescesStagedRollbackState(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	const updates = 1000

	for endpointID := uint64(1); endpointID <= updates; endpointID++ {
		updated, _, finalize, err := c.UpsertNetworkPolicy(
			t.Context(), "node1", "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)
		require.NoError(t, err)
		require.True(t, updated)
		require.NotNil(t, finalize)
		finalize()
	}

	state := c.nodeStates["node1"]
	require.NotNil(t, state)
	require.NotNil(t, state.staged)
	require.Equal(t, 1, state.staged.rollbacks.Len())
	policyRollback, exists := state.staged.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.Len(t, policyRollback.networkPolicies, 1,
		"staging must retain one inverse per changed resource, not one per update")
	require.True(t, state.rollbackOwners.Empty(), "non-removal updates need no tombstone ownership")
}

func TestFirstUntrackedSnapshotNACKRevertsColdStartResources(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const streamID int64 = 1
	require.NoError(t, c.completionCbs.OnStreamOpen(ctx, streamID, ""))
	t.Cleanup(func() { c.completionCbs.OnStreamClosed(streamID, nil) })

	// Initial endpoint policies are populated before Envoy connects and do not
	// have WaitGroups. Caller finalization must leave the coalesced response
	// rollback intact so the first response can still be NACKed safely.
	for id := uint64(1); id <= 2; id++ {
		name := strconv.FormatUint(id, 10)
		updated, _, finalize, err := c.UpsertNetworkPolicy(
			ctx, "node1", name, &cilium.NetworkPolicy{EndpointId: id}, nil, nil)
		require.NoError(t, err)
		require.True(t, updated)
		require.NotNil(t, finalize)
		finalize()
	}

	state := c.nodeStates["node1"]
	require.NotNil(t, state.staged)
	policyRollback, exists := state.staged.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	coldStartRollback := policyRollback.networkPolicies
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
	c.completionCbs.OnStreamResponse(response.GetContext(), streamID, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, &discovery.DiscoveryRequest{
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
		_, _, finalize, err := c.UpsertNetworkPolicy(
			t.Context(), "node1", name, &cilium.NetworkPolicy{EndpointId: uint64(id)}, nil, nil)
		require.NoError(t, err)
		finalize()
	}
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(t.Context(), "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
	initial := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	for id := range resources {
		name := strconv.Itoa(id)
		_, _, finalize, err := c.RemoveNetworkPolicy(t.Context(), "node1", name, nil, nil)
		require.NoError(t, err)
		finalize()
	}
	c.mutex.Lock()
	_, finalized, err = c.finalizeStagedSnapshotLocked(t.Context(), "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
	removed := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", removed.GetVersion(NetworkPolicyTypeURL))

	state := c.nodeStates["node1"]
	require.Empty(t, state.resources.networkPolicies,
		"finalized removals must not leave generation tombstones behind")
	require.True(t, state.rollbackOwners.Empty())
}

func TestAcceptedRemovalReleasesResponseTombstone(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	_, _, finalize, err := c.UpsertNetworkPolicy(
		ctx, "node1", "policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	finalize()
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(ctx, "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
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
	_, _, finalize, err = c.RemoveNetworkPolicy(ctx, "node1", "policy", wg, nil)
	require.NoError(t, err)
	finalize()
	tombstone := c.nodeStates["node1"].resources.networkPolicies["policy"]
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
	require.Empty(t, c.nodeStates["node1"].resources.networkPolicies)
	require.True(t, c.nodeStates["node1"].rollbackOwners.Empty())
}

func TestNACKedRemovalRestoresResourceAfterCallerCompletion(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	_, _, finalize, err := c.UpsertNetworkPolicy(ctx, "node1", "policy", policy, nil, nil)
	require.NoError(t, err)
	finalize()
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(ctx, "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
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
	_, _, finalize, err = c.RemoveNetworkPolicy(ctx, "node1", "policy", wg, nil)
	require.NoError(t, err)
	require.NoError(t, wg.Wait(), "an empty policy state must not make callers wait for an ACK")
	finalize()
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
	require.Same(t, policy, c.nodeStates["node1"].resources.networkPolicies["policy"].resource,
		"completing the caller early must not make a sent removal irreversible")
}

func TestNACKRevertsAfterWaitCancellationAndCallerFinalize(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	_, _, finalize, err := c.UpsertNetworkPolicy(ctx, "node1", "policy", policyA, nil, nil)
	require.NoError(t, err)
	finalize()
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(ctx, "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
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
	updated, _, finalize, err := c.UpsertNetworkPolicy(ctx, "node1", "policy", policyB, wg, nil)
	require.NoError(t, err)
	require.True(t, updated)
	response := <-responses

	const nonce = "timed-out-response"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     NetworkPolicyTypeURL,
		Nonce:       nonce,
	})
	cancelWait()
	require.ErrorIs(t, wg.Wait(), context.Canceled)
	finalize()
	require.Same(t, policyB, c.nodeStates["node1"].resources.networkPolicies["policy"].resource)

	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   initialVersion,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected after timeout"},
	}))
	require.Same(t, policyA, c.nodeStates["node1"].resources.networkPolicies["policy"].resource,
		"caller timeout and finalization must not disable the response-owned NACK revert")
}

func TestResourceUpdateTerminalOperationsAreNoOpAfterFirstCall(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	_, _, initialFinalize, err := c.UpsertNetworkPolicy(
		t.Context(), "node1", "policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	initialFinalize()

	_, revertFunc, finalizeFunc, err := c.UpsertNetworkPolicy(
		t.Context(), "node1", "policy", &cilium.NetworkPolicy{EndpointId: 2}, nil, nil)
	require.NoError(t, err)
	finalizeFunc()
	_, reverted := revertFunc(0)
	require.False(t, reverted)
	finalizeFunc()
	require.Equal(t, uint64(2), c.nodeStates["node1"].resources.networkPolicies["policy"].resource.EndpointId)
}

func TestApplyResourcesOwnsGlobalGenerationAndPerNodeReverts(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	policy := func(endpointID uint64) ResourceMutations {
		return ResourceMutations{Upserted: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"policy": {EndpointId: endpointID},
		}}}
	}
	apply := func(nodeID string, endpointID uint64) RevertFunc {
		t.Helper()
		updated, revertFunc, _, err := c.ApplyResources(t.Context(), nodeID, policy(endpointID), nil, TypeURLCallbacks{})
		require.NoError(t, err)
		require.True(t, updated)
		return revertFunc
	}

	apply("node-a", 1)                // global generation 1
	apply("node-b", 1)                // global generation 2
	revertNodeA := apply("node-a", 2) // global generation 3
	apply("node-b", 2)                // global generation 4
	require.Equal(t, uint64(4), c.resourceGeneration)
	require.Equal(t, uint64(3), c.nodeStates["node-a"].resourceGeneration)
	require.Equal(t, uint64(4), c.nodeStates["node-b"].resourceGeneration)

	generation, reverted := revertNodeA(0)
	require.True(t, reverted)
	require.Equal(t, uint64(5), generation)
	require.Equal(t, generation, c.resourceGeneration)
	require.Equal(t, generation, c.nodeStates["node-a"].resourceGeneration)
	require.Equal(t, uint64(4), c.nodeStates["node-b"].resourceGeneration)
	resource, exists := c.GetResource("node-a", typeurl.NetworkPolicy, "policy")
	require.True(t, exists)
	require.Equal(t, uint64(1), resource.(*cilium.NetworkPolicy).EndpointId)
}

func TestApplyResourcesRevertOnlyRestoresOwnedResourceVersions(t *testing.T) {
	newCache := func(t *testing.T) *cacheImpl {
		t.Helper()
		return NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	}
	policies := func(values map[string]uint64) ResourceMutations {
		resources := make(map[string]*cilium.NetworkPolicy, len(values))
		for name, endpointID := range values {
			resources[name] = &cilium.NetworkPolicy{EndpointId: endpointID}
		}
		return ResourceMutations{Upserted: xds.Resources{NetworkPolicies: resources}}
	}
	apply := func(t *testing.T, c *cacheImpl, mutations ResourceMutations) RevertFunc {
		t.Helper()
		updated, revertFunc, _, err := c.ApplyResources(t.Context(), "node-a", mutations, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		require.True(t, updated)
		require.NotNil(t, revertFunc)
		return revertFunc
	}

	for _, tt := range []struct {
		name               string
		expectedGeneration uint64
	}{
		{name: "NACK-driven", expectedGeneration: 2},
		{name: "caller-driven", expectedGeneration: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(t)
			apply(t, c, policies(map[string]uint64{"newer": 1, "unchanged": 1}))
			revert := apply(t, c, policies(map[string]uint64{"newer": 2, "unchanged": 2}))
			apply(t, c, policies(map[string]uint64{"newer": 3}))

			_, reverted := revert(tt.expectedGeneration)
			require.True(t, reverted)
			resources := maps.Collect(c.NetworkPolicies("node-a"))
			require.Equal(t, uint64(3), resources["newer"].EndpointId,
				"a revert must not overwrite a resource changed by a newer generation")
			require.Equal(t, uint64(1), resources["unchanged"].EndpointId,
				"the same revert must still restore resources untouched by newer generations")
		})
	}

	t.Run("removed resource ABA", func(t *testing.T) {
		c := newCache(t)
		apply(t, c, policies(map[string]uint64{"newer": 1, "unchanged": 1}))
		removed := xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"newer": nil, "unchanged": nil,
		}}
		revert := apply(t, c, ResourceMutations{Removed: removed})
		apply(t, c, policies(map[string]uint64{"newer": 3}))
		apply(t, c, ResourceMutations{Removed: xds.Resources{NetworkPolicies: map[string]*cilium.NetworkPolicy{"newer": nil}}})

		_, reverted := revert(2)
		require.True(t, reverted)
		resources := maps.Collect(c.NetworkPolicies("node-a"))
		require.NotContains(t, resources, "newer",
			"a newer removal must not be mistaken for the removal being reverted")
		require.Equal(t, uint64(1), resources["unchanged"].EndpointId)
	})
}

func TestApplyResourcesRevertGenerationCoversEveryResourceType(t *testing.T) {
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
			resources.NetworkPolicies[name] = &cilium.NetworkPolicy{EndpointId: version}
			resources.NetworkPolicyHosts[name] = &cilium.NetworkPolicyHosts{Policy: version}
		}
		return resources
	}
	apply := func(resources xds.Resources) RevertFunc {
		t.Helper()
		updated, revertFunc, _, err := c.ApplyResources(t.Context(), "node-a", ResourceMutations{Upserted: resources}, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		require.True(t, updated)
		return revertFunc
	}

	baseline := resources(1, "newer", "unchanged")
	apply(baseline)
	revert := apply(resources(2, "newer", "unchanged"))
	newer := resources(3, "newer")
	apply(newer)

	_, reverted := revert(2)
	require.True(t, reverted)
	current := c.getAllResources("node-a")
	require.Same(t, newer.Listeners["newer"], current.Listeners["newer"])
	require.Same(t, baseline.Listeners["unchanged"], current.Listeners["unchanged"])
	require.Same(t, newer.Routes["newer"], current.Routes["newer"])
	require.Same(t, baseline.Routes["unchanged"], current.Routes["unchanged"])
	require.Same(t, newer.Clusters["newer"], current.Clusters["newer"])
	require.Same(t, baseline.Clusters["unchanged"], current.Clusters["unchanged"])
	require.Same(t, newer.Endpoints["newer"], current.Endpoints["newer"])
	require.Same(t, baseline.Endpoints["unchanged"], current.Endpoints["unchanged"])
	require.Same(t, newer.Secrets["newer"], current.Secrets["newer"])
	require.Same(t, baseline.Secrets["unchanged"], current.Secrets["unchanged"])
	require.Same(t, newer.NetworkPolicies["newer"], current.NetworkPolicies["newer"])
	require.Same(t, baseline.NetworkPolicies["unchanged"], current.NetworkPolicies["unchanged"])
	require.Same(t, newer.NetworkPolicyHosts["newer"], current.NetworkPolicyHosts["newer"])
	require.Same(t, baseline.NetworkPolicyHosts["unchanged"], current.NetworkPolicyHosts["unchanged"])
}

func TestUpdateResourcesFinalizesOncePerAvailableWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	generated := 0
	generator := testSnapshotGenerator(c, &generated)
	changed := map[string]struct{}{NetworkPolicyTypeURL: {}}
	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	subscription := stream.NewSotwSubscription(nil, false)
	responses := make(chan cache.Response, 1)

	resourcesA := emptyResources()
	resourcesA.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.updateResources(t.Context(), "node1", 1, resourcesA, changed, generator, nil, nil))
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	responseA := <-responses
	subscription.SetReturnedResources(responseA.GetReturnedResources())
	cancel()
	require.Equal(t, 1, generated)

	request.VersionInfo = responseA.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	resourcesB := emptyResources()
	resourcesB.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 2}
	require.NoError(t, c.updateResources(t.Context(), "node1", 2, resourcesB, changed, generator, nil, nil))
	responseB := <-responses
	subscription.SetReturnedResources(responseB.GetReturnedResources())
	require.Equal(t, 2, generated)

	// The B response consumed the only NPDS watch. C remains staged while the
	// simulated client processes B, even though its response channel is empty.
	resourcesC := emptyResources()
	resourcesC.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 3}
	require.NoError(t, c.updateResources(t.Context(), "node1", 3, resourcesC, changed, generator, nil, nil))
	require.Equal(t, 2, generated)

	request.VersionInfo = responseB.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	responseC := <-responses
	require.Equal(t, 3, generated)
	require.NotEqual(t, responseB.GetResponseVersion(), responseC.GetResponseVersion())
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
	upserted := &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"listener": listener}}
	wg1 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg1.Cancel)
	updated, _, listenerFinalize, err := c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: *upserted}, wg1, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)

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
	updated, _, finalize, err := c.UpsertNetworkPolicy(ctx, node.GetId(), "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	finalize()
	policyResponse := <-policyResponses
	policySubscription.SetReturnedResources(policyResponse.GetReturnedResources())
	require.Greater(t, c.nodeStates[node.GetId()].snapshotGeneration,
		c.nodeStates[node.GetId()].resources.listeners[listener.GetName()].generation)

	// The response has left the cache, but deliberately delay OnStreamResponse.
	// A semantic no-op for the same listener must attach to that response while
	// it is in the handoff window, even though an unrelated resource type has
	// advanced the node-wide generation in the meantime.
	wg2 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg2.Cancel)
	equalUpsert := &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener": proto.Clone(listener).(*envoy_config_listener.Listener),
	}}
	updated, revertFunc, _, err := c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: *equalUpsert}, wg2, TypeURLCallbacks{})
	require.NoError(t, err)
	require.False(t, updated)
	require.Nil(t, revertFunc)
	typedWG := completion.NewWaitGroup(ctx)
	t.Cleanup(typedWG.Cancel)
	updated, revertFunc, _, err = c.UpsertListener(ctx, node.GetId(), listener.GetName(),
		proto.Clone(listener).(*envoy_config_listener.Listener), typedWG, nil)
	require.NoError(t, err)
	require.False(t, updated)
	require.Nil(t, revertFunc)
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
	listenerFinalize()
	require.NoError(t, wg2.Wait())
	require.NoError(t, typedWG.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestUpdateResourcesIgnoresUnrelatedOpenWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	generated := 0
	generator := testSnapshotGenerator(c, &generated)
	node := &envoy_config_core.Node{Id: "node1"}

	resourcesA := emptyResources()
	resourcesA.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.updateResources(t.Context(), "node1", 1, resourcesA,
		map[string]struct{}{NetworkPolicyTypeURL: {}}, generator, nil, nil))
	npResponses := make(chan cache.Response, 1)
	_, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: NetworkPolicyTypeURL},
		stream.NewSotwSubscription(nil, false), npResponses)
	require.NoError(t, err)
	<-npResponses
	require.Equal(t, 1, generated)

	listenerVersion := mustSnapshot(t, c, "node1").GetVersion(envoy_resource.ListenerType)
	listenerResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: listenerVersion,
	}, stream.NewSotwSubscription(nil, false), listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	resourcesB := emptyResources()
	resourcesB.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 2}
	require.NoError(t, c.updateResources(t.Context(), "node1", 2, resourcesB,
		map[string]struct{}{NetworkPolicyTypeURL: {}}, generator, nil, nil))
	require.Equal(t, 1, generated)
}

func TestListenerMutationWaitsForListenerWatchAndReleasesUnchangedDependencies(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, false)

	listener := &envoy_config_listener.Listener{Name: "listener"}
	updated, _, finalize, err := c.UpsertListener(ctx, node.GetId(), listener.GetName(), listener, nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	finalize()

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
	// not change the RDS version. It must not make the cache believe Envoy can
	// consume a new listener snapshot.
	routeResponses := make(chan cache.Response, 1)
	cancelRoute, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.RouteType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.RouteType),
	}, subscription, routeResponses)
	require.NoError(t, err)
	t.Cleanup(cancelRoute)
	initialGeneration := c.nodeStates[node.GetId()].snapshotGeneration

	updated, _, finalize, err = c.RemoveListener(ctx, node.GetId(), listener.GetName(), nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	finalize()
	require.Equal(t, initialGeneration, c.nodeStates[node.GetId()].snapshotGeneration)
	require.NotNil(t, c.nodeStates[node.GetId()].staged)
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly consumed the listener update")
	default:
	}

	// A listener watch now consumes the staged removal. Only LDS has a changed
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
	require.Empty(t, state.resources.listeners,
		"an ACKed removal must not retain a tombstone for unchanged dependent types")
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly received the listener update")
	default:
	}
}

func TestPublishedUnsentRollbackCoalescesUntilResponse(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}

	baselineListener := &envoy_config_listener.Listener{Name: "listener-0"}
	baselinePolicy := &cilium.NetworkPolicy{EndpointId: 1}
	updated, _, finalize, err := c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners:       map[string]*envoy_config_listener.Listener{"listener": baselineListener},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{"policy": baselinePolicy},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	finalize()

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

		latestListener = &envoy_config_listener.Listener{Name: fmt.Sprintf("listener-%d", update)}
		mutations := ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			"listener": latestListener,
		}}}
		if update%2 == 0 {
			mutations.Upserted.NetworkPolicies = map[string]*cilium.NetworkPolicy{
				"policy": {EndpointId: update},
			}
		} else {
			mutations.Removed.NetworkPolicies = map[string]*cilium.NetworkPolicy{"policy": nil}
		}
		updated, _, finalize, err = c.ApplyResources(ctx, nodeID, mutations, nil, TypeURLCallbacks{})
		require.NoError(t, err)
		require.True(t, updated)
		finalize()
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
		require.Len(t, current.resources.networkPolicies, 1)
		require.Same(t, baselinePolicy, current.resources.networkPolicies["policy"].previous.resource)
		require.Empty(t, current.resources.listeners,
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

func TestUpdateResourcesCompletesCoalescedABAOnCreateWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	generated := 0
	generator := testSnapshotGenerator(c, &generated)
	changed := map[string]struct{}{NetworkPolicyTypeURL: {}}
	node := &envoy_config_core.Node{Id: "node1"}
	subscription := stream.NewSotwSubscription(nil, false)

	resourcesA := emptyResources()
	resourcesA.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.updateResources(t.Context(), "node1", 1, resourcesA,
		changed, generator, nil, nil))
	responses := make(chan cache.Response, 1)
	_, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: NetworkPolicyTypeURL}, subscription, responses)
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

	resourcesB := emptyResources()
	resourcesB.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 2}
	wgB := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgB.Cancel)
	require.NoError(t, c.updateResources(t.Context(), "node1", 2, resourcesB,
		changed, generator, wgB, map[string]func(error){NetworkPolicyTypeURL: nil}))
	wgA := completion.NewWaitGroup(t.Context())
	t.Cleanup(wgA.Cancel)
	require.NoError(t, c.updateResources(t.Context(), "node1", 3, resourcesA,
		changed, generator, wgA, map[string]func(error){NetworkPolicyTypeURL: nil}))
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
	require.Equal(t, 1, generated)

	// Finalization returns to the already ACKed contents. CreateWatch therefore
	// opens a watch without emitting another response, while both folded
	// generations complete successfully.
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: NetworkPolicyTypeURL, VersionInfo: responseA.GetResponseVersion(),
	}, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.Equal(t, 2, generated)
	select {
	case <-responses:
		t.Fatal("unexpected response for already accepted finalized contents")
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
	updated, _, _, err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Upserted: xds.Resources{
			NetworkPolicies: map[string]*cilium.NetworkPolicy{"policy": policy},
		},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
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
	require.Equal(t, 1, mock.createWatchCalls)
	require.NotContains(t, c.nodeStates, "node1")
	require.Empty(t, c.openWatches)
}

func TestRemoveNetworkPolicyFromUnknownNodeIsNoOp(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	callbackCalls := 0

	updated, revertFunc, finalizeFunc, err := c.RemoveNetworkPolicy(ctx, "unknown-node", "missing-policy", wg, func(err error) {
		require.NoError(t, err)
		callbackCalls++
	})
	require.NoError(t, err)
	require.False(t, updated)
	require.Nil(t, revertFunc)
	require.Nil(t, finalizeFunc)
	require.NoError(t, wg.Wait())
	require.Equal(t, 1, callbackCalls)
	require.NotContains(t, c.nodeStates, "unknown-node")
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

	updated, revertFunc, finalizeFunc, err := c.ApplyResources(ctx, "unknown-node", ResourceMutations{
		Removed: xds.Resources{
			Listeners:       map[string]*envoy_config_listener.Listener{"listener": nil},
			NetworkPolicies: map[string]*cilium.NetworkPolicy{"policy": nil},
		},
	}, wg, indexedTypeURLCallbacks(map[string]func(error){
		envoy_resource.ListenerType: callback,
		NetworkPolicyTypeURL:        callback,
	}))
	require.NoError(t, err)
	require.False(t, updated)
	require.Nil(t, revertFunc)
	require.Nil(t, finalizeFunc)
	require.NoError(t, wg.Wait())
	require.Equal(t, 2, callbackCalls)
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

func TestCreateWatch_IgnoresEmptySecretSubscription(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := NewCache(logger, false).(*cacheImpl)
	resources := emptyResources()
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}

	snap, err := c.generateSnapshot(resources, logger)
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

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	resources.Clusters["c1"] = &envoy_config_cluster.Cluster{Name: "c1"}

	snap, err := c.generateSnapshot(resources, c.logger)
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

// --- Integration-style: SetResources + GetAllResources ---

func TestSetAndGetAllResourcesRoundTrip(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	resources.Routes["r1"] = &envoy_config_route.RouteConfiguration{Name: "r1"}
	resources.Secrets["s1"] = &envoy_config_tls.Secret{Name: "s1"}

	c.setResources("node1", resources)

	result := c.getAllResources("node1")
	require.NotNil(t, result)
	assert.Contains(t, result.Listeners, "l1")
	assert.Contains(t, result.Routes, "r1")
	assert.Contains(t, result.Secrets, "s1")
}

// --- Integration-style: ClearSnapshot resets and delegates ---

func TestClearSnapshot_ResetsResourcesAndDelegates(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	c.setResources("node1", resources)

	snap, _ := c.generateSnapshot(resources, c.logger)
	_ = mock.SetSnapshot(context.Background(), "node1", snap)
	mock.setSnapshotCalls = nil

	c.ClearSnapshot("node1")

	// ClearSnapshot on the mock should have been called
	require.Len(t, mock.clearSnapshotCalls, 1)
	assert.Equal(t, "node1", mock.clearSnapshotCalls[0])

	// Resources should be reset to empty.
	_, exists := c.GetResource("node1", typeurl.Listener, "l1")
	require.False(t, exists)
}

// --- GenerateSnapshot versions are deterministic ---

func TestGenerateSnapshot_VersionIsDeterministic(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	resources.Clusters["c1"] = &envoy_config_cluster.Cluster{Name: "c1"}

	snap1, err := c.generateSnapshot(resources, c.logger)
	require.NoError(t, err)
	snap2, err := c.generateSnapshot(resources, c.logger)
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

	resources := emptyResources()
	resources.Listeners["l1"] = listener
	resources.Clusters["c1"] = cluster
	resources.Endpoints["c1"] = ep
	resources.Secrets["s1"] = secret

	snap, err := c.generateSnapshot(resources, c.logger)
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

// --- Verify no delegation to snapshotCache for local-only operations ---

func TestSetResources_DoesNotCallSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	resources := emptyResources()
	c.setResources("node1", resources)

	// SetResources should only update resourcesInSnapshot, not call the underlying snapshot cache
	assert.Empty(t, mock.setSnapshotCalls)
	assert.Empty(t, mock.getSnapshotCalls)
	assert.Empty(t, mock.clearSnapshotCalls)
}

func TestGetAllResources_DoesNotCallSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	_ = c.getAllResources("node1")

	assert.Empty(t, mock.setSnapshotCalls)
	assert.Empty(t, mock.getSnapshotCalls)
	assert.Empty(t, mock.clearSnapshotCalls)
}

func TestInitialListenerNACKSoftResetsOnlyLDS(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), true).(*cacheImpl)
	const streamID int64 = 11
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), streamID, ""))
	t.Cleanup(func() { c.completionCbs.OnStreamClosed(streamID, node) })

	initialListener := &envoy_config_listener.Listener{
		Name: "listener",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
						RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
							Rds: &envoy_config_http.Rds{RouteConfigName: "route"},
						},
					}),
				},
			}},
		}},
	}
	initialRoute := &envoy_config_route.RouteConfiguration{Name: "route"}
	initialPolicy := &cilium.NetworkPolicy{EndpointId: 1}
	initialPolicyHosts := &cilium.NetworkPolicyHosts{Policy: 1}
	updated, _, finalize, err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Upserted: xds.Resources{
			Listeners:          map[string]*envoy_config_listener.Listener{"listener": initialListener},
			Routes:             map[string]*envoy_config_route.RouteConfiguration{"route": initialRoute},
			NetworkPolicies:    map[string]*cilium.NetworkPolicy{"policy": initialPolicy},
			NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{"hosts": initialPolicyHosts},
		},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	finalize()

	responses := make(chan cache.Response, int(typeurl.Count)+1)
	listenerSubscription := stream.NewSotwSubscription(nil, false)
	policySubscription := stream.NewSotwSubscription(nil, false)
	policyHostsSubscription := stream.NewSotwSubscription(nil, false)

	listenerRequest := &cache.Request{
		Node:        node,
		TypeUrl:     envoy_resource.ListenerType,
		VersionInfo: "envoy-listener-before-agent-restart",
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, listenerRequest))
	listenerCancel, err := c.CreateWatch(listenerRequest, listenerSubscription, responses)
	require.NoError(t, err)
	initialListenerResponse := <-responses
	require.Equal(t, envoy_resource.ListenerType, initialListenerResponse.GetRequest().GetTypeUrl())
	listenerSubscription.SetReturnedResources(initialListenerResponse.GetReturnedResources())
	c.completionCbs.OnStreamResponse(initialListenerResponse.GetContext(), streamID,
		initialListenerResponse.GetRequest(), &discovery.DiscoveryResponse{
			VersionInfo: initialListenerResponse.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "initial-listener",
		})

	policyRequest := &cache.Request{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: "envoy-policy-before-agent-restart",
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, policyRequest))
	policyCancel, err := c.CreateWatch(policyRequest, policySubscription, responses)
	require.NoError(t, err)
	initialPolicyResponse := <-responses
	require.Equal(t, NetworkPolicyTypeURL, initialPolicyResponse.GetRequest().GetTypeUrl())
	policySubscription.SetReturnedResources(initialPolicyResponse.GetReturnedResources())
	c.completionCbs.OnStreamResponse(initialPolicyResponse.GetContext(), streamID,
		initialPolicyResponse.GetRequest(), &discovery.DiscoveryResponse{
			VersionInfo: initialPolicyResponse.GetResponseVersion(),
			TypeUrl:     NetworkPolicyTypeURL,
			Nonce:       "initial-policy",
		})
	publishedBeforeReset := mustSnapshot(t, c, nodeID)

	// The first NACK on this ADS stream requests a transport-only empty view.
	// It must not run the rollback attached to the desired Listener generation.
	listenerNACK := &cache.Request{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		VersionInfo:   listenerRequest.GetVersionInfo(),
		ResponseNonce: "initial-listener",
		ErrorDetail:   &status.Status{Message: "address already in use"},
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, listenerNACK))
	listenerCancel()
	listenerResetCancel, err := c.CreateWatch(listenerNACK, listenerSubscription, responses)
	require.NoError(t, err)
	c.mutex.RLock()
	resetWatchOpen := c.hasOpenWatchLocked(nodeID, typeurl.NewSet(typeurl.Listener))
	c.mutex.RUnlock()
	require.False(t, resetWatchOpen,
		"the synthetic reset response must not leave an open desired-state watch")
	emptyListenerResponse := <-responses
	require.Empty(t, emptyListenerResponse.GetReturnedResources())
	require.Equal(t, nodeID, emptyListenerResponse.GetRequest().GetNode().GetId())
	require.Same(t, initialListener, c.nodeStates[nodeID].resources.listeners["listener"].resource)
	require.Same(t, initialPolicy, c.nodeStates[nodeID].resources.networkPolicies["policy"].resource)
	require.Same(t, initialPolicyHosts, c.nodeStates[nodeID].resources.networkPolicyHosts["hosts"].resource)
	require.Same(t, publishedBeforeReset, mustSnapshot(t, c, nodeID))
	c.completionCbs.OnStreamResponse(emptyListenerResponse.GetContext(), streamID,
		emptyListenerResponse.GetRequest(), &discovery.DiscoveryResponse{
			VersionInfo: emptyListenerResponse.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "empty-listener",
		})

	// Desired state keeps changing while the stream is reset. The reset watch
	// must not be mistaken for Envoy capacity to consume a live snapshot.
	latestListener := proto.Clone(initialListener).(*envoy_config_listener.Listener)
	latestListener.TrafficDirection = envoy_config_core.TrafficDirection_OUTBOUND
	latestPolicy := &cilium.NetworkPolicy{EndpointId: 2}
	latestPolicyHosts := &cilium.NetworkPolicyHosts{Policy: 2}
	updated, _, finalize, err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Upserted: xds.Resources{
			Listeners:          map[string]*envoy_config_listener.Listener{"listener": latestListener},
			NetworkPolicies:    map[string]*cilium.NetworkPolicy{"policy": latestPolicy},
			NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{"hosts": latestPolicyHosts},
		},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.True(t, updated)
	finalize()
	require.Same(t, publishedBeforeReset, mustSnapshot(t, c, nodeID))
	require.NotNil(t, c.nodeStates[nodeID].staged)
	require.Same(t, latestListener, c.nodeStates[nodeID].resources.listeners["listener"].resource)
	require.Same(t, latestPolicy, c.nodeStates[nodeID].resources.networkPolicies["policy"].resource)
	require.Same(t, latestPolicyHosts, c.nodeStates[nodeID].resources.networkPolicyHosts["hosts"].resource)

	// NPDS remains on the authoritative cache throughout the LDS reset. Once
	// its earlier response is ACKed, its next watch immediately consumes the
	// newest policy instead of receiving an empty reset response. NPHDS, RDS,
	// CDS/EDS, and SDS follow the same non-LDS path.
	policyACK := &cache.Request{
		Node:          node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   initialPolicyResponse.GetResponseVersion(),
		ResponseNonce: "initial-policy",
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, policyACK))
	policyCancel()
	policyLiveCancel, err := c.CreateWatch(policyACK, policySubscription, responses)
	require.NoError(t, err)
	latestPolicyResponse := <-responses
	require.Equal(t, NetworkPolicyTypeURL, latestPolicyResponse.GetRequest().GetTypeUrl())
	require.Contains(t, latestPolicyResponse.GetReturnedResources(), "policy")
	require.Same(t, latestPolicy,
		mustSnapshot(t, c, nodeID).GetResources(NetworkPolicyTypeURL)["policy"])
	policySubscription.SetReturnedResources(latestPolicyResponse.GetReturnedResources())
	acknowledgeResponse(t, c, streamID, latestPolicyResponse, "latest-policy")
	policyLiveCancel()

	policyHostsRequest := &cache.Request{
		Node:        node,
		TypeUrl:     NetworkPolicyHostsTypeURL,
		VersionInfo: "envoy-policy-hosts-before-agent-restart",
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, policyHostsRequest))
	policyHostsCancel, err := c.CreateWatch(policyHostsRequest, policyHostsSubscription, responses)
	require.NoError(t, err)
	latestPolicyHostsResponse := <-responses
	require.Equal(t, NetworkPolicyHostsTypeURL, latestPolicyHostsResponse.GetRequest().GetTypeUrl())
	require.Contains(t, latestPolicyHostsResponse.GetReturnedResources(), "hosts")
	require.Same(t, latestPolicyHosts,
		mustSnapshot(t, c, nodeID).GetResources(NetworkPolicyHostsTypeURL)["hosts"])
	policyHostsSubscription.SetReturnedResources(latestPolicyHostsResponse.GetReturnedResources())
	acknowledgeResponse(t, c, streamID, latestPolicyHostsResponse, "latest-policy-hosts")
	policyHostsCancel()

	// ACKing the empty LDS view ends the type-local barrier. The next LDS watch
	// returns the latest Listener, while no other TypeURL is rebound or replayed.
	listenerResetACK := &cache.Request{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		VersionInfo:   emptyListenerResponse.GetResponseVersion(),
		ResponseNonce: "empty-listener",
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, listenerResetACK))
	listenerResetCancel()
	listenerReplayCancel, err := c.CreateWatch(listenerResetACK, listenerSubscription, responses)
	require.NoError(t, err)
	t.Cleanup(listenerReplayCancel)
	replayedListener := <-responses
	require.Equal(t, envoy_resource.ListenerType, replayedListener.GetRequest().GetTypeUrl())
	require.Same(t, latestListener,
		mustSnapshot(t, c, nodeID).GetResources(envoy_resource.ListenerType)["listener"])
	_, err = c.SnapshotCache.GetSnapshot(streamResetNodeID(streamID))
	require.Error(t, err)
	select {
	case response := <-responses:
		t.Fatalf("unexpected replay for non-LDS type %s", response.GetRequest().GetTypeUrl())
	default:
	}

	acknowledgeResponse(t, c, streamID, replayedListener, "replayed-listener")
	require.True(t, c.nodeStates[nodeID].rollbackOwners.Empty())
}

func TestStreamSoftResetSnapshotIsRemovedOnDisconnect(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	const streamID int64 = 12
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), streamID, ""))

	listener := &envoy_config_listener.Listener{Name: "listener"}
	updated, _, finalize, err := c.UpsertListener(t.Context(), nodeID, listener.GetName(), listener, nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	finalize()

	responses := make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, false)
	request := &cache.Request{Node: node, TypeUrl: envoy_resource.ListenerType}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, request))
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	response := <-responses
	c.completionCbs.OnStreamResponse(response.GetContext(), streamID, response.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: response.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "initial-listener",
		})

	nack := &cache.Request{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		ResponseNonce: "initial-listener",
		ErrorDetail:   &status.Status{Message: "rejected"},
	}
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, nack))
	cancel()
	resetCancel, err := c.CreateWatch(nack, subscription, responses)
	require.NoError(t, err)
	resetResponse := <-responses
	c.completionCbs.OnStreamResponse(resetResponse.GetContext(), streamID, resetResponse.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: resetResponse.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "empty-listener",
		})
	require.Error(t, c.completionCbs.OnStreamRequest(streamID, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		ResponseNonce: "empty-listener",
		ErrorDetail:   &status.Status{Message: "empty state rejected"},
	}))
	resetCancel()
	_, err = c.SnapshotCache.GetSnapshot(streamResetNodeID(streamID))
	require.NoError(t, err)

	c.completionCbs.OnStreamClosed(streamID, node)
	_, err = c.SnapshotCache.GetSnapshot(streamResetNodeID(streamID))
	require.Error(t, err)
	require.Same(t, listener, c.nodeStates[nodeID].resources.listeners[listener.GetName()].resource)
}
