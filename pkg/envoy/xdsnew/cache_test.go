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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
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

func (state *nodeState) seedResourceAtGeneration(typeURL typeurl.Index, name string, resource cache_types.Resource, generation uint64) {
	state.seedResource(typeURL, name, resource)
	entry := state.resources[typeURL].entries[name]
	entry.generation = generation
	state.resources[typeURL].entries[name] = entry
	state.resources[typeURL].generation = max(state.resources[typeURL].generation, generation)
}

// stageSnapshotTestResource models a resource mutation waiting for the next
// snapshot, so incremental generation can distinguish parent replacements.
func (state *nodeState) stageSnapshotTestResource(typeURL typeurl.Index, name string, resource cache_types.Resource) typeurl.Set {
	var changes resourceChanges
	generation := state.resourceGeneration + 1
	changes.add(typeURL, name, state.resources[typeURL].entries[name], resourceEntry{resource: resource, generation: generation})
	state.commitResourceMutation(changes, generation)
	state.resourceGeneration = generation
	state.staged = &stagedSnapshot{generation: generation}
	return changes.typeURLs()
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

// snapshotPublicationCounter counts publication attempts without adding a
// replaceable snapshot-construction callback to production cache state.
type snapshotPublicationCounter struct {
	cache.SnapshotCache
	publications int
}

func (counter *snapshotPublicationCounter) SetSnapshot(ctx context.Context, node string, snapshot cache.ResourceSnapshot) error {
	counter.publications++
	return counter.SnapshotCache.SetSnapshot(ctx, node, snapshot)
}

func (c *cacheImpl) trackSnapshotPublications() *snapshotPublicationCounter {
	counter := &snapshotPublicationCounter{SnapshotCache: c.SnapshotCache}
	c.SnapshotCache = counter
	return counter
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
func newTestCache(mockedCache *mockSnapshotCache) *cacheImpl {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := &cacheImpl{
		SnapshotCache: mockedCache,
		mutex:         &lock.RWMutex{},
		nodeStates:    make(map[string]*nodeState),
		openWatches:   make(map[string]*nodeWatchState),
		watchRelays:   make(map[chan cache.Response]*watchRelay),
		logger:        logger,
	}
	c.completionCbs = callbacks.NewCompletionCallbacks(logger, c)
	return c
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
// callback tests below. It seeds desired state from the requested snapshot and
// publishes that exact snapshot so tests can ACK its supplied versions.
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
	if err != nil {
		return err
	}
	c.mutex.Lock()
	state := c.nodeStates[nodeID]
	var finalized []finalizedCompletion
	if state != nil && state.staged != nil {
		oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
		_, finalized, err = c.installStagedSnapshotLocked(ctx, nodeID, state, state.staged, oldSnapshot, snapshot)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.completeFinalized(nodeID, finalized)
	return err
}

func setTestNodeEpochs(c *cacheImpl, nodeID string, epoch uint64) {
	state := c.nodeStates[nodeID]
	if state == nil {
		state = &nodeState{}
		c.nodeStates[nodeID] = state
	}
	state.epoch = epoch
	for typeURL := range typeurl.Indices() {
		state.resources[typeURL].negotiatedEpoch = epoch
	}
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
	// Distinct test policies need distinct generation-derived wire versions.
	state.resources[typeurl.NetworkPolicy].generation = endpointID
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

func TestGenerateSnapshotNewEDSClusterSharingEndpointBumpsVersion(t *testing.T) {
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

	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Cluster, "cluster2", &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
	require.Same(t, before.GetResources(envoy_resource.EndpointType)["backend"], after.GetResources(envoy_resource.EndpointType)["backend"])
}

func TestGenerateSnapshotNewQualifiedEDSClusterSharingEndpointBumpsVersion(t *testing.T) {
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

	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Cluster, "cec-b/shared-cluster", &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotExistingClusterUpdateBumpsEndpointVersion(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	state := &nodeState{epoch: 1, resourceGeneration: 10}
	state.seedResourceAtGeneration(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"}, 9)
	state.seedResourceAtGeneration(typeurl.Endpoint, "unrelated", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "unrelated"}, 9)
	cluster := &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}
	state.seedResourceAtGeneration(typeurl.Cluster, "cluster1", cluster, 10)
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	updatedCluster := proto.Clone(cluster).(*envoy_config_cluster.Cluster)
	updatedCluster.AltStatName = "updated"
	changed := state.stageSnapshotTestResource(typeurl.Cluster, "cluster1", updatedCluster)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, "e1:g11", after.GetVersion(envoy_resource.EndpointType))
	require.Same(t, before.GetResources(envoy_resource.EndpointType)["backend"], after.GetResources(envoy_resource.EndpointType)["backend"])

	// A real EDS update after the CDS update has the newer generation. The
	// forced aggregate version must never move it backwards.
	changed = changed.Union(state.stageSnapshotTestResource(typeurl.Endpoint, "backend",
		&envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}))
	after, err = c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, "e1:g12", after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotRemovedClusterDoesNotBumpEndpointVersion(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	for _, name := range []string{"cluster1", "cluster2"} {
		state.seedResource(typeurl.Cluster, name, &envoy_config_cluster.Cluster{
			Name:                 name,
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
			EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
		})
	}
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	changed := state.stageSnapshotTestResource(typeurl.Cluster, "cluster2", nil)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotNewRDSListenerDoesNotBumpRouteVersion(t *testing.T) {
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
	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
}

func TestGenerateSnapshotExistingListenerUpdateKeepsReferencedRouteVersions(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	state := &nodeState{epoch: 1, resourceGeneration: 10}
	state.seedResourceAtGeneration(typeurl.Route, "route1", &envoy_config_route.RouteConfiguration{Name: "route1"}, 9)
	state.seedResourceAtGeneration(typeurl.Route, "unrelated", &envoy_config_route.RouteConfiguration{Name: "unrelated"}, 9)
	listener := &envoy_config_listener.Listener{Name: "listener1", FilterChains: []*envoy_config_listener.FilterChain{{
		Filters: []*envoy_config_listener.Filter{{
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
				RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{RouteConfigName: "route1"}},
			})},
		}},
	}}}
	state.seedResourceAtGeneration(typeurl.Listener, "listener1", listener, 10)
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	updatedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
	updatedListener.TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
	changed := state.stageSnapshotTestResource(typeurl.Listener, "listener1", updatedListener)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
	require.Same(t, before.GetResources(envoy_resource.RouteType)["route1"], after.GetResources(envoy_resource.RouteType)["route1"])
}

// The live-Envoy test observes a fresh EDS response after a Cluster changes,
// but an unchanged RDS resource needs no response after a Listener changes.
// Exercise both watch paths here without starting Envoy in every test run.
func TestParentReplacementReplaysOnlyEndpointWatches(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		for _, parent := range []typeurl.Index{typeurl.Cluster, typeurl.Listener} {
			t.Run(fmt.Sprintf("strict=%t/parent=%s", strictADS, parent.URL()), func(t *testing.T) {
				logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				c := NewCache(logger, strictADS).(*cacheImpl)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				const childName = "child"
				var child typeurl.Index
				var parentName string
				var updated cache_types.Resource
				var initial xds.Resources
				if parent == typeurl.Cluster {
					child = typeurl.Endpoint
					parentName = "cluster"
					initial = xds.Resources{
						Clusters: map[string]*envoy_config_cluster.Cluster{parentName: {
							Name:                 parentName,
							ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
							EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: childName},
						}},
						Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{childName: {ClusterName: childName}},
					}
					updated = proto.Clone(initial.Clusters[parentName]).(*envoy_config_cluster.Cluster)
					updated.(*envoy_config_cluster.Cluster).AltStatName = "replacement"
				} else {
					child = typeurl.Route
					parentName = "listener"
					initial = xds.Resources{
						Listeners: map[string]*envoy_config_listener.Listener{parentName: {
							Name: parentName,
							FilterChains: []*envoy_config_listener.FilterChain{{Filters: []*envoy_config_listener.Filter{{
								Name: "envoy.filters.network.http_connection_manager",
								ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
									RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{RouteConfigName: childName}},
								})},
							}}}},
						}},
						Routes: map[string]*envoy_config_route.RouteConfiguration{childName: {Name: childName}},
					}
					updated = proto.Clone(initial.Listeners[parentName]).(*envoy_config_listener.Listener)
					updated.(*envoy_config_listener.Listener).TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
				}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))

				sotwResponses := make(chan cache.Response, 1)
				sotwSubscription := stream.NewSotwSubscription([]string{childName}, false)
				request := &cache.Request{Node: node, TypeUrl: child.URL(), ResourceNames: []string{childName}}
				cancel, err := c.CreateWatch(request, sotwSubscription, sotwResponses)
				require.NoError(t, err)
				if cancel != nil {
					t.Cleanup(cancel)
				}
				initialSotW := <-sotwResponses
				sotwSubscription.SetReturnedResources(initialSotW.GetReturnedResources())
				parentResponses := make(chan cache.Response, 1)
				parentSubscription := stream.NewSotwSubscription(nil, false)
				parentRequest := &cache.Request{Node: node, TypeUrl: parent.URL()}
				cancel, err = c.CreateWatch(parentRequest, parentSubscription, parentResponses)
				require.NoError(t, err)
				if cancel != nil {
					t.Cleanup(cancel)
				}
				initialParent := <-parentResponses
				parentSubscription.SetReturnedResources(initialParent.GetReturnedResources())

				request.VersionInfo = initialSotW.GetResponseVersion()
				cancel, err = c.CreateWatch(request, sotwSubscription, sotwResponses)
				require.NoError(t, err)
				if cancel != nil {
					t.Cleanup(cancel)
				}
				parentRequest.VersionInfo = initialParent.GetResponseVersion()
				cancel, err = c.CreateWatch(parentRequest, parentSubscription, parentResponses)
				require.NoError(t, err)
				if cancel != nil {
					t.Cleanup(cancel)
				}
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, parent, parentName, updated, nil, nil))
				require.Eventually(t, func() bool { return len(parentResponses) != 0 }, time.Second, time.Millisecond)
				<-parentResponses
				if parent == typeurl.Cluster {
					require.Eventually(t, func() bool { return len(sotwResponses) != 0 }, time.Second, time.Millisecond)
					response := <-sotwResponses
					require.NotEqual(t, initialSotW.GetResponseVersion(), response.GetResponseVersion())
				} else {
					require.Empty(t, sotwResponses)
					require.Equal(t, initialSotW.GetResponseVersion(), mustSnapshot(t, c, nodeID).GetVersion(child.URL()))
				}
			})
		}
	}
}

func TestNewClusterSharingEndpointReplaysWatches(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strictADS), func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
			c := NewCache(logger, strictADS).(*cacheImpl)
			const nodeID = "node1"
			const endpointName = "shared-endpoint"
			node := &envoy_config_core.Node{Id: nodeID}
			cluster := func(name string) *envoy_config_cluster.Cluster {
				return &envoy_config_cluster.Cluster{
					Name:                 name,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
					EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: endpointName},
				}
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters:  map[string]*envoy_config_cluster.Cluster{"first": cluster("first")},
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpointName: {ClusterName: endpointName}},
			}}, nil, TypeURLCallbacks{}))

			endpointRequest := &cache.Request{Node: node, TypeUrl: envoy_resource.EndpointType, ResourceNames: []string{endpointName}}
			endpointSubscription := stream.NewSotwSubscription([]string{endpointName}, false)
			endpointResponses := make(chan cache.Response, 1)
			cancel, err := c.CreateWatch(endpointRequest, endpointSubscription, endpointResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			initialEndpoint := <-endpointResponses
			endpointSubscription.SetReturnedResources(initialEndpoint.GetReturnedResources())

			clusterRequest := &cache.Request{Node: node, TypeUrl: envoy_resource.ClusterType}
			clusterSubscription := stream.NewSotwSubscription(nil, false)
			clusterResponses := make(chan cache.Response, 1)
			cancel, err = c.CreateWatch(clusterRequest, clusterSubscription, clusterResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			initialCluster := <-clusterResponses
			clusterSubscription.SetReturnedResources(initialCluster.GetReturnedResources())

			endpointRequest.VersionInfo = initialEndpoint.GetResponseVersion()
			cancel, err = c.CreateWatch(endpointRequest, endpointSubscription, endpointResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			clusterRequest.VersionInfo = initialCluster.GetResponseVersion()
			cancel, err = c.CreateWatch(clusterRequest, clusterSubscription, clusterResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "second", cluster("second"), nil, nil))
			require.Eventually(t, func() bool { return len(clusterResponses) != 0 }, time.Second, time.Millisecond)
			<-clusterResponses
			require.Eventually(t, func() bool { return len(endpointResponses) != 0 }, time.Second, time.Millisecond)
			require.NotEqual(t, initialEndpoint.GetResponseVersion(), (<-endpointResponses).GetResponseVersion())
		})
	}
}

func TestDeliverResponsesOrdersADSParentBeforeChild(t *testing.T) {
	c := &cacheImpl{}
	var sotwResponses []cache.Response
	for _, typeURL := range []string{
		envoy_resource.EndpointType,
		envoy_resource.RouteType,
		envoy_resource.ClusterType,
		envoy_resource.ListenerType,
	} {
		// The backend may produce these responses in randomized watch-map order.
		sotwResponses = append(sotwResponses, &cache.RawResponse{Request: &discovery.DiscoveryRequest{TypeUrl: typeURL}})
	}
	// Coalesced responses for a stream share one relay/channel.
	orderedSotW := make(chan cache.Response, 4)
	c.deliverResponses(responseDeliveries{
		sotw: []responseDelivery{{channel: orderedSotW, responses: sotwResponses}},
	})
	for _, want := range []string{
		envoy_resource.ClusterType,
		envoy_resource.EndpointType,
		envoy_resource.ListenerType,
		envoy_resource.RouteType,
	} {
		require.Equal(t, want, (<-orderedSotW).GetRequest().GetTypeUrl())
	}
}

func TestGenerateSnapshotNewSDSListenerDoesNotBumpSecretVersion(t *testing.T) {
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
	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.SecretType), after.GetVersion(envoy_resource.SecretType))
}

func TestGenerateSnapshotNewTCPProxyListenerDoesNotBumpClusterVersion(t *testing.T) {
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
	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.ClusterType), after.GetVersion(envoy_resource.ClusterType))
}

func TestGenerateSnapshotIncrementallyReusesUnchangedResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener1", &envoy_config_listener.Listener{Name: "listener1"})
	state.seedResource(typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 1})
	equalOriginal := &cilium.NetworkPolicy{EndpointId: 2}
	state.seedResource(typeurl.NetworkPolicy, "equal", equalOriginal)
	state.seedResource(typeurl.NetworkPolicy, "removed", &cilium.NetworkPolicy{EndpointId: 4})

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changedPolicy := &cilium.NetworkPolicy{EndpointId: 3}
	addedPolicy := &cilium.NetworkPolicy{EndpointId: 5}
	// A different pointer with equal protobuf content must retain the already
	// published object.
	equalPolicy := proto.Clone(equalOriginal).(*cilium.NetworkPolicy)
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 1, state.resourceEntries(typeurl.NetworkPolicy),
		map[string]*cilium.NetworkPolicy{"removed": nil},
		map[string]*cilium.NetworkPolicy{
			"changed": changedPolicy,
			"equal":   equalPolicy,
			"added":   addedPolicy,
		})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 1)

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)

	for typeURL := range typeurl.Indices() {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			"resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Same(t,
		previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
	)
	require.Same(t,
		changedPolicy,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["changed"].Resource,
	)
	require.NotContains(t, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items, "removed")
	require.Same(t,
		addedPolicy,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["added"].Resource,
	)
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.False(t, c.areDifferentSnapshots(next, fullyGenerated))
}

func TestGenerateSnapshotFromStateIncrementallyUsesPublishedCopyOnWriteMaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"})
	state.resources[typeurl.NetworkPolicy].entries = map[string]resourceEntry{
		"changed":   {resource: &cilium.NetworkPolicy{EndpointId: 1}, generation: 1},
		"unchanged": {resource: &cilium.NetworkPolicy{EndpointId: 2}, generation: 1},
		"removed":   {resource: &cilium.NetworkPolicy{EndpointId: 3}, generation: 1},
	}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changedPolicy := &cilium.NetworkPolicy{EndpointId: 4}
	addedPolicy := &cilium.NetworkPolicy{EndpointId: 5}
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 2, state.resourceEntries(typeurl.NetworkPolicy),
		map[string]*cilium.NetworkPolicy{"removed": nil},
		map[string]*cilium.NetworkPolicy{
			"changed": changedPolicy,
			"added":   addedPolicy,
		})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 2)

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)
	for typeURL := range typeurl.Indices() {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			"published resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Same(t,
		previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
	)
	require.Same(t, changedPolicy, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["changed"].Resource)
	require.Same(t, addedPolicy, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["added"].Resource)
	require.NotContains(t, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items, "removed")
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.False(t, c.areDifferentSnapshots(next, fullyGenerated))
}

func TestGenerateSnapshotFromStateIncrementallyReusesPublishedMapAfterCoalescedABA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	state := &nodeState{}
	state.resources[typeurl.NetworkPolicy].entries = map[string]resourceEntry{
		"policy": {resource: policyA, generation: 1},
	}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 2, state.resourceEntries(typeurl.NetworkPolicy),
		(map[string]*cilium.NetworkPolicy)(nil), map[string]*cilium.NetworkPolicy{"policy": {EndpointId: 2}})
	state.commitResourceMutation(changes, 2)
	changes = resourceChanges{}
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 3, state.resourceEntries(typeurl.NetworkPolicy),
		(map[string]*cilium.NetworkPolicy)(nil), map[string]*cilium.NetworkPolicy{"policy": policyA})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 3)
	require.Equal(t, 1, state.resources[typeurl.NetworkPolicy].changed.Len())
	require.True(t, state.resources[typeurl.NetworkPolicy].changed.Has("policy"))

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)
	require.Equal(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.NotEqual(t, previousSnapshot.GetVersion(NetworkPolicyTypeURL), nextSnapshot.GetVersion(NetworkPolicyTypeURL))
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
	state.commitResourceMutation(changes, 1)
	require.Equal(t, typeurl.NewSet(
		typeurl.Listener,
		typeurl.Cluster,
		typeurl.Secret,
	), changedTypeURLs)
	require.Equal(t, 1, state.resources[typeurl.Listener].changed.Len())
	require.True(t, state.resources[typeurl.Listener].changed.Has("listener"))
	require.Equal(t, 1, state.resources[typeurl.Cluster].changed.Len())
	require.True(t, state.resources[typeurl.Cluster].changed.Has("cluster"))
	require.Equal(t, 1, state.resources[typeurl.Secret].changed.Len())
	require.True(t, state.resources[typeurl.Secret].changed.Has("new-secret"))
	require.Empty(t, state.resources[typeurl.Route].changed)
	require.Empty(t, state.resources[typeurl.Endpoint].changed)
	require.Empty(t, state.resources[typeurl.NetworkPolicyHosts].changed)
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

	state.commitResourceMutation(changes, 1)
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
				changes = state.resourceRevert(rollback, typeurl.NetworkPolicy)
			}
			require.Len(t, changes.more, 3)
			require.Equal(t, current, state.resourceEntries(typeurl.NetworkPolicy), "preparation must not mutate entries")
			state.commitResourceMutation(changes, 12)
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

func TestGenerateSnapshotIncrementallyAdvancesGenerationAcrossABA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	state := &nodeState{}
	state.seedResource(typeurl.NetworkPolicy, "np1", policyA)

	snapshotA, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	changedTypeURLs := state.stageSnapshotTestResource(typeurl.NetworkPolicy, "np1", &cilium.NetworkPolicy{EndpointId: 2})
	snapshotB, err := c.generateSnapshotFromStateIncrementally(state, snapshotA, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, snapshotA.GetVersion(NetworkPolicyTypeURL), snapshotB.GetVersion(NetworkPolicyTypeURL))

	changedTypeURLs = state.stageSnapshotTestResource(typeurl.NetworkPolicy, "np1", policyA)
	snapshotAAgain, err := c.generateSnapshotFromStateIncrementally(state, snapshotB, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, snapshotA.GetVersion(NetworkPolicyTypeURL), snapshotAAgain.GetVersion(NetworkPolicyTypeURL),
		"returning to the same contents must not reuse an older on-wire version")
	require.Equal(t, "e0:g2", snapshotAAgain.GetVersion(NetworkPolicyTypeURL))
	require.Same(t, policyA, snapshotAAgain.GetResources(NetworkPolicyTypeURL)["np1"])
}

func TestGenerateSnapshotIncrementallyReturnsPreviousForKnownNoChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.NetworkPolicy, "np1", &cilium.NetworkPolicy{EndpointId: 1})

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	next, err := c.generateSnapshotFromStateIncrementally(state, previous, typeurl.NewSet())
	require.NoError(t, err)
	require.Same(t, previous, next)
}

func TestGenerateSnapshotIncrementallyInvalidatesListenerDependencies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Route, "route1", &envoy_config_route.RouteConfiguration{Name: "route1"})
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{Name: "cluster1"})
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
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

	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Listener, "listener1", listener)
	incremental, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	for typeURL := range typeurl.Indices() {
		require.Equal(t, fullyGenerated.GetResourcesAndTTL(typeURL.URL()), incremental.GetResourcesAndTTL(typeURL.URL()), typeURL.URL())
	}
	require.NotEqual(t, previous.GetVersion(envoy_resource.ListenerType), incremental.GetVersion(envoy_resource.ListenerType))
	for _, typeURL := range []string{envoy_resource.RouteType, envoy_resource.ClusterType, envoy_resource.SecretType, envoy_resource.EndpointType} {
		require.Equal(t, previous.GetVersion(typeURL), incremental.GetVersion(typeURL), typeURL)
	}
}

func TestGenerateSnapshotIncrementallyInvalidatesClusterDependencies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{Name: "cluster1"})
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	cluster := &envoy_config_cluster.Cluster{
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

	changedTypeURLs := state.stageSnapshotTestResource(typeurl.Cluster, "cluster1", cluster)
	incremental, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	for typeURL := range typeurl.Indices() {
		require.Equal(t, fullyGenerated.GetResourcesAndTTL(typeURL.URL()), incremental.GetResourcesAndTTL(typeURL.URL()), typeURL.URL())
	}
	require.NotEqual(t, previous.GetVersion(envoy_resource.ClusterType), incremental.GetVersion(envoy_resource.ClusterType))
	// The previous Cluster did not subscribe to this EDS name. Envoy's new
	// subscription requests it directly, so replaying the unchanged CLA is
	// only necessary when another Cluster already subscribed to that name.
	require.Equal(t, previous.GetVersion(envoy_resource.EndpointType), incremental.GetVersion(envoy_resource.EndpointType))
	require.Equal(t, previous.GetVersion(envoy_resource.SecretType), incremental.GetVersion(envoy_resource.SecretType))
	require.Equal(t, previous.GetVersion(envoy_resource.ListenerType), incremental.GetVersion(envoy_resource.ListenerType))
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
	generatedSnapshot.resourceGroups[typeurl.Endpoint].resources = cache.Resources{Version: "missing-endpoints"}

	require.ErrorContains(t, CheckSnapshotConsistency(snap), envoy_resource.EndpointType)
}

func TestCiliumSnapshotIndexedResourcesWithoutDeltaVersions(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	state := &nodeState{}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	state.seedResource(typeurl.NetworkPolicy, "np1", policy)

	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.Equal(t, policy, snapshot.GetResources(NetworkPolicyTypeURL)["np1"])
	require.Empty(t, snapshot.GetVersion("type.googleapis.com/unknown.Resource"))
	require.Nil(t, snapshot.GetResourcesAndTTL("type.googleapis.com/unknown.Resource"))

	require.ErrorContains(t, snapshot.ConstructVersionMap(), "delta xDS is not supported")
	require.Nil(t, snapshot.GetVersionMap(envoy_resource.EndpointType))
	require.Nil(t, snapshot.GetVersionMap(NetworkPolicyTypeURL))
	require.Nil(t, snapshot.GetVersionMap("type.googleapis.com/unknown.Resource"))
}

func TestGenerateSnapshotProjectionPreservesDesiredResources(t *testing.T) {
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
		require.Len(t, published, 1, "resource type %s", typeURL.URL())
	}
	// The generated empty CLA and the filtered wildcard endpoint affect only
	// the snapshot projection, not authoritative desired resource state.
	require.Contains(t, snapshot.GetResourcesAndTTL(envoy_resource.EndpointType), "cluster")
	require.NotContains(t, snapshot.GetResourcesAndTTL(envoy_resource.EndpointType), "orphan:*")
	_, exists := state.getResource(typeurl.Endpoint, "cluster")
	require.False(t, exists)
	_, exists = state.getResource(typeurl.Endpoint, "orphan:*")
	require.True(t, exists)

	emptySnapshot, err := c.generateSnapshotFromState(&nodeState{})
	require.NoError(t, err)
	for typeURL := range typeurl.Indices() {
		require.Nil(t, emptySnapshot.GetResourcesAndTTL(typeURL.URL()))
	}
}

func TestSnapshotDefersResourceEncodingToResponse(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	// Protobuf binary encoding rejects invalid UTF-8. Generation-based
	// versions let cache mutation and snapshot finalization succeed without
	// encoding the resource; the error belongs to response construction.
	listener := &envoy_config_listener.Listener{Name: "\xff"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	_, err = (<-responses).GetDiscoveryResponse()
	require.ErrorContains(t, err, "invalid UTF-8")
}

func strictTestListener(t *testing.T, name, route string) *envoy_config_listener.Listener {
	t.Helper()
	return &envoy_config_listener.Listener{
		Name: name,
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
						RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
							Rds: &envoy_config_http.Rds{RouteConfigName: route},
						},
					}),
				},
			}},
		}},
	}
}

func strictTestEDSCluster(name, endpoint string) *envoy_config_cluster.Cluster {
	return &envoy_config_cluster.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			ServiceName: endpoint,
		},
	}
}

func TestStrictADSValidatesRouteMutationsBeforeCommit(t *testing.T) {
	c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true).(*cacheImpl)
	const nodeID = "node1"
	listener := strictTestListener(t, "listener1", "route1")
	route := &envoy_config_route.RouteConfiguration{Name: "route1"}

	rollback, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Routes: map[string]*envoy_config_route.RouteConfiguration{"route1": route},
	}}, nil, TypeURLCallbacks{})
	require.ErrorContains(t, err, "orphan RDS resource \"route1\"")
	require.Nil(t, rollback)
	require.Nil(t, c.nodeStates[nodeID], "rejection must not create desired state")

	rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, "listener1", listener, nil, nil)
	require.ErrorContains(t, err, "missing RDS resource \"route1\"")
	require.Nil(t, rollback)
	require.Nil(t, c.nodeStates[nodeID])

	// Applying both sides in one transaction is valid regardless of map order.
	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener1": listener},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"route1": route},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	<-responses
	cancel()
	require.NoError(t, CheckSnapshotConsistency(mustSnapshot(t, c, nodeID)))

	err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener2",
		strictTestListener(t, "listener2", "route1"), nil, nil)
	require.NoError(t, err)
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener1", nil, nil, nil)
	require.NoError(t, err, "the second listener still references route1")
	rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, "listener2", nil, nil, nil)
	require.ErrorContains(t, err, "orphan RDS resource \"route1\"")
	require.Nil(t, rollback)
	_, exists := c.GetResource(nodeID, typeurl.Listener, "listener2")
	require.True(t, exists, "a rejected mutation must leave the listener intact")

	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener2": strictTestListener(t, "listener2", "route1")},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"route1": route},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	_, exists = c.GetResource(nodeID, typeurl.Route, "route1")
	require.False(t, exists)
}

func TestStrictADSValidatesEndpointMutationsBeforeCommit(t *testing.T) {
	c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true).(*cacheImpl)
	const nodeID = "node1"
	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}

	rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Endpoint, "endpoint", endpoint, nil, nil)
	require.ErrorContains(t, err, "orphan EDS resource \"endpoint\"")
	require.Nil(t, rollback)
	require.Nil(t, c.nodeStates[nodeID])

	// An EDS Cluster without an explicit CLA is valid: publication synthesizes
	// an empty assignment for its reference.
	cluster1 := strictTestEDSCluster("cluster1", "endpoint")
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster1", cluster1, nil, nil)
	require.NoError(t, err)
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ClusterType,
	}, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	<-responses
	cancel()
	require.NoError(t, CheckSnapshotConsistency(mustSnapshot(t, c, nodeID)))

	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", endpoint, nil, nil)
	require.NoError(t, err)
	cluster2 := strictTestEDSCluster("cluster2", "endpoint")
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster2", cluster2, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster1", nil, nil, nil)
	require.NoError(t, err, "the second cluster still references the CLA")
	rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Cluster, "cluster2", nil, nil, nil)
	require.ErrorContains(t, err, "orphan EDS resource \"endpoint\"")
	require.Nil(t, rollback)

	// Removing both the final reference and the explicit CLA is atomic.
	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: xds.Resources{
		Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster2": cluster2},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"endpoint": endpoint},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	_, exists := c.GetResource(nodeID, typeurl.Endpoint, "endpoint")
	require.False(t, exists)
}

func TestStrictADSReferenceIndexRestoredAfterPublicationFailure(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	c.strictAdsMode = true
	c.logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	const nodeID = "node1"
	route := &envoy_config_route.RouteConfiguration{Name: "route1"}
	listener1 := strictTestListener(t, "listener1", "route1")
	err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener1": listener1},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"route1": route},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	// The mock leaves the listener watch open, so the next mutation attempts
	// synchronous publication and can exercise its restoration path.
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	mock.setSnapshotErr = errors.New("snapshot publication failed")
	rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, "listener2",
		strictTestListener(t, "listener2", "route1"), nil, nil)
	require.ErrorContains(t, err, "snapshot publication failed")
	require.Nil(t, rollback)
	_, exists := c.GetResource(nodeID, typeurl.Listener, "listener2")
	require.False(t, exists)
	mock.setSnapshotErr = nil

	// If the failed transaction left a phantom reference in the index, this
	// removal would be incorrectly accepted and orphan the route.
	rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, "listener1", nil, nil, nil)
	require.ErrorContains(t, err, "orphan RDS resource \"route1\"")
	require.Nil(t, rollback)
}

func TestApplyResourcesPublicationFailureCleansUnchangedWait(t *testing.T) {
	for _, stagedEndpoint := range []bool{false, true} {
		name := "published"
		if stagedEndpoint {
			name = "staged"
		}
		t.Run(name, func(t *testing.T) {
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

			// Keep an LDS watch open so the next listener change publishes immediately.
			responses := make(chan cache.Response, 1)
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
			}, stream.NewSotwSubscription(nil, false), responses)
			require.NoError(t, err)
			t.Cleanup(cancel)

			if stagedEndpoint {
				// An EDS-only change remains staged because only LDS has an open watch.
				endpoint = &envoy_config_endpoint.ClusterLoadAssignment{
					ClusterName: endpoint.ClusterName,
					Endpoints:   []*envoy_config_endpoint.LocalityLbEndpoints{{}},
				}
				err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, endpoint.ClusterName, endpoint, nil, nil)
				require.NoError(t, err)
				require.NotNil(t, c.nodeStates[nodeID].staged)
			}

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
			err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{
					listener.Name: {Name: listener.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND},
				},
				// The identical endpoint waits for its staged or published EDS version.
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpoint.ClusterName: endpoint},
			}}, wg, waits)
			require.ErrorIs(t, err, publicationErr)
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			require.ErrorIs(t, wg.Wait(), publicationErr)
			require.ErrorIs(t, callbackErr, publicationErr)
			current, exists := c.GetResource(nodeID, typeurl.Listener, listener.Name)
			require.True(t, exists)
			require.Same(t, listener, current)
			current, exists = c.GetResource(nodeID, typeurl.Endpoint, endpoint.ClusterName)
			require.True(t, exists)
			require.Same(t, endpoint, current)
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
			// The mock keeps this watch open, making both mutations and reverts
			// finalize synchronously. Without an open watch, the injected
			// publication failure would be deferred until the next CreateWatch.
			cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: envoy_resource.RouteType},
				stream.NewSotwSubscription(nil, false), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
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

func TestNonStrictADSAllowsOrphanEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	err := c.ApplyResource(t.Context(), "node1", typeurl.Endpoint, "orphan",
		&envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan"}, nil, nil)
	require.NoError(t, err)
	require.Nil(t, c.nodeStates["node1"].strictRefs)
}

func TestStrictADSIgnoresUnrelatedResourceMutations(t *testing.T) {
	c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true).(*cacheImpl)
	err := c.ApplyResource(t.Context(), "node1", typeurl.Secret, "secret1",
		&envoy_config_tls.Secret{Name: "secret1"}, nil, nil)
	require.NoError(t, err)
	require.Nil(t, c.nodeStates["node1"].strictRefs,
		"unrelated mutations should not initialize the consistency index")
}

func TestGenerateSnapshotForUpdateChecksConsistencyOnlyInStrictDebugMode(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
			t.Run(fmt.Sprintf("strict-ads=%t/level=%s", strictADS, level), func(t *testing.T) {
				logger := hivetest.Logger(t, hivetest.LogLevel(level))
				c := NewCache(logger, strictADS).(*cacheImpl)
				state := &nodeState{}
				// Deliberately bypass mutation-time validation to exercise the
				// full snapshot check with an orphan route in the projection.
				state.seedResource(typeurl.Route, "orphan", &envoy_config_route.RouteConfiguration{Name: "orphan"})
				snapshot, err := c.generateSnapshotForUpdate(state, nil, typeurl.NewSet(typeurl.Route))
				if strictADS && level == slog.LevelDebug {
					require.ErrorContains(t, err, "generated ADS snapshot is inconsistent")
					require.Nil(t, snapshot)
				} else {
					require.NoError(t, err)
					require.NotNil(t, snapshot)
				}
			})
		}
	}
}

func TestCloneStagedRollbacksClonesStrictADSCompanion(t *testing.T) {
	var staged typeurl.Map[rollbackResources]
	var rollback rollbackResources
	rollback[typeurl.Listener] = map[string]rollbackEntry{"listener": {expectedGeneration: 1}}
	rollback[typeurl.Route] = map[string]rollbackEntry{"route": {expectedGeneration: 1}}
	staged.Set(typeurl.Listener, rollback)

	cloned := cloneStagedRollbacks(staged)
	clonedRollback, _ := cloned.Get(typeurl.Listener)
	delete(clonedRollback[typeurl.Route], "route")

	originalRollback, _ := staged.Get(typeurl.Listener)
	require.Contains(t, originalRollback[typeurl.Route], "route")
}

func TestNewCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger, false).(*cacheImpl)

	assert.NotNil(t, c.SnapshotCache)
	assert.NotNil(t, c.logger)
}

func TestStrictADSCacheHoldsPartialNamedRequest(t *testing.T) {
	c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true).(*cacheImpl)
	const nodeID = "node1"
	err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Secrets: map[string]*envoy_config_tls.Secret{
			"secret1": {Name: "secret1"},
			"secret2": {Name: "secret2"},
		},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node:          &envoy_config_core.Node{Id: nodeID},
		TypeUrl:       envoy_resource.SecretType,
		ResourceNames: []string{"secret1"},
	}, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Empty(t, responses, "strict ADS holds a watch until its named request covers the snapshot")
	cancel()

	fullResponses := make(chan cache.Response, 1)
	fullCancel, err := c.CreateWatch(&cache.Request{
		Node:          &envoy_config_core.Node{Id: nodeID},
		TypeUrl:       envoy_resource.SecretType,
		ResourceNames: []string{"secret1", "secret2"},
	}, stream.NewSotwSubscription(nil, false), fullResponses)
	require.NoError(t, err)
	if fullCancel != nil {
		t.Cleanup(fullCancel)
	}
	require.Eventually(t, func() bool { return len(fullResponses) != 0 }, time.Second, time.Millisecond)
	response := <-fullResponses
	require.Contains(t, response.GetReturnedResources(), "secret1")
	require.Contains(t, response.GetReturnedResources(), "secret2")
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

func TestSnapshotVersion_DifferentGenerationsProduceDifferentVersions(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)

	state1 := &nodeState{}
	state1.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state2 := &nodeState{}
	state2.seedResource(typeurl.Listener, "l2", &envoy_config_listener.Listener{Name: "l2"})
	state2.resources[typeurl.Listener].generation = 1

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

func TestSnapshotVersion_SameGenerationProducesSameVersion(t *testing.T) {
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
	state2.resources[typeurl.Listener].generation = 1

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

func TestUpsertNetworkPolicyFinalizesLatestGenerationOnCreateWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	publications := c.trackSnapshotPublications()
	for _, endpointID := range []uint64{1, 2} {
		err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)
		require.NoError(t, err)
	}

	require.Zero(t, publications.publications)
	_, err := c.SnapshotCache.GetSnapshot("node1")
	require.Error(t, err)
	require.Equal(t, uint64(2), maps.Collect(c.NetworkPolicies("node1"))["policy"].EndpointId)

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
	require.Equal(t, 1, publications.publications)
	require.Equal(t, response.GetResponseVersion(), mustSnapshot(t, c, "node1").GetVersion(NetworkPolicyTypeURL))
	policy := mustSnapshot(t, c, "node1").GetResources(NetworkPolicyTypeURL)["policy"].(*cilium.NetworkPolicy)
	require.Equal(t, uint64(2), policy.EndpointId)
}

func TestApplyResourcesKeepsChangedNamesUntilFinalization(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	publications := c.trackSnapshotPublications()

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policyA, nil, nil)
	require.NoError(t, err)
	require.Zero(t, publications.publications)
	state := c.nodeStates["node1"]
	require.Same(t, policyA, state.resources[typeurl.NetworkPolicy].entries["policy"].resource)
	resourceMap := reflect.ValueOf(state.resources[typeurl.NetworkPolicy].entries).Pointer()
	require.Equal(t, 1, state.resources[typeurl.NetworkPolicy].changed.Len())
	require.True(t, state.resources[typeurl.NetworkPolicy].changed.Has("policy"))

	policyB := &cilium.NetworkPolicy{EndpointId: 2}
	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policyB, nil, nil)
	require.NoError(t, err)
	require.Zero(t, publications.publications)
	require.Equal(t, resourceMap, reflect.ValueOf(state.resources[typeurl.NetworkPolicy].entries).Pointer())
	require.Equal(t, 1, state.resources[typeurl.NetworkPolicy].changed.Len())
	require.True(t, state.resources[typeurl.NetworkPolicy].changed.Has("policy"))
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
	require.Equal(t, 1, publications.publications, "all staged updates must be published by one finalization")
	require.Equal(t, state.resourceGeneration, state.snapshotGeneration)
	require.Nil(t, state.staged)
	require.Same(t, policyB, state.resources[typeurl.NetworkPolicy].entries["policy"].resource)
	require.Empty(t, state.resources[typeurl.NetworkPolicy].changed)
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

func TestCloneStagedRollbacksIncludesStrictADSCompanions(t *testing.T) {
	var rollback rollbackResources
	rollback[typeurl.Listener] = map[string]rollbackEntry{"listener": {expectedGeneration: 1}}
	rollback[typeurl.Route] = map[string]rollbackEntry{"route": {expectedGeneration: 1}}
	var original typeurl.Map[rollbackResources]
	original.Set(typeurl.Listener, rollback)

	cloned := cloneStagedRollbacks(original)
	clonedRollback, _ := cloned.Get(typeurl.Listener)
	clonedRollback[typeurl.Listener]["listener"] = rollbackEntry{expectedGeneration: 2}
	clonedRollback[typeurl.Route]["route"] = rollbackEntry{expectedGeneration: 2}
	originalRollback, _ := original.Get(typeurl.Listener)
	require.Equal(t, uint64(1), originalRollback[typeurl.Listener]["listener"].expectedGeneration)
	require.Equal(t, uint64(1), originalRollback[typeurl.Route]["route"].expectedGeneration)
}

func TestApplyResourcesCoalescesStagedRollbackState(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	const updates = 1000

	for endpointID := uint64(1); endpointID <= updates; endpointID++ {
		err := c.ApplyResource(
			t.Context(), "node1", typeurl.NetworkPolicy,
			"policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)

		require.NoError(t, err)
	}

	state := c.nodeStates["node1"]
	require.NotNil(t, state)
	require.NotNil(t, state.staged)
	require.Equal(t, 1, state.staged.rollbacks.Len())
	policyRollback, exists := state.staged.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.Len(t, policyRollback[typeurl.NetworkPolicy], 1,
		"staging must retain one inverse per changed resource, not one per update")
	require.True(t, state.rollbackOwners.Empty(), "non-removal updates need no tombstone ownership")
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
	require.NotNil(t, state.staged)
	policyRollback, exists := state.staged.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	coldStartRollback := policyRollback[typeurl.NetworkPolicy]
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
	c.mutex.Lock()
	_, finalized, err := c.finalizeStagedSnapshotLocked(t.Context(), "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
	initial := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	for id := range resources {
		name := strconv.Itoa(id)
		rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicy, name, nil, nil, nil)
		require.NoError(t, err)
		rollback.Finalize()
	}
	c.mutex.Lock()
	_, finalized, err = c.finalizeStagedSnapshotLocked(t.Context(), "node1")
	c.mutex.Unlock()
	require.NoError(t, err)
	c.completeFinalized("node1", finalized)
	removed := mustSnapshot(t, c, "node1")
	ackNetworkPolicyVersion(t, c, "node1", removed.GetVersion(NetworkPolicyTypeURL))
	c.completionCbs.OnStreamClosed(1, &envoy_config_core.Node{Id: "node1"})

	state := c.nodeStates["node1"]
	require.Nil(t, state,
		"a node without desired resources, rollback state, or streams must be released")
}

func TestAcceptedRemovalReleasesResponseTombstone(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	setTestNodeEpochs(c, "node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	rollback, err := c.ApplyResourceWithRollback(
		ctx, "node1", typeurl.NetworkPolicy,
		"policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	rollback.Finalize()
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
	c.completionCbs.OnStreamClosed(1, request.Node)
	require.Nil(t, c.nodeStates["node1"],
		"the accepted removal leaves neither desired nor rollback state")
}

func TestNACKedRemovalRestoresResourceAfterCallerCompletion(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	setTestNodeEpochs(c, "node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
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
	setTestNodeEpochs(c, "node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policyA, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
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
			request := &cache.Request{Node: node, TypeUrl: envoy_resource.RouteType}
			subscription := stream.NewSotwSubscription(nil, false)
			responses := make(chan cache.Response, 1)
			// Let a real watch finalize the staged baseline before accepting it.
			cancel, err := c.CreateWatch(request, subscription, responses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			require.Len(t, responses, 1)
			baseline := <-responses
			subscription.SetReturnedResources(baseline.GetReturnedResources())
			acknowledgeResponse(t, c, 1, baseline, "accepted-routes")
			request.VersionInfo = baseline.GetResponseVersion()
			cancel, err = c.CreateWatch(request, subscription, responses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			rollback := apply(t, c, routes(map[string]uint64{"newer": 2, "unchanged": 2}))
			if mode == "NACK-driven" {
				defer rollback.Finalize()
			}
			// Bind the response before the newer resource is changed, so its
			// NACK must not include the later update.
			require.Len(t, responses, 1)
			response := <-responses
			c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
				&discovery.DiscoveryResponse{
					VersionInfo: response.GetResponseVersion(),
					TypeUrl:     envoy_resource.RouteType,
					Nonce:       "rejected-routes",
				})
			applyPlain(t, c, routes(map[string]uint64{"newer": 3}))

			if mode == "NACK-driven" {
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node:          node,
					TypeUrl:       envoy_resource.RouteType,
					VersionInfo:   baseline.GetResponseVersion(),
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

func TestUpsertNetworkPolicyFinalizesOncePerAvailableWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	publications := c.trackSnapshotPublications()
	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	subscription := stream.NewSotwSubscription(nil, false)
	responses := make(chan cache.Response, 1)

	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	responseA := <-responses
	subscription.SetReturnedResources(responseA.GetReturnedResources())
	cancel()
	require.Equal(t, 1, publications.publications)

	request.VersionInfo = responseA.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 2}, nil, nil)
	require.NoError(t, err)
	responseB := <-responses
	subscription.SetReturnedResources(responseB.GetReturnedResources())
	require.Equal(t, 2, publications.publications)

	// The B response consumed the only NPDS watch. C remains staged while the
	// simulated client processes B, even though its response channel is empty.
	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 3}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, publications.publications)

	request.VersionInfo = responseB.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	responseC := <-responses
	require.Equal(t, 3, publications.publications)
	require.NotEqual(t, responseB.GetResponseVersion(), responseC.GetResponseVersion())
}

func TestApplyResourcesAttachesNoOpDuringResponseDelivery(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	setTestNodeEpochs(c, node.GetId(), 1)
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

func TestUpsertNetworkPolicyIgnoresUnrelatedOpenWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	publications := c.trackSnapshotPublications()
	node := &envoy_config_core.Node{Id: "node1"}

	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	npResponses := make(chan cache.Response, 1)
	_, err = c.CreateWatch(&cache.Request{Node: node, TypeUrl: NetworkPolicyTypeURL},
		stream.NewSotwSubscription(nil, false), npResponses)
	require.NoError(t, err)
	<-npResponses
	require.Equal(t, 1, publications.publications)

	listenerVersion := mustSnapshot(t, c, "node1").GetVersion(envoy_resource.ListenerType)
	listenerResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: listenerVersion,
	}, stream.NewSotwSubscription(nil, false), listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	// A first Listener request may rotate the shared epoch and republish the
	// protocol view. Only the policy mutation must leave this unrelated watch
	// without a new snapshot.
	beforeMutation := publications.publications
	err = c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 2}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, beforeMutation, publications.publications)
}

func TestListenerMutationWaitsForListenerWatchAndReleasesUnchangedDependencies(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	setTestNodeEpochs(c, node.GetId(), 1)
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

	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), nil, nil, nil)
	require.NoError(t, err)
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

	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly received the listener update")
	default:
	}
	c.completionCbs.OnStreamClosed(1, node)
	require.Nil(t, c.nodeStates[node.GetId()],
		"an ACKed removal must release an otherwise empty streamless node")
}

func TestStagedRollbackDropsAddedThenRemovedEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan"}

	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "orphan", endpoint, nil, nil)
	require.NoError(t, err)
	staged, exists := c.nodeStates[nodeID].staged.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists)
	require.Len(t, staged[typeurl.Endpoint], 1)

	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "orphan", nil, nil, nil)
	require.NoError(t, err)
	state := c.nodeStates[nodeID]
	require.NotNil(t, state)
	require.True(t, state.staged.rollbacks.Empty(), "a never-sent add/remove has no rollback target")
	require.True(t, state.rollbackOwners.Empty())
	require.Empty(t, state.resources[typeurl.Endpoint].entries, "the removal tombstone must be released")
}

func TestStagedRollbackRetainsOriginalEndpointAfterRemoval(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	original := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}
	c.nodeStates[nodeID] = &nodeState{}
	c.nodeStates[nodeID].seedResource(typeurl.Endpoint, "endpoint", original)

	changed := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", changed, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", nil, nil, nil)
	require.NoError(t, err)

	state := c.nodeStates[nodeID]
	staged, exists := state.staged.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists)
	require.Same(t, original, staged[typeurl.Endpoint]["endpoint"].previous.resource,
		"a removal is not a net no-op when the resource existed before the unsent changes")
}

func TestStagedRollbackDropsSemanticEndpointABA(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	original := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}
	c.nodeStates[nodeID] = &nodeState{}
	c.nodeStates[nodeID].seedResource(typeurl.Endpoint, "endpoint", original)

	changed := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", changed, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint",
		&envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}, nil, nil)
	require.NoError(t, err)

	require.True(t, c.nodeStates[nodeID].staged.rollbacks.Empty(),
		"a distinct protobuf pointer with the original contents needs no rollback")
}

func TestPublishedUnsentRollbackKeepsOtherTransactionChangesAfterNetZeroEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	setTestNodeEpochs(c, nodeID, 1)

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
	endpointRollback, exists := state.unsentRollbacks.Get(typeurl.Endpoint)
	require.True(t, exists, "an EDS NACK must still be able to revert the whole second transaction")
	require.Empty(t, (*endpointRollback.resources)[typeurl.Endpoint], "the net-zero endpoint change needs no rollback")
	require.Contains(t, (*endpointRollback.resources)[typeurl.Cluster], "another-cluster")
	require.True(t, state.rollbackOwners.Empty())
	require.Empty(t, state.resources[typeurl.Endpoint].entries)
}

func TestPublishedUnsentRollbackCoalescesUntilResponse(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	setTestNodeEpochs(c, nodeID, 1)

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

func TestUpsertNetworkPolicyCompletesCoalescedABAOnCreateWatch(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	publications := c.trackSnapshotPublications()
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
	// The return to accepted A completes immediately, but B needs the next
	// watch to finalize the coalesced update.
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	published, err := c.SnapshotCache.GetSnapshot(node.GetId())
	require.NoError(t, err)
	require.Equal(t, responseA.GetResponseVersion(), published.GetVersion(NetworkPolicyTypeURL))

	// Finalization returns to the already ACKed contents, but generation-based
	// versions deliberately advance across A-B-A changes. The response for the
	// newest generation resolves both folded mutations when Envoy ACKs it.
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: NetworkPolicyTypeURL, VersionInfo: responseA.GetResponseVersion(),
	}, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	afterWatch, err := c.SnapshotCache.GetSnapshot(node.GetId())
	require.NoError(t, err)
	require.NotSame(t, published, afterWatch, "CreateWatch must finalize the staged snapshot")
	require.NotEqual(t, responseA.GetResponseVersion(), afterWatch.GetVersion(NetworkPolicyTypeURL))
	response := <-responses
	require.Equal(t, afterWatch.GetVersion(NetworkPolicyTypeURL), response.GetResponseVersion())
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: response.GetResponseVersion(),
			TypeUrl:     NetworkPolicyTypeURL,
			Nonce:       "nonce-aba",
		})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: "nonce-aba",
	}))
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.Equal(t, 2, publications.publications)
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
	state := c.nodeStates[nodeID]
	require.NotNil(t, state)
	require.Equal(t, uint64(1), state.epoch)
	require.Equal(t, state.epoch, state.resources[typeurl.NetworkPolicy].negotiatedEpoch)

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
	require.Contains(t, c.nodeStates, nodeID)

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
				logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
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
				state := c.nodeStates[nodeID]
				require.NotNil(t, state, "the open stream retains its negotiated epoch")
				for typeURL := range typeurl.Indices() {
					require.Empty(t, state.resources[typeURL].entries, "connecting must not create desired resources")
				}

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
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}
	// The first watch finalizes the staged state. A subsequent watch must use
	// that published snapshot rather than replacing it.
	initialResponses := make(chan cache.Response, 1)
	initialCancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), initialResponses)
	require.NoError(t, err)
	t.Cleanup(initialCancel)
	<-initialResponses
	snapshot := mustSnapshot(t, c, nodeID)

	responses := make(chan cache.Response, 1)
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
			if stored {
				require.NotNil(t, c.nodeStates["node1"])
			} else {
				require.NotContains(t, c.nodeStates, "node1")
			}
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

func TestCreateWatchSelectsEpochForNodeAndTypeURL(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: "e1:g99",
	}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	response := <-responses
	require.Equal(t, uint64(2), c.nodeStates["node1"].epoch)
	require.Equal(t, uint64(2), c.nodeStates["node1"].resources[typeurl.NetworkPolicy].negotiatedEpoch)
	require.Equal(t, "e2:g1", response.GetResponseVersion())
	require.Same(t, policy, response.(*cache.RawResponse).GetRawResources()[0].Resource)
}

func TestCreateWatchRotatesNodeEpochForMixedTypeURLHistory(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	resources := xds.NewResources()
	resources.Clusters["cluster"] = &envoy_config_cluster.Cluster{Name: "cluster"}
	resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResources(t.Context(), "node1",
		ResourceMutations{Upserted: resources}, nil, NewTypeURLCallbacks())
	require.NoError(t, err)

	createWatch := func(typeURL, version string) cache.Response {
		t.Helper()
		request := &cache.Request{
			Node:        &envoy_config_core.Node{Id: "node1"},
			TypeUrl:     typeURL,
			VersionInfo: version,
		}
		responses := make(chan cache.Response, 1)
		cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
		require.NoError(t, err)
		if cancel != nil {
			t.Cleanup(cancel)
		}
		select {
		case response := <-responses:
			return response
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for xDS response")
			return nil
		}
	}

	// Model a partially updated Envoy left by previous agent instances: CDS
	// still reports epoch 1 while LDS already reports epoch 2. A cache-global
	// choice based on CDS would collide with the retained LDS namespace.
	clusterResponse := createWatch(envoy_resource.ClusterType, "e1:g99")
	require.Equal(t, "e2:g1", clusterResponse.GetResponseVersion())
	beforeRotation := mustSnapshot(t, c, "node1").(*ciliumSnapshot)
	var versionsBeforeRotation typeurl.Slots[string]
	for typeURL := range typeurl.Indices() {
		versionsBeforeRotation[typeURL] = beforeRotation.GetVersion(typeURL.URL())
	}
	listenerResponse := createWatch(envoy_resource.ListenerType, "e2:g1")
	require.Equal(t, "e3:g1", listenerResponse.GetResponseVersion())

	state := c.nodeStates["node1"]
	require.Equal(t, uint64(3), state.epoch)
	require.Equal(t, uint64(3), state.resources[typeurl.Cluster].negotiatedEpoch)
	require.Equal(t, uint64(3), state.resources[typeurl.Listener].negotiatedEpoch)
	snapshot := mustSnapshot(t, c, "node1")
	require.Equal(t, "e3:g1", snapshot.GetVersion(envoy_resource.ClusterType))
	require.Equal(t, "e3:g1", snapshot.GetVersion(envoy_resource.ListenerType))
	afterRotation := snapshot.(*ciliumSnapshot)
	for typeURL := range typeurl.Indices() {
		require.Equal(t,
			versionsBeforeRotation[typeURL],
			beforeRotation.GetVersion(typeURL.URL()),
			"epoch rotation mutated the old %s aggregate version", typeURL,
		)
		require.NotEqual(t,
			versionsBeforeRotation[typeURL],
			afterRotation.GetVersion(typeURL.URL()),
			"epoch rotation did not replace the %s aggregate version", typeURL,
		)
		require.Equal(t,
			reflect.ValueOf(beforeRotation.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(afterRotation.resourceGroups[typeURL].resources.Items).Pointer(),
			"epoch rotation copied %s resources", typeURL,
		)
	}
}

func TestEmptyNodeStateFollowsStreamLifetime(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	node := &envoy_config_core.Node{Id: "node1"}
	request := &discovery.DiscoveryRequest{Node: node, TypeUrl: NetworkPolicyTypeURL}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 1, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(1, request))

	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	<-responses
	cancel()

	state := c.nodeStates[node.GetId()]
	require.NotNil(t, state)
	require.True(t, state.streams[callbacks.StreamModeSotW].Has(1))
	require.Equal(t, uint64(1), state.epoch)
	require.Equal(t, state.epoch, state.resources[typeurl.NetworkPolicy].negotiatedEpoch)

	c.completionCbs.OnStreamClosed(1, node)
	require.NotContains(t, c.nodeStates, node.GetId())
	_, err = c.SnapshotCache.GetSnapshot(node.GetId())
	require.Error(t, err)
}

func TestNodeEpochSurvivesStreamGapWithDesiredState(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false).(*cacheImpl)
	node := &envoy_config_core.Node{Id: "node1"}
	err := c.ApplyResource(t.Context(), node.GetId(), typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)

	request := &discovery.DiscoveryRequest{
		Node: node, TypeUrl: NetworkPolicyTypeURL, VersionInfo: "e1:g99",
	}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 1, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	response := <-responses
	cancel()
	require.Equal(t, "e2:g1", response.GetResponseVersion())
	acknowledgeResponse(t, c, 1, response, "initial")
	c.completionCbs.OnStreamClosed(1, node)

	state := c.nodeStates[node.GetId()]
	require.NotNil(t, state, "desired state must retain the negotiated epoch")
	require.True(t, state.streams[callbacks.StreamModeSotW].Empty())
	require.Equal(t, uint64(2), state.epoch)

	request = &discovery.DiscoveryRequest{
		Node: node, TypeUrl: NetworkPolicyTypeURL, VersionInfo: "e2:g1",
	}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 2, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
	responses = make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	cancel()
	require.Equal(t, uint64(2), c.nodeStates[node.GetId()].epoch)
	select {
	case <-responses:
		t.Fatal("a reconnect using the retained epoch unexpectedly received a response")
	default:
	}
	c.completionCbs.OnStreamClosed(2, node)
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

func TestXDSVersionFormatAndEpochParsing(t *testing.T) {
	require.Equal(t, "e1:g2", formatXDSVersion(1, 2))

	for version, expected := range map[string]uint64{
		"e1:g2":        1,
		"e42:anything": 42,
	} {
		epoch, ok := parseXDSEpoch(version)
		require.True(t, ok, version)
		require.Equal(t, expected, epoch, version)
	}
	for _, version := range []string{"", "e0:g1", "e:g1", "e-1:g1", "1:g1", "legacy-hash"} {
		_, ok := parseXDSEpoch(version)
		require.False(t, ok, version)
	}
}

func TestSelectEpochDiffersFromReportedEpoch(t *testing.T) {
	for _, test := range []struct {
		version string
		epoch   uint64
	}{
		{version: "", epoch: 1},
		{version: "legacy-hash", epoch: 1},
		{version: "e1:g100", epoch: 2},
		{version: "e3:g9", epoch: 1},
	} {
		t.Run(test.version, func(t *testing.T) {
			state := &nodeState{}
			require.True(t, state.selectEpochLocked(typeurl.Listener, singleVersion(test.version)))
			require.Equal(t, test.epoch, state.epoch)
			state.commitEpochNegotiation(typeurl.Listener)

			// A later stream cannot change the same node and TypeURL epoch.
			require.False(t, state.selectEpochLocked(typeurl.Listener, singleVersion("e2:g7")))
			require.Equal(t, test.epoch, state.epoch)
		})
	}
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
