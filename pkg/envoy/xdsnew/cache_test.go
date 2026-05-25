// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/lock"
)

type mockSnapshotCache struct {
	snapshots      map[string]cache.ResourceSnapshot
	setSnapshotErr error
	clearCalled    map[string]bool

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
		SnapshotCache:       mockedCache,
		mutex:               &lock.RWMutex{},
		resourcesInSnapshot: make(map[string]*xds.Resources),
		logger:              logger,
		hasher:              nil, // not needed for tests that don't call hash/GetVersion
		completionCbs:       callbacks.NewCompletionCallbacks(logger),
	}
}

func newTestCacheWithHasher(mock *mockSnapshotCache) *cacheImpl {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))).(*cacheImpl)
	c.SnapshotCache = mock
	c.resourcesInSnapshot = make(map[string]*xds.Resources)
	return c
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

func networkPolicySnapshot(t *testing.T, c *cacheImpl, endpointID uint64) (*xds.Resources, cache.ResourceSnapshot) {
	t.Helper()

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: endpointID}
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)
	return resources, snap
}

func listenerSnapshot(t *testing.T, c *cacheImpl, name string) (*xds.Resources, cache.ResourceSnapshot) {
	t.Helper()

	resources := emptyResources()
	resources.Listeners[name] = &envoy_config_listener.Listener{Name: name}
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)
	return resources, snap
}

func ackNetworkPolicyVersion(t *testing.T, c *cacheImpl, nodeID, version string) {
	t.Helper()

	node := &envoy_config_core.Node{Id: nodeID}
	c.completionCbs.OnStreamResponse(context.Background(), 1,
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
	c.completionCbs.OnStreamResponse(context.Background(), 1,
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

func TestNewCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := NewCache(logger).(*cacheImpl)

	assert.NotNil(t, c.SnapshotCache)
	assert.NotNil(t, c.logger)
	assert.NotNil(t, c.hasher)
}

func TestGetSnapshot_ExistingNode(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	// Pre-populate a snapshot in the mock
	resources := emptyResources()
	resources.Listeners["test-listener"] = &envoy_config_listener.Listener{Name: "test-listener"}

	snap, err := c.GenerateSnapshot(resources, c.logger)
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

	assert.False(t, c.AreDifferentSnapshots(snap, result))
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
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	snap, err := c.GenerateSnapshot(resources, c.logger)
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

	c.SetResources("node1", resources)

	storedResources := c.resourcesInSnapshot["node1"]
	require.NotNil(t, storedResources)
	assert.Contains(t, storedResources.Listeners, "listener1")
}

func TestSetResources_OverwriteExisting(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	res1 := emptyResources()
	res1.Listeners["old-listener"] = &envoy_config_listener.Listener{Name: "old-listener"}
	c.SetResources("node1", res1)
	storedResources := c.resourcesInSnapshot["node1"]
	require.NotNil(t, storedResources)
	assert.Len(t, storedResources.Listeners, 1)
	assert.Contains(t, storedResources.Listeners, "old-listener")

	res2 := emptyResources()
	res2.Listeners["new-listener"] = &envoy_config_listener.Listener{Name: "new-listener"}
	c.SetResources("node1", res2)

	storedResources = c.resourcesInSnapshot["node1"]
	require.NotNil(t, storedResources)
	assert.Len(t, storedResources.Listeners, 1)
	assert.Contains(t, storedResources.Listeners, "new-listener")
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
	c.resourcesInSnapshot["node1"] = resources

	result := c.GetAllResources("node1")
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

	result := c.GetAllResources("nonexistent")
	assert.Nil(t, result)
}

func TestClearSnapshot(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	c.resourcesInSnapshot["node1"] = resources

	snap, _ := c.GenerateSnapshot(resources, c.logger)
	_ = mock.SetSnapshot(context.Background(), "node1", snap)
	mock.setSnapshotCalls = nil // reset

	c.ClearSnapshot("node1")

	// Verify ClearSnapshot was called on the mock
	require.Len(t, mock.clearSnapshotCalls, 1)
	assert.Equal(t, "node1", mock.clearSnapshotCalls[0])

	// Verify resourcesInSnapshot was reset to empty
	stored := c.resourcesInSnapshot["node1"]
	require.NotNil(t, stored)
	assert.Empty(t, stored.Listeners)
	assert.Empty(t, stored.Clusters)
}

func TestGenerateSnapshot_WithAllResourceTypes(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.Endpoints["cluster1"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}
	resources.Clusters["cluster1"] = &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	}
	resources.Listeners["listener1"] = &envoy_config_listener.Listener{Name: "listener1"}
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}

	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)
	require.NotNil(t, snap)

	assert.Len(t, snap.GetResources(envoy_resource.ListenerType), 1)
	assert.Len(t, snap.GetResources(envoy_resource.ClusterType), 1)
	assert.Empty(t, snap.GetResources(envoy_resource.RouteType))
	assert.Len(t, snap.GetResources(envoy_resource.EndpointType), 1)
	assert.Len(t, snap.GetResources(envoy_resource.SecretType), 1)
}

func TestUpdateSnapshot_StoresNetworkPoliciesWhenTypeChanged(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil}, nil)
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	policies := mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL)
	require.Contains(t, policies, "np1")
	assert.Equal(t, resources.NetworkPolicies["np1"], policies["np1"])
}

func TestUpdateSnapshot_ClearsNetworkPoliciesWhenTypeChangedToEmpty(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil}, nil)
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	assert.Empty(t, mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL))
}

func TestUpdateSnapshot_StoresNetworkPoliciesWithoutTypeChange(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	resources.NetworkPolicies["np1"] = policy
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)

	err = c.UpdateSnapshot(context.Background(), "node1", snap, nil, nil, nil)
	require.NoError(t, err)

	require.Len(t, mock.setSnapshotCalls, 1)
	policies := mock.setSnapshotCalls[0].snapshot.GetResources(NetworkPolicyTypeURL)
	require.Contains(t, policies, "np1")
	assert.Equal(t, policy, policies["np1"])
}

func TestUpdateSnapshot_RegistersNetworkPolicyCompletionForPolicyChange(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.NetworkPolicies["np1"] = &cilium.NetworkPolicy{EndpointId: 1}
	snap, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)

	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), "node1", snap, wg,
		map[string]func(error){NetworkPolicyTypeURL: nil}, nil)
	require.NoError(t, err)

	assert.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	c.completionCbs.CancelPendingCompletions(NetworkPolicyTypeURL)
}

func TestUpdateSnapshot_CompletesAlreadyAckedNetworkPolicyVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	const nodeID = "node1"
	_, snap := networkPolicySnapshot(t, c, 1)

	err := c.UpdateSnapshot(context.Background(), nodeID, snap, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil}, nil)
	require.NoError(t, err)
	ackNetworkPolicyVersion(t, c, nodeID, snap.GetVersion(NetworkPolicyTypeURL))

	var callbackErrs []error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), nodeID, snap, wg,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			callbackErrs = append(callbackErrs, err)
		}}, nil)
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wg.Wait())
	require.Len(t, callbackErrs, 1)
	assert.NoError(t, callbackErrs[0])
}

func TestUpdateSnapshot_CompletesAlreadyAckedListenerVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	const nodeID = "node1"
	_, snap := listenerSnapshot(t, c, "listener1")

	err := c.UpdateSnapshot(context.Background(), nodeID, snap, nil, nil, nil)
	require.NoError(t, err)
	ackListenerVersion(t, c, nodeID, snap.GetVersion(envoy_resource.ListenerType))

	var callbackErrs []error
	wg := completion.NewWaitGroup(context.Background())
	defer wg.Cancel()

	err = c.UpdateSnapshot(context.Background(), nodeID, snap, wg,
		map[string]func(error){envoy_resource.ListenerType: func(err error) {
			callbackErrs = append(callbackErrs, err)
		}}, nil)
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wg.Wait())
	require.Len(t, callbackErrs, 1)
	assert.NoError(t, callbackErrs[0])
}

func TestUpdateSnapshot_CompletesUnsentCoalescedNetworkPolicyUpdates(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	const nodeID = "node1"
	_, snapA := networkPolicySnapshot(t, c, 1)
	_, snapB := networkPolicySnapshot(t, c, 2)
	require.NotEqual(t, snapA.GetVersion(NetworkPolicyTypeURL), snapB.GetVersion(NetworkPolicyTypeURL))

	err := c.UpdateSnapshot(context.Background(), nodeID, snapA, nil,
		map[string]func(error){NetworkPolicyTypeURL: nil}, nil)
	require.NoError(t, err)
	ackNetworkPolicyVersion(t, c, nodeID, snapA.GetVersion(NetworkPolicyTypeURL))

	var bCallbackErrs []error
	wgB := completion.NewWaitGroup(context.Background())
	defer wgB.Cancel()
	err = c.UpdateSnapshot(context.Background(), nodeID, snapB, wgB,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			bCallbackErrs = append(bCallbackErrs, err)
		}}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	var aCallbackErrs []error
	wgA := completion.NewWaitGroup(context.Background())
	defer wgA.Cancel()
	err = c.UpdateSnapshot(context.Background(), nodeID, snapA, wgA,
		map[string]func(error){NetworkPolicyTypeURL: func(err error) {
			aCallbackErrs = append(aCallbackErrs, err)
		}}, nil)
	require.NoError(t, err)

	assert.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA.Wait())
	require.Len(t, bCallbackErrs, 1)
	assert.NoError(t, bCallbackErrs[0])
	require.Len(t, aCallbackErrs, 1)
	assert.NoError(t, aCallbackErrs[0])
}

// --- GetVersion ---

func TestGetVersion_DifferentResourcesProduceDifferentVersions(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l2"] = &envoy_config_listener.Listener{Name: "l2"}

	v1 := c.GetVersion(res1)
	v2 := c.GetVersion(res2)

	assert.NotEmpty(t, v1)
	assert.NotEmpty(t, v2)
	assert.NotEqual(t, v1, v2)
}

func TestGetVersion_SameResourcesProduceSameVersion(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	v1 := c.GetVersion(res1)
	v2 := c.GetVersion(res2)

	assert.Equal(t, v1, v2)
}

// --- AreDifferentSnapshots ---

func TestAreDifferentSnapshots_Identical(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	snap1, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)
	snap2, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)

	assert.False(t, c.AreDifferentSnapshots(snap1, snap2))
}

func TestAreDifferentSnapshots_Different(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	res1 := emptyResources()
	res1.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}

	res2 := emptyResources()
	res2.Listeners["l2"] = &envoy_config_listener.Listener{Name: "l2"}

	snap1, err := c.GenerateSnapshot(res1, c.logger)
	require.NoError(t, err)
	snap2, err := c.GenerateSnapshot(res2, c.logger)
	require.NoError(t, err)

	assert.True(t, c.AreDifferentSnapshots(snap1, snap2))
}

// --- CreateWatch ---

func TestCreateWatch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	respChan := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{TypeUrl: envoy_resource.ListenerType}, nil, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)

	assert.Equal(t, 1, mock.createWatchCalls)
}

func TestCreateWatch_IgnoresEmptySecretSubscription(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := NewCache(logger)
	resources := emptyResources()
	resources.Secrets["secret1"] = &envoy_config_tls.Secret{Name: "secret1"}

	snap, err := c.GenerateSnapshot(resources, logger)
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
	c := newTestCacheWithHasher(mock)

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
	c := newTestCacheWithHasher(mock)
	ctx := context.Background()

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	resources.Clusters["c1"] = &envoy_config_cluster.Cluster{Name: "c1"}

	snap, err := c.GenerateSnapshot(resources, c.logger)
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

	c.SetResources("node1", resources)

	result := c.GetAllResources("node1")
	require.NotNil(t, result)
	assert.Contains(t, result.Listeners, "l1")
	assert.Contains(t, result.Routes, "r1")
	assert.Contains(t, result.Secrets, "s1")
}

// --- Integration-style: ClearSnapshot resets and delegates ---

func TestClearSnapshot_ResetsResourcesAndDelegates(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	c.resourcesInSnapshot["node1"] = resources

	snap, _ := c.GenerateSnapshot(resources, c.logger)
	_ = mock.SetSnapshot(context.Background(), "node1", snap)
	mock.setSnapshotCalls = nil

	c.ClearSnapshot("node1")

	// ClearSnapshot on the mock should have been called
	require.Len(t, mock.clearSnapshotCalls, 1)
	assert.Equal(t, "node1", mock.clearSnapshotCalls[0])

	// Resources should be reset to empty
	stored := c.resourcesInSnapshot["node1"]
	require.NotNil(t, stored)
	assert.Empty(t, stored.Listeners)
}

// --- GenerateSnapshot versions are deterministic ---

func TestGenerateSnapshot_VersionIsDeterministic(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCacheWithHasher(mock)

	resources := emptyResources()
	resources.Listeners["l1"] = &envoy_config_listener.Listener{Name: "l1"}
	resources.Clusters["c1"] = &envoy_config_cluster.Cluster{Name: "c1"}

	snap1, err := c.GenerateSnapshot(resources, c.logger)
	require.NoError(t, err)
	snap2, err := c.GenerateSnapshot(resources, c.logger)
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
	c := newTestCacheWithHasher(mock)

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

	snap, err := c.GenerateSnapshot(resources, c.logger)
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
	c.SetResources("node1", resources)

	// SetResources should only update resourcesInSnapshot, not call the underlying snapshot cache
	assert.Empty(t, mock.setSnapshotCalls)
	assert.Empty(t, mock.getSnapshotCalls)
	assert.Empty(t, mock.clearSnapshotCalls)
}

func TestGetAllResources_DoesNotCallSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newTestCache(mock)

	_ = c.GetAllResources("node1")

	assert.Empty(t, mock.setSnapshotCalls)
	assert.Empty(t, mock.getSnapshotCalls)
	assert.Empty(t, mock.clearSnapshotCalls)
}
