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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func (state *nodeState) requireNoRollbackOwners(t *testing.T) {
	t.Helper()
	for typeURL := range typeurl.Indices() {
		require.Nil(t, state.typeStates[typeURL].rollbacks.owners)
	}
}

func (state *nodeState) requireNoUnsentRollbacks(t *testing.T, msgAndArgs ...any) {
	t.Helper()
	for typeURL := range typeurl.Indices() {
		require.Nil(t, state.typeStates[typeURL].rollbacks.unsent, msgAndArgs...)
	}
}

func TestPreparedResourceRevertsCarryTargetEntries(t *testing.T) {
	for _, mode := range []string{"caller", "response"} {
		t.Run(mode, func(t *testing.T) {
			targets := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 1}, revision: callbacks.Generation(3).Revision(), transaction: callbacks.Generation(3).TransactionID()},
				"removed":    {resource: &cilium.NetworkPolicy{EndpointId: 2}, revision: callbacks.Generation(5).Revision(), transaction: callbacks.Generation(5).TransactionID()},
				"added":      {},
				"tombstone":  {revision: callbacks.Generation(2).Revision(), transaction: callbacks.Generation(2).TransactionID()},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 3}, revision: callbacks.Generation(4).Revision(), transaction: callbacks.Generation(4).TransactionID()},
			}
			current := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 10}, revision: callbacks.Generation(12).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"removed":    {revision: callbacks.Generation(10).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"added":      {resource: &cilium.NetworkPolicy{EndpointId: 11}, revision: callbacks.Generation(10).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"tombstone":  {resource: &cilium.NetworkPolicy{EndpointId: 12}, revision: callbacks.Generation(10).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 13}, revision: callbacks.Generation(11).Revision(), transaction: callbacks.Generation(11).TransactionID()},
			}
			state := &nodeState{}
			state.resources[typeurl.NetworkPolicy] = maps.Clone(current)
			var changes resourceChanges
			if mode == "caller" {
				var inverse resources
				inverse.entries[typeurl.NetworkPolicy] = targets
				changes = state.rollbacks.resourceRevertInverse(state, callbacks.Generation(10).TransactionID(), inverse)
			} else {
				var rollback rollbackResources
				rollback[typeurl.NetworkPolicy] = make(map[string]rollbackEntry)
				for name, entry := range targets {
					rollback[typeurl.NetworkPolicy][name] = rollbackEntry{previous: entry, expectedTransaction: callbacks.Generation(10).TransactionID()}
				}
				changes = rollback.resourceRevert(state, typeurl.NetworkPolicy, set.Set[callbacks.TransactionID]{})
			}
			require.Len(t, changes.more, 3)
			require.Equal(t, current, state.resourceEntries(typeurl.NetworkPolicy), "preparation must not mutate entries")
			state.commitResourceMutation(changes, 12)
			entries := state.resourceEntries(typeurl.NetworkPolicy)
			for name, target := range targets {
				if name == "superseded" {
					require.Equal(t, current[name], entries[name], "a newer API transaction must not be reverted")
				} else {
					require.Equal(t, target, entries[name], "restore the complete original entry for %s", name)
				}
			}
			require.NotContains(t, entries, "added", "transaction zero must restore absence, not create a tombstone")
			require.Contains(t, entries, "tombstone", "a nonzero removal transaction must survive restoration")
		})
	}
}

func TestAcceptedRemovalsReleaseTombstones(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	const resources = 100

	for id := range resources {
		name := strconv.Itoa(id)
		rollback, err := c.ApplyResourceWithRollback(
			t.Context(), "node1", typeurl.NetworkPolicy,
			name, &cilium.NetworkPolicy{EndpointId: uint64(id)}, nil, nil)

		require.NoError(t, err)
		rollback.Finalize()
	}
	initial := requestSnapshotForTest(t, c, "node1", typeurl.NetworkPolicy)
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	for id := range resources {
		name := strconv.Itoa(id)
		rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicy, name, nil, nil, nil)
		require.NoError(t, err)
		rollback.Finalize()
	}
	removed := requestSnapshotForTest(t, c, "node1", typeurl.NetworkPolicy)
	ackNetworkPolicyVersion(t, c, "node1", removed.GetVersion(NetworkPolicyTypeURL))
	c.completionCbs.OnStreamClosed(1, &envoy_config_core.Node{Id: "node1"})

	state := c.getNodeState("node1")
	require.NotNil(t, state, "known nodes remain after all resources and streams are gone")
	require.Empty(t, state.resources[typeurl.NetworkPolicy],
		"finalized removals must not leave generation tombstones behind")
	state.requireNoRollbackOwners(t)
	state.requireNoUnsentRollbacks(t)
}

func TestAcceptedRemovalReleasesResponseTombstone(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	c.setTestNodeEpochs("node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	rollback, err := c.ApplyResourceWithRollback(
		ctx, "node1", typeurl.NetworkPolicy,
		"policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	rollback.Finalize()
	initial := requestSnapshotForTest(t, c, "node1", typeurl.NetworkPolicy)
	ackNetworkPolicyVersion(t, c, "node1", initial.GetVersion(NetworkPolicyTypeURL))

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initial.GetVersion(NetworkPolicyTypeURL),
	}
	responses := make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, true)
	subscription.SetReturnedResources(map[string]string{"policy": initial.GetVersion(NetworkPolicyTypeURL)})
	cancelWatch, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)

	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", nil, wg, nil)
	require.NoError(t, err)
	rollback.Finalize()
	tombstone := c.getNodeState("node1").resources[typeurl.NetworkPolicy]["policy"]
	require.Nil(t, tombstone.resource)
	require.NotEmpty(t, c.getNodeState("node1").typeStates[typeurl.NetworkPolicy].rollbacks.owners,
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
	require.Empty(t, c.getNodeState("node1").resources[typeurl.NetworkPolicy])
	c.getNodeState("node1").requireNoRollbackOwners(t)
	c.completionCbs.OnStreamClosed(1, request.Node)
	state := c.getNodeState("node1")
	require.NotNil(t, state)
	require.Empty(t, state.resources[typeurl.NetworkPolicy], "the accepted removal releases its tombstone")
	state.requireNoRollbackOwners(t)
	state.requireNoUnsentRollbacks(t)
}

func TestPublishedUnsentRollbackDropsAddedThenRemovedEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	c.setTestNodeEpochs(nodeID, 1)

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
	}, stream.NewSotwSubscription(nil, true), clusterResponses)
	require.NoError(t, err)
	response := <-clusterResponses
	cancel()
	acknowledgeResponse(t, c, 1, response, "initial-cluster")
	require.NotNil(t, c.getNodeState(nodeID).typeStates[typeurl.Endpoint].rollbacks.unsent,
		"EDS rollback remains unsent without an EDS subscription")

	previous := mustSnapshot(t, c, nodeID)
	clusterResponses = make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, true)
	subscription.SetReturnedResources(response.GetReturnedResources())
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ClusterType,
		VersionInfo: previous.GetVersion(envoy_resource.ClusterType),
	}, subscription, clusterResponses)
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

	state := c.getNodeState(nodeID)
	require.NotNil(t, state)
	state.requireNoUnsentRollbacks(t, "the net-zero EDS rollback must be discarded")
	state.requireNoRollbackOwners(t)
	require.Empty(t, state.resources[typeurl.Endpoint])
}

func TestPublishedUnsentRollbackCoalescesUntilResponse(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	c.setTestNodeEpochs(nodeID, 1)

	baselineListener := &envoy_config_listener.Listener{Name: "listener-0"}
	baselinePolicy := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", baselinePolicy, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": baselineListener},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	listenerResponses := make(chan cache.Response, 1)
	listenerSubscription := stream.NewSotwSubscription(nil, true)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
	}, listenerSubscription, listenerResponses)
	require.NoError(t, err)
	initialResponse := <-listenerResponses
	listenerSubscription.SetReturnedResources(initialResponse.GetReturnedResources())
	cancel()
	acknowledgeResponse(t, c, 1, initialResponse, "initial-listener")
	baselineSnapshot := mustSnapshot(t, c, nodeID)
	acceptPublishedSnapshotVersions(t, c, 1, node, baselineSnapshot)
	c.getNodeState(nodeID).requireNoUnsentRollbacks(t)

	var policyRollback *rollbackLifecycle
	var latestListener *envoy_config_listener.Listener
	for update := uint64(2); update <= 9; update++ {
		previousSnapshot := mustSnapshot(t, c, nodeID)
		listenerResponses = make(chan cache.Response, 1)
		cancel, err = c.CreateWatch(&cache.Request{
			Node: node, TypeUrl: envoy_resource.ListenerType,
			VersionInfo: previousSnapshot.GetVersion(envoy_resource.ListenerType),
		}, listenerSubscription, listenerResponses)
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
		listenerSubscription.SetReturnedResources(response.GetReturnedResources())
		cancel()
		acknowledgeResponse(t, c, 1, response, fmt.Sprintf("listener-%d", update))

		current := c.getNodeState(nodeID).typeStates[typeurl.NetworkPolicy].rollbacks.unsent
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
	owners := c.getNodeState(nodeID).typeStates[typeurl.NetworkPolicy].rollbacks.owners
	require.Len(t, owners, 1,
		"the final unsent removal must retain exactly one coalesced tombstone owner")

	latestSnapshot := mustSnapshot(t, c, nodeID)
	policyResponses := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: NetworkPolicyTypeURL,
		VersionInfo: baselineSnapshot.GetVersion(NetworkPolicyTypeURL),
	}, stream.NewSotwSubscription(nil, true), policyResponses)
	require.NoError(t, err)
	policyResponse := <-policyResponses
	cancel()
	require.Equal(t, latestSnapshot.GetVersion(NetworkPolicyTypeURL), policyResponse.GetResponseVersion())
	c.getNodeState(nodeID).requireNoUnsentRollbacks(t,
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

	listener := c.GetResource(nodeID, typeurl.Listener, "listener")
	require.NotNil(t, listener)
	require.Same(t, latestListener, listener,
		"a NetworkPolicy NACK must not revert Listener updates from the same transaction")
	policy := c.GetResource(nodeID, typeurl.NetworkPolicy, "policy")
	require.NotNil(t, policy)
	require.Same(t, baselinePolicy, policy)
	c.getNodeState(nodeID).requireNoRollbackOwners(t)
}

func TestClonePendingRollbacksKeepsIndependentRecoveryState(t *testing.T) {
	var pending typeurl.Map[rollbackResources]
	var rollback rollbackResources
	rollback[typeurl.Listener] = map[string]rollbackEntry{"listener": {expectedTransaction: callbacks.Generation(1).TransactionID()}}
	rollback[typeurl.Route] = map[string]rollbackEntry{"route": {expectedTransaction: callbacks.Generation(1).TransactionID()}}
	entry := rollback[typeurl.Route]["route"]
	entry.transactions.Insert(callbacks.Generation(1).TransactionID())
	entry.transactions.Insert(callbacks.Generation(2).TransactionID()) // Exercise a map-backed membership set.
	rollback[typeurl.Route]["route"] = entry
	pending.Set(typeurl.Listener, rollback)

	cloned := clonePendingRollbacks(pending)
	clonedRollback, _ := cloned.Get(typeurl.Listener)
	entry = clonedRollback[typeurl.Route]["route"]
	entry.transactions.Insert(callbacks.Generation(3).TransactionID())
	clonedRollback[typeurl.Route]["route"] = entry
	originalRollback, _ := pending.Get(typeurl.Listener)
	require.False(t, originalRollback[typeurl.Route]["route"].transactions.Has(callbacks.Generation(3).TransactionID()), "failed publication must not change the prior recovery relationships")
	delete(clonedRollback[typeurl.Route], "route")

	require.Contains(t, originalRollback[typeurl.Route], "route")
}

func TestPendingRollbackDropsAddedThenRemovedEndpoint(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan"}

	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "orphan", endpoint, nil, nil)
	require.NoError(t, err)
	pending, exists := c.getNodeState(nodeID).pendingPublication.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists)
	require.Len(t, pending[typeurl.Endpoint], 1)

	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "orphan", nil, nil, nil)
	require.NoError(t, err)
	state := c.getNodeState(nodeID)
	require.NotNil(t, state)
	pending, exists = state.pendingPublication.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists, "the pending type still needs completion finalization")
	require.True(t, pending.empty(), "a never-sent add/remove has no rollback target")
	state.requireNoRollbackOwners(t)
	require.Empty(t, state.resources[typeurl.Endpoint], "the removal tombstone must be released")
}

func TestPendingRollbackRetainsRemovedEndpointForTransactionSibling(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	original := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}
	c.getNodeState(nodeID).seedResource(typeurl.Endpoint, "endpoint", original)

	changed := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", changed, nil, nil)
	require.NoError(t, err)
	// EDS omission alone cannot be NACKed. A changed Cluster in the same API
	// transaction can reject the removal, so its response rollback must retain
	// the Endpoint's original value across the coalesced changes.
	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Removed: xds.Resources{Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"endpoint": nil}},
		Upserted: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster": {Name: "cluster"},
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)

	state := c.getNodeState(nodeID)
	pending, exists := state.pendingPublication.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists)
	require.Same(t, original, pending[typeurl.Endpoint]["endpoint"].previous.resource,
		"a removal is not a net no-op when the resource existed before the unsent changes")
}

func TestPendingRollbackDropsSemanticEndpointABA(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	original := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}
	c.getNodeState(nodeID).seedResource(typeurl.Endpoint, "endpoint", original)

	changed := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint", changed, nil, nil)
	require.NoError(t, err)
	err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "endpoint",
		&envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}, nil, nil)
	require.NoError(t, err)

	pending, exists := c.getNodeState(nodeID).pendingPublication.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists, "the pending type still needs completion finalization")
	require.True(t, pending.empty(),
		"a distinct protobuf pointer with the original contents needs no rollback")
}

func TestCallerRevertIsTerminalAfterStrictConsistencyFailure(t *testing.T) {
	var logs strings.Builder
	c := NewCache(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), true, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	listener := &envoy_config_listener.Listener{
		Name: "l1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t,
					&envoy_config_http.HttpConnectionManager{RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
						Rds: &envoy_config_http.Rds{RouteConfigName: "r1"},
					}})},
			}},
		}},
	}
	route := &envoy_config_route.RouteConfiguration{Name: "r1"}
	first, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"l1": listener},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": route},
	}}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	newRoute := &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
	second, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, "r1", newRoute, nil, nil)
	require.NoError(t, err)

	// A's revert can remove l1, but its transaction fence skips B's r1.
	// Incremental validation rejects the orphan route before committing or
	// publishing anything. The caller receives the failure, but its lifecycle
	// is terminal: it must release its inverse rather than require a retry.
	require.ErrorContains(t, first.Revert(), "strict ADS cache mutation is inconsistent: orphan RDS resource \"r1\"")
	current := c.GetResource(nodeID, typeurl.Listener, "l1")
	require.NotNil(t, current)
	require.Same(t, listener, current)
	current = c.GetResource(nodeID, typeurl.Route, "r1")
	require.NotNil(t, current)
	require.Same(t, newRoute, current)

	// Undo B first, restoring r1's original transaction. Retrying A would now
	// succeed if its inverse had survived, but duplicate terminal operations
	// must only warn and leave both resources unchanged.
	require.NoError(t, second.Revert())
	generation := c.resourceGeneration
	logs.Reset()
	require.NoError(t, first.Revert())
	require.Contains(t, logs.String(), "level=WARN")
	require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
	logs.Reset()
	first.Finalize()
	require.Contains(t, logs.String(), "level=WARN")
	require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
	require.Equal(t, generation, c.resourceGeneration)
	current = c.GetResource(nodeID, typeurl.Listener, "l1")
	require.NotNil(t, current)
	require.Same(t, listener, current)
	current = c.GetResource(nodeID, typeurl.Route, "r1")
	require.NotNil(t, current)
	require.Same(t, route, current)
}

func TestFailedCallerRevertReleasesRemovalTombstone(t *testing.T) {
	for _, api := range []string{"ApplyResourceWithRollback", "ApplyResourcesWithRollback"} {
		t.Run(api, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(mock)
			var logs strings.Builder
			c.logger = slog.New(slog.NewTextHandler(&logs, nil))
			const nodeID = "node1"
			// The mock keeps the watch open, forcing reverts to publish so
			// the injected transport error occurs during the caller's attempt.
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.RouteType,
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
			route := &envoy_config_route.RouteConfiguration{Name: "removed"}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Route, route.Name, route, nil, nil))
			acceptPublishedSnapshotVersions(t, c, 1, &envoy_config_core.Node{Id: nodeID}, mustSnapshot(t, c, nodeID))

			var rollback Rollback
			if api == "ApplyResourceWithRollback" {
				rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, route.Name, nil, nil, nil)
			} else {
				rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID,
					ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{route.Name: nil}}},
					nil, TypeURLCallbacks{})
			}
			require.NoError(t, err)
			require.NotNil(t, rollback)
			state := c.getNodeState(nodeID)
			require.Contains(t, state.resourceEntries(typeurl.Route), route.Name,
				"the caller owns the removal tombstone; SotW cannot NACK this independent RDS omission")
			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			require.ErrorIs(t, rollback.Revert(), publicationErr)
			require.Empty(t, state.resourceEntries(typeurl.Route), "the terminal caller must release its last tombstone ownership")
			state.requireNoRollbackOwners(t)

			mock.setSnapshotErr = nil
			generation := c.resourceGeneration
			logs.Reset()
			require.NoError(t, rollback.Revert())
			require.Contains(t, logs.String(), "level=WARN")
			require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
			logs.Reset()
			rollback.Finalize()
			require.Contains(t, logs.String(), "level=WARN")
			require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
			require.Equal(t, generation, c.resourceGeneration)
			require.Nil(t, c.GetResource(nodeID, typeurl.Route, route.Name), "a duplicate caller revert must not restore the removed resource")
		})
	}
}

func TestCallerRevertAfterCancellation(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(mock)
	const nodeID = "node1"
	// The mock leaves this watch open so the revert publishes synchronously.
	// Otherwise it only commits unpublished compensation and never exercises delivery
	// with the canceled caller's context.
	cancelWatch, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: NetworkPolicyTypeURL,
	}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	cancel()

	publications := len(mock.setSnapshotCalls)
	require.NoError(t, rollback.Revert())
	require.Len(t, mock.setSnapshotCalls, publications+1)
	require.Nil(t, c.GetResource(nodeID, typeurl.NetworkPolicy, "policy"))
	// The publication context must still permit delivering the compensating
	// response. The expired mutation context must not cancel that delivery.
	require.NoError(t, mock.setSnapshotCalls[len(mock.setSnapshotCalls)-1].Err())
}

func TestNetworkPolicyWaitCompletesWhenLastListenerIsReverted(t *testing.T) {
	observer := &testNPDSListenerObserver{
		nodeID: "node1",
		matches: func(listener *envoy_config_listener.Listener) bool {
			return listener.GetName() == "npds-listener"
		},
	}
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false,
		WithListenerObserver(observer), WithNodeIDs("node1")).(*cacheImpl)
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
	require.NotNil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"))
}

func TestApplyResourcesCoalescesPendingRollbackState(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	const updates = 1000

	for endpointID := uint64(1); endpointID <= updates; endpointID++ {
		err := c.ApplyResource(
			t.Context(), "node1", typeurl.NetworkPolicy,
			"policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil, nil)

		require.NoError(t, err)
	}

	state := c.getNodeState("node1")
	require.NotNil(t, state)
	require.NotNil(t, state.pendingPublication)
	require.Equal(t, 1, state.pendingPublication.rollbacks.Len())
	policyRollback, exists := state.pendingPublication.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.Len(t, policyRollback[typeurl.NetworkPolicy], 1,
		"pending publication must retain one inverse per changed resource, not one per update")
	state.requireNoRollbackOwners(t)
}

func TestFirstUntrackedSnapshotNACKRevertsColdStartResources(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
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

	state := c.getNodeState("node1")
	require.NotNil(t, state.pendingPublication)
	policyRollback, exists := state.pendingPublication.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	coldStartRollback := policyRollback[typeurl.NetworkPolicy]
	require.Len(t, coldStartRollback, 2)
	for _, rollback := range coldStartRollback {
		require.Nil(t, rollback.previous.resource,
			"cold-start rollback must not retain a protobuf that did not exist")
		require.Zero(t, rollback.previous.revision)
	}

	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: NetworkPolicyTypeURL,
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
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

func TestNACKedRemovalRestoresResourceAfterCallerCompletion(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	c.setTestNodeEpochs("node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
	initial := requestSnapshotForTest(t, c, "node1", typeurl.NetworkPolicy)
	initialVersion := initial.GetVersion(NetworkPolicyTypeURL)
	ackNetworkPolicyVersion(t, c, "node1", initialVersion)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initialVersion,
	}
	responses := make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, true)
	// The mock has already received the initial policy; this is an ACK watch.
	subscription.SetReturnedResources(map[string]string{"policy": initialVersion})
	cancelWatch, err := c.CreateWatch(request, subscription, responses)
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
	require.Same(t, policy, c.getNodeState("node1").resources[typeurl.NetworkPolicy]["policy"].resource,
		"completing the caller early must not make a sent removal irreversible")
}

func TestNACKRevertsAfterWaitCancellationAndCallerFinalize(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
	c.setTestNodeEpochs("node1", 1)
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policyA, nil, nil)
	require.NoError(t, err)
	rollback.Finalize()
	initial := requestSnapshotForTest(t, c, "node1", typeurl.NetworkPolicy)
	initialVersion := initial.GetVersion(NetworkPolicyTypeURL)
	ackNetworkPolicyVersion(t, c, "node1", initialVersion)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: initialVersion,
	}
	responses := make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, true)
	// The mock has already received the initial policy; this is an ACK watch.
	subscription.SetReturnedResources(map[string]string{"policy": initialVersion})
	cancelWatch, err := c.CreateWatch(request, subscription, responses)
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
	require.Same(t, policyB, c.getNodeState("node1").resources[typeurl.NetworkPolicy]["policy"].resource)

	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       NetworkPolicyTypeURL,
		VersionInfo:   initialVersion,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected after timeout"},
	}))
	require.Same(t, policyA, c.getNodeState("node1").resources[typeurl.NetworkPolicy]["policy"].resource,
		"caller timeout and finalization must not disable the response-owned NACK revert")
}

func TestResourceUpdateRevertibleIsNoOpAfterFirstCall(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node1")).(*cacheImpl)
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
	policy := c.getNodeState("node1").resources[typeurl.NetworkPolicy]["policy"].resource.(*cilium.NetworkPolicy)
	require.Equal(t, uint64(2), policy.EndpointId)
}

func TestApplyResourcesOwnsGlobalGenerationAndPerNodeReverts(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node-a", "node-b")).(*cacheImpl)
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
	require.Equal(t, callbacks.Generation(4), c.resourceGeneration)
	require.Equal(t, callbacks.Generation(3), c.getNodeState("node-a").resourceGeneration)
	require.Equal(t, callbacks.Generation(4), c.getNodeState("node-b").resourceGeneration)

	require.NoError(t, revertNodeA.Revert())
	require.Equal(t, callbacks.Generation(5), c.resourceGeneration)
	require.Equal(t, callbacks.Generation(5), c.getNodeState("node-a").resourceGeneration)
	require.Equal(t, callbacks.Generation(4), c.getNodeState("node-b").resourceGeneration)
	entry := c.getNodeState("node-a").resources[typeurl.NetworkPolicy]["policy"]
	require.Equal(t, callbacks.Generation(5).Revision(), entry.revision, "reverting advances the named value's revision")
	require.Equal(t, callbacks.Generation(1).TransactionID(), entry.transaction, "reverting restores the value's originating API transaction")
	resource := c.GetResource("node-a", typeurl.NetworkPolicy, "policy")
	require.NotNil(t, resource)
	require.Equal(t, uint64(1), resource.(*cilium.NetworkPolicy).EndpointId)
}

func TestApplyResourcesRevertOnlyRestoresOwnedResourceVersions(t *testing.T) {
	newCache := func(t *testing.T) *cacheImpl {
		t.Helper()
		return NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node-a")).(*cacheImpl)
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
			subscription := stream.NewSotwSubscription(nil, true)
			responses := make(chan cache.Response, 1)
			// Let a real watch finalize the pending baseline before accepting it.
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
				"the same revert must still restore resources untouched by newer API transactions")
			entries := c.getNodeState(node.Id).resources[typeurl.Route]
			require.Equal(t, callbacks.Generation(3).Revision(), entries["newer"].revision)
			require.Equal(t, callbacks.Generation(3).TransactionID(), entries["newer"].transaction)
			require.Equal(t, callbacks.Generation(4).Revision(), entries["unchanged"].revision)
			require.Equal(t, callbacks.Generation(1).TransactionID(), entries["unchanged"].transaction)
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
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), false, WithNodeIDs("node-a")).(*cacheImpl)
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
		actual := c.GetResource("node-a", resource.typeURL, "newer")
		require.NotNil(t, actual)
		require.Same(t, resource.newer, actual)
		actual = c.GetResource("node-a", resource.typeURL, "unchanged")
		require.NotNil(t, actual)
		require.Same(t, resource.older, actual)
	}
}

func TestResponseRevertRemovesSupersededDependentRoute(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})), true, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	listener := strictTestListener(t, "l1", "r1")
	route := &envoy_config_route.RouteConfiguration{Name: "r1"}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	var waits TypeURLCallbacks
	waits.Set(typeurl.Listener, nil)
	require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"l1": listener},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": route},
	}}, wg, waits))
	newRoute := &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
	second, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, "r1", newRoute, nil, nil)
	require.NoError(t, err)

	request := &discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.ListenerType}
	// Mutations remain unpublished until a watch can consume them. Use the actual
	// response and its captured generation rather than assuming eager publication.
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	response := <-responses
	discoveryResponse, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	discoveryResponse.Nonce = "rejected-listeners"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, request, discoveryResponse)
	// B's route edit depends on the Listener introduced by A. Rejecting that
	// Listener must also remove the newer Route, rather than skip it and fail
	// validation with an orphan. Caller waits still receive the original NACK.
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node: node, TypeUrl: envoy_resource.ListenerType, ResponseNonce: "rejected-listeners",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))
	require.ErrorContains(t, wg.Wait(), "rejected listener")
	require.Nil(t, c.GetResource(nodeID, typeurl.Listener, "l1"))
	require.Nil(t, c.GetResource(nodeID, typeurl.Route, "r1"))

	// B's caller rollback is now superseded too: it must not resurrect r1 after
	// the response-driven rollback removed the parent and its dependent child.
	require.NoError(t, second.Revert())
	require.Nil(t, c.GetResource(nodeID, typeurl.Listener, "l1"))
	require.Nil(t, c.GetResource(nodeID, typeurl.Route, "r1"))

	// Finalize the pending compensation through the next LDS watch. No stream
	// restart or second NACK is needed to restore a consistent empty snapshot.
	cancelWatch, err = c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	response = <-responses
	discoveryResponse, err = response.GetDiscoveryResponse()
	require.NoError(t, err)
	require.Empty(t, discoveryResponse.GetResources())
	require.NoError(t, CheckSnapshotConsistency(mustSnapshot(t, c, nodeID)))
}

func TestApplyResourcesUnchangedListenerNACKRevertsDependentTransaction(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, routeACKed := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/route-acked=%t", strict, routeACKed), func(t *testing.T) {
				logger := hivetest.Logger(t)
				if strict {
					logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				}
				c := NewCache(logger, strict, WithNodeIDs("node1"))
				ctx, cancelContext := context.WithTimeout(t.Context(), 5*time.Second)
				t.Cleanup(cancelContext)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				watch := func(typeURL typeurl.Index, version string) cache.Response {
					t.Helper()
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeURL.URL(), VersionInfo: version},
						stream.NewSotwSubscription(nil, true), responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case response := <-responses:
						return response
					case <-ctx.Done():
						t.Fatal("no response for ", typeURL.URL())
						return nil
					}
				}

				// A introduces l1 and its route. Deliver LDS, but leave its ACK/NACK
				// outstanding while B updates the route using the identical listener.
				listener := strictTestListener(t, "l1", "r1")
				firstWG := completion.NewWaitGroup(ctx)
				t.Cleanup(firstWG.Cancel)
				var firstWaits TypeURLCallbacks
				firstWaits.Set(typeurl.Listener, nil)
				require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": listener},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": {Name: "r1"}},
				}}, firstWG, firstWaits))
				listenerResponse := watch(typeurl.Listener, "")
				rejected, err := listenerResponse.GetDiscoveryResponse()
				require.NoError(t, err)
				rejected.Nonce = "a-listener"
				c.GetCompletionCallbacks().OnStreamResponse(listenerResponse.GetContext(), 1, listenerResponse.GetRequest(), rejected)

				secondWG := completion.NewWaitGroup(ctx)
				t.Cleanup(secondWG.Cancel)
				listenerResult := make(chan error, 1)
				routeResult := make(chan error, 1)
				var secondWaits TypeURLCallbacks
				secondWaits.Set(typeurl.Listener, func(err error) { listenerResult <- err })
				secondWaits.Set(typeurl.Route, func(err error) { routeResult <- err })
				newRoute := &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
				// This unrelated secret belongs only to B, so its removal below
				// proves that response rollback reverts B's whole transaction in
				// both ADS modes, not just A's structurally dependent route.
				secret := &envoy_config_tls.Secret{Name: "b-secret"}
				second, err := c.ApplyResourcesWithRollback(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": proto.Clone(listener).(*envoy_config_listener.Listener)},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": newRoute},
					Secrets:   map[string]*envoy_config_tls.Secret{secret.Name: secret},
				}}, secondWG, secondWaits)
				require.NoError(t, err)
				require.NotNil(t, second)
				current := c.GetResource(nodeID, typeurl.Listener, "l1")
				require.NotNil(t, current)
				require.Same(t, listener, current, "B must retain A's unchanged listener")

				routeResponse := watch(typeurl.Route, "")
				routeDiscoveryResponse, err := routeResponse.GetDiscoveryResponse()
				require.NoError(t, err)
				require.Len(t, routeDiscoveryResponse.Resources, 1)
				var deliveredRoute envoy_config_route.RouteConfiguration
				require.NoError(t, routeDiscoveryResponse.Resources[0].UnmarshalTo(&deliveredRoute))
				require.True(t, proto.Equal(newRoute, &deliveredRoute), "RDS must deliver B's route, not A's")
				if routeACKed {
					acknowledgeResponse(t, c.(*cacheImpl), 1, routeResponse, "b-route")
					select {
					case err := <-routeResult:
						require.NoError(t, err)
					default:
						t.Fatal("B's RDS wait did not receive its ACK")
					}
					// Response-owned recovery must also outlive early caller finalization.
					second.Finalize()
				} else {
					routeDiscoveryResponse.Nonce = "b-route"
					c.GetCompletionCallbacks().OnStreamResponse(routeResponse.GetContext(), 1, routeResponse.GetRequest(), routeDiscoveryResponse)
				}
				select {
				case err := <-listenerResult:
					t.Fatalf("B's unchanged listener completed before A's LDS outcome: %v", err)
				default:
				}

				// B's LDS wait is attached to A's response, not B's newer global
				// generation. Even an RDS ACK for B cannot turn A's LDS NACK into
				// success for B's enclosing transaction.
				require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: typeurl.Listener.URL(), ResponseNonce: rejected.Nonce,
					ErrorDetail: &status.Status{Message: "rejected A's listener"},
				}))
				require.ErrorContains(t, firstWG.Wait(), "rejected A's listener")
				select {
				case err := <-listenerResult:
					require.ErrorContains(t, err, "rejected A's listener")
				default:
					t.Fatal("B's unchanged listener wait did not receive A's NACK")
				}
				require.ErrorContains(t, secondWG.Wait(), "rejected A's listener")

				// The response-owned dependency must revert B's entire transaction,
				// including its independent Secret, before notifying either caller.
				for typeURL, name := range map[typeurl.Index]string{
					typeurl.Listener: "l1", typeurl.Route: "r1", typeurl.Secret: secret.Name,
				} {
					require.Nil(t, c.GetResource(nodeID, typeURL, name), "%s %s must be reverted", typeURL.URL(), name)
				}
				if !routeACKed {
					// The caller's failure path remains safe, but is no longer needed
					// to remove B's independent changes.
					require.NoError(t, second.Revert())
				}
				response := watch(typeurl.Listener, rejected.VersionInfo)
				rolledBack, err := response.GetDiscoveryResponse()
				require.NoError(t, err)
				require.Empty(t, rolledBack.Resources)
				snapshot, err := c.GetSnapshot(nodeID)
				require.NoError(t, err)
				require.NoError(t, CheckSnapshotConsistency(snapshot))
			})
		}
	}
}

func TestResponseNACKRejectsDependentTransactionWaitersAcrossTypeURLs(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, phase := range []string{"unpublished", "published-unsent", "in-flight"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, phase), func(t *testing.T) {
				logger := hivetest.Logger(t)
				if strict {
					logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				}
				c := NewCache(logger, strict, WithNodeIDs("node1")).(*cacheImpl)
				ctx, cancelContext := context.WithTimeout(t.Context(), 5*time.Second)
				t.Cleanup(cancelContext)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				watch := func(typeURL typeurl.Index) cache.Response {
					t.Helper()
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeURL.URL()},
						stream.NewSotwSubscription(nil, true), responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case response := <-responses:
						return response
					case <-ctx.Done():
						t.Fatal("no response for ", typeURL.URL())
						return nil
					}
				}
				publish := func(response cache.Response) string {
					t.Helper()
					rejected, err := response.GetDiscoveryResponse()
					require.NoError(t, err)
					rejected.Nonce = "a-cluster"
					c.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(), rejected)
					return rejected.Nonce
				}

				// A has no caller wait, but its response still owns rollback.
				cluster := &envoy_config_cluster.Cluster{Name: "cluster-bad"}
				require.NoError(t, c.ApplyResource(ctx, nodeID, typeurl.Cluster, cluster.Name, cluster, nil, nil))
				var nonce string
				switch phase {
				case "published-unsent":
					// An unrelated LDS request publishes A without delivering CDS.
					acknowledgeResponse(t, c, 1, watch(typeurl.Listener), "empty-listeners")
				case "in-flight":
					nonce = publish(watch(typeurl.Cluster))
				}

				// B reuses A's pending Cluster, but waits only on its new Secret.
				// A CDS waiter here would mask a stranded SDS waiter by failing
				// the enclosing WaitGroup through that other completion.
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				result := make(chan error, 1)
				var waits TypeURLCallbacks
				waits.Set(typeurl.Secret, func(err error) { result <- err })
				secret := &envoy_config_tls.Secret{Name: "bad-dependent"}
				require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
					Clusters: map[string]*envoy_config_cluster.Cluster{cluster.Name: proto.Clone(cluster).(*envoy_config_cluster.Cluster)},
					Secrets:  map[string]*envoy_config_tls.Secret{secret.Name: secret},
				}}, wg, waits))
				if nonce == "" {
					nonce = publish(watch(typeurl.Cluster))
				}
				select {
				case err := <-result:
					t.Fatalf("dependent SDS wait completed before CDS NACK: %v", err)
				default:
				}

				require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: typeurl.Cluster.URL(), ResponseNonce: nonce,
					ErrorDetail: &status.Status{Message: "rejected cluster-bad"},
				}))
				for typeURL, name := range map[typeurl.Index]string{
					typeurl.Cluster: cluster.Name, typeurl.Secret: secret.Name,
				} {
					require.Nil(t, c.GetResource(nodeID, typeURL, name), "%s %s must be reverted before the caller is notified", typeURL.URL(), name)
				}
				select {
				case err := <-result:
					require.ErrorContains(t, err, "rejected cluster-bad")
				default:
					t.Fatal("dependent SDS wait did not receive the CDS NACK")
				}
				require.ErrorContains(t, wg.Wait(), "rejected cluster-bad")
				require.Zero(t, c.GetCompletionCallbacks().PendingCompletionCount())
			})
		}
	}
}

func TestResponseRollbackRetainsTransitiveTransactionDependencies(t *testing.T) {
	for _, phase := range []string{"unpublished", "published-unsent", "in-flight", "resource-aba"} {
		for _, accepted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/accepted=%t", phase, accepted), func(t *testing.T) {
				c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs("node1")).(*cacheImpl)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				t.Cleanup(cancel)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				watch := func(typeURL typeurl.Index) cache.Response {
					t.Helper()
					request := &cache.Request{Node: node, TypeUrl: typeURL.URL()}
					if typeURL == typeurl.Secret {
						request.ResourceNames = []string{"b-secret", "c-secret"}
					}
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.GetResourceNames(), true), responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case response := <-responses:
						return response
					case <-ctx.Done():
						t.Fatal("no response for ", typeURL.URL())
						return nil
					}
				}
				listener := strictTestListener(t, "l1", "r1")
				route := &envoy_config_route.RouteConfiguration{Name: "r1"}
				require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": listener},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": route},
				}}, nil, TypeURLCallbacks{}))
				var listenerResponse cache.Response
				if phase == "published-unsent" {
					// RDS publishes A, but LDS has not produced a response yet.
					acknowledgeResponse(t, c, 1, watch(typeurl.Route), "initial-route")
				} else if phase == "in-flight" || phase == "resource-aba" {
					listenerResponse = watch(typeurl.Listener)
				}

				// No caller waits or rollback handles participate in this chain.
				// B depends on A's l1, while C depends only on B's Secret. ACKing
				// RDS and SDS cannot erase either dependency on the pending LDS.
				bSecret := &envoy_config_tls.Secret{Name: "b-secret"}
				newRoute := &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
				require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": proto.Clone(listener).(*envoy_config_listener.Listener)},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": newRoute},
					Secrets:   map[string]*envoy_config_tls.Secret{bSecret.Name: bSecret},
				}}, nil, TypeURLCallbacks{}))
				acknowledgeResponse(t, c, 1, watch(typeurl.Route), "b-route")
				acknowledgeResponse(t, c, 1, watch(typeurl.Secret), "b-secret")
				cSecret := &envoy_config_tls.Secret{Name: "c-secret"}
				third := xds.Resources{
					Secrets: map[string]*envoy_config_tls.Secret{
						bSecret.Name: proto.Clone(bSecret).(*envoy_config_tls.Secret),
						cSecret.Name: cSecret,
					},
				}
				if phase == "resource-aba" {
					// Returning r1 to A's protobuf creates a newer generation, but
					// that value still depends on A. C uses only this ABA value,
					// rather than the Secret which B originally introduced.
					require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
						Listeners: map[string]*envoy_config_listener.Listener{"l1": listener},
						Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": route},
					}}, nil, TypeURLCallbacks{}))
					acknowledgeResponse(t, c, 1, watch(typeurl.Route), "aba-route")
					delete(third.Secrets, bSecret.Name)
					third.Routes = map[string]*envoy_config_route.RouteConfiguration{"r1": route}
				}
				require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: third}, nil, TypeURLCallbacks{}))
				acknowledgeResponse(t, c, 1, watch(typeurl.Secret), "c-secret")
				if listenerResponse == nil {
					listenerResponse = watch(typeurl.Listener)
				}
				if accepted {
					acknowledgeResponse(t, c, 1, listenerResponse, "accepted-listener")
					for typeURL, name := range map[typeurl.Index]string{
						typeurl.Listener: "l1", typeurl.Route: "r1", typeurl.Secret: cSecret.Name,
					} {
						require.NotNil(t, c.GetResource(nodeID, typeURL, name), "%s %s must survive an ACK", typeURL.URL(), name)
					}
					require.NotNil(t, c.GetResource(nodeID, typeurl.Secret, bSecret.Name))
				} else {
					rejected, err := listenerResponse.GetDiscoveryResponse()
					require.NoError(t, err)
					rejected.Nonce = "rejected-listener"
					c.GetCompletionCallbacks().OnStreamResponse(listenerResponse.GetContext(), 1, listenerResponse.GetRequest(), rejected)
					require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
						Node: node, TypeUrl: typeurl.Listener.URL(), ResponseNonce: rejected.Nonce,
						ErrorDetail: &status.Status{Message: "rejected A"},
					}))
					for typeURL, name := range map[typeurl.Index]string{
						typeurl.Listener: "l1", typeurl.Route: "r1", typeurl.Secret: cSecret.Name,
					} {
						require.Nil(t, c.GetResource(nodeID, typeURL, name), "%s %s must be reverted with A", typeURL.URL(), name)
					}
					require.Nil(t, c.GetResource(nodeID, typeurl.Secret, bSecret.Name))
				}
			})
		}
	}
}

func TestResponseRollbackDependencyDoesNotRevertIndependentNewerValues(t *testing.T) {
	for _, superseded := range []typeurl.Index{typeurl.Listener, typeurl.Secret} {
		t.Run(superseded.URL(), func(t *testing.T) {
			c := NewCache(hivetest.Logger(t), false, WithNodeIDs("node1"))
			const nodeID = "node1"
			listener := &envoy_config_listener.Listener{Name: "l1"}
			originalSecret := &envoy_config_tls.Secret{Name: "original"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
				Secrets:   map[string]*envoy_config_tls.Secret{originalSecret.Name: originalSecret},
			}}, nil, TypeURLCallbacks{}))
			responses := make(chan cache.Response, 1)
			request := &cache.Request{Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL()}
			cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			response := <-responses
			rejected, err := response.GetDiscoveryResponse()
			require.NoError(t, err)
			rejected.Nonce = "rejected"
			c.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, request, rejected)
			secret := &envoy_config_tls.Secret{Name: "secret"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener, "dependent": {Name: "dependent"}},
				Secrets:   map[string]*envoy_config_tls.Secret{secret.Name: secret},
			}}, nil, TypeURLCallbacks{}))
			var newer proto.Message
			name := listener.Name
			if superseded == typeurl.Listener {
				newer = &envoy_config_listener.Listener{Name: name, TrafficDirection: envoy_config_core.TrafficDirection_INBOUND}
			} else {
				name = secret.Name
				newer = &envoy_config_tls.Secret{Name: name, Type: &envoy_config_tls.Secret_GenericSecret{GenericSecret: &envoy_config_tls.GenericSecret{}}}
			}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, superseded, name, newer, nil, nil))
			require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: request.Node, TypeUrl: request.TypeUrl, ResponseNonce: rejected.Nonce,
				ErrorDetail: &status.Status{Message: "rejected A"},
			}))
			current := c.GetResource(nodeID, superseded, name)
			require.NotNil(t, current)
			require.Same(t, newer, current)
			otherType, otherName := typeurl.Secret, secret.Name
			if superseded == typeurl.Secret {
				otherType, otherName = typeurl.Listener, listener.Name
			}
			require.Nil(t, c.GetResource(nodeID, otherType, otherName))
			require.Nil(t, c.GetResource(nodeID, typeurl.Listener, "dependent"))
			require.Equal(t, superseded == typeurl.Listener, c.GetResource(nodeID, typeurl.Secret, originalSecret.Name) != nil,
				"dependent Listener names must not make a superseded original Listener's transaction members revertible")
		})
	}
}

func TestNamedResponseRetainsOnlyItsDependentTransactions(t *testing.T) {
	for _, rejectedName := range []string{"s1", "s2"} {
		for _, coalesced := range []bool{false, true} {
			t.Run(fmt.Sprintf("rejected=%s/coalesced=%t", rejectedName, coalesced), func(t *testing.T) {
				c := NewCache(hivetest.Logger(t), false, WithNodeIDs("node1")).(*cacheImpl)
				node := &envoy_config_core.Node{Id: "node1"}
				s1 := &envoy_config_tls.Secret{Name: "s1"}
				s2 := &envoy_config_tls.Secret{Name: "s2"}
				// Separate transactions share one unsent SDS group. Only s1 is
				// a prerequisite for the later Listener transaction.
				require.NoError(t, c.ApplyResource(t.Context(), node.Id, typeurl.Secret, s1.Name, s1, nil, nil))
				require.NoError(t, c.ApplyResource(t.Context(), node.Id, typeurl.Secret, s2.Name, s2, nil, nil))
				listener := &envoy_config_listener.Listener{Name: "dependent"}
				require.NoError(t, c.ApplyResources(t.Context(), node.Id, ResourceMutations{Upserted: xds.Resources{
					Secrets:   map[string]*envoy_config_tls.Secret{s1.Name: s1},
					Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
				}}, nil, TypeURLCallbacks{}))
				if coalesced {
					newer := &envoy_config_tls.Secret{Name: s1.Name, Type: &envoy_config_tls.Secret_ValidationContext{
						ValidationContext: &envoy_config_tls.CertificateValidationContext{AllowExpiredCertificate: true},
					}}
					require.NoError(t, c.ApplyResource(t.Context(), node.Id, typeurl.Secret, newer.Name, newer, nil, nil))
				}
				request := &cache.Request{Node: node, TypeUrl: typeurl.Secret.URL(), ResourceNames: []string{rejectedName}}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.ResourceNames, false), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				response := <-responses
				rejected, err := response.GetDiscoveryResponse()
				require.NoError(t, err)
				rejected.Nonce = "partial"
				c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), rejected)
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: request.TypeUrl, ResponseNonce: rejected.Nonce,
					ErrorDetail: &status.Status{Message: "rejected named Secret"},
				}))
				require.Equal(t, rejectedName != s1.Name, c.GetResource(node.Id, typeurl.Listener, listener.Name) != nil, "only a rejected prerequisite rolls back its dependent")
				other := s1.Name
				if rejectedName == s1.Name {
					other = s2.Name
				}
				require.NotNil(t, c.GetResource(node.Id, typeurl.Secret, other), "an unrequested independent transaction remains desired")
			})
		}
	}
}

func TestResponseRollbackRetainsEveryPendingTransactionPrerequisite(t *testing.T) {
	c := NewCache(hivetest.Logger(t), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	watch := func(typeURL typeurl.Index) cache.Response {
		t.Helper()
		responses := make(chan cache.Response, 1)
		cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeURL.URL()},
			stream.NewSotwSubscription(nil, true), responses)
		require.NoError(t, err)
		t.Cleanup(cancel)
		select {
		case response := <-responses:
			return response
		case <-time.After(5 * time.Second):
			t.Fatal("no response for ", typeURL.URL())
			return nil
		}
	}
	listener := &envoy_config_listener.Listener{Name: "l1"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
	listenerResponse := watch(typeurl.Listener)
	cluster := &envoy_config_cluster.Cluster{Name: "c1"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, cluster.Name, cluster, nil, nil))
	clusterResponse := watch(typeurl.Cluster)
	secret := &envoy_config_tls.Secret{Name: "dependent"}
	require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{listener.Name: proto.Clone(listener).(*envoy_config_listener.Listener)},
		Clusters:  map[string]*envoy_config_cluster.Cluster{cluster.Name: proto.Clone(cluster).(*envoy_config_cluster.Cluster)},
		Secrets:   map[string]*envoy_config_tls.Secret{secret.Name: secret},
	}}, nil, TypeURLCallbacks{}))
	// Accepting one prerequisite must not finalize the inverse still needed by
	// the other. B has no WaitGroup and exposes no caller rollback handle.
	acknowledgeResponse(t, c, 1, listenerResponse, "accepted-listener")
	rejected, err := clusterResponse.GetDiscoveryResponse()
	require.NoError(t, err)
	rejected.Nonce = "rejected-cluster"
	c.GetCompletionCallbacks().OnStreamResponse(clusterResponse.GetContext(), 1, clusterResponse.GetRequest(), rejected)
	require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node: node, TypeUrl: typeurl.Cluster.URL(), ResponseNonce: rejected.Nonce,
		ErrorDetail: &status.Status{Message: "rejected cluster prerequisite"},
	}))
	require.Nil(t, c.GetResource(nodeID, typeurl.Secret, secret.Name))
	require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, cluster.Name))
	current := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.NotNil(t, current)
	require.Same(t, listener, current)
}

func TestResponseRollbackDependencyChurnDoesNotRetainRemovedResources(t *testing.T) {
	c := NewCache(hivetest.Logger(t), false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}
	listener := &envoy_config_listener.Listener{Name: "l1"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeurl.Listener.URL()},
		stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	<-responses // Keep this LDS response unresolved throughout the churn.
	for i := range 40 {
		name := fmt.Sprintf("secret-%d", i)
		require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
			Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
			Secrets:   map[string]*envoy_config_tls.Secret{name: {Name: name}},
		}}, nil, TypeURLCallbacks{}))
		require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Secret, name, nil, nil, nil))
		cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeurl.Secret.URL(), ResourceNames: []string{name}},
			stream.NewSotwSubscription([]string{name}, false), responses)
		require.NoError(t, err)
		t.Cleanup(cancel)
		select {
		case response := <-responses:
			acknowledgeResponse(t, c, 1, response, name)
		case <-time.After(5 * time.Second):
			t.Fatal("no response for removed Secret ", name)
		}
		require.Nil(t, c.GetResource(nodeID, typeurl.Secret, name))
		// Check the retained bookkeeping itself: externally visible absence
		// alone cannot catch accumulation of obsolete inverse maps or names.
		for response := range c.getNodeState(nodeID).rollbacks.responses.Members() {
			require.Nil(t, response.dependents)
		}
		c.getNodeState(nodeID).rollbacks.requireDependentIndex(t)
		require.True(t, c.getNodeState(nodeID).rollbacks.dependents.Empty())
	}
}

func TestResponseRevertExpandsReferencesOnlyInStrictADS(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, test := range []struct {
			name         string
			rejectedType typeurl.Index
			updatedType  typeurl.Index
			updatedName  string
			updated      func(*testing.T) proto.Message
		}{
			{
				name: "listener-nack-newer-route", rejectedType: typeurl.Listener,
				updatedType: typeurl.Route, updatedName: "r1",
				updated: func(*testing.T) proto.Message {
					return &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
				},
			},
			{
				name: "cluster-nack-newer-endpoint", rejectedType: typeurl.Cluster,
				updatedType: typeurl.Endpoint, updatedName: "e1",
				updated: func(*testing.T) proto.Message {
					return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "e1", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
						Locality: &envoy_config_core.Locality{Region: "newer"},
					}}}
				},
			},
			{
				name: "route-nack-new-dependent-listener", rejectedType: typeurl.Route,
				updatedType: typeurl.Listener, updatedName: "dependent",
				updated: func(t *testing.T) proto.Message { return strictTestListener(t, "dependent", "r1") },
			},
		} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, test.name), func(t *testing.T) {
				logger := hivetest.Logger(t)
				if strict {
					logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				}
				c := NewCache(logger, strict, WithNodeIDs("node1")).(*cacheImpl)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				wg := completion.NewWaitGroup(t.Context())
				t.Cleanup(wg.Cancel)
				var waits TypeURLCallbacks
				waits.Set(test.rejectedType, nil)
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": strictTestListener(t, "l1", "r1")},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": {Name: "r1"}},
					Clusters:  map[string]*envoy_config_cluster.Cluster{"c1": strictTestEDSCluster("c1", "e1")},
					Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"e1": {ClusterName: "e1"}},
					Secrets:   map[string]*envoy_config_tls.Secret{"s1": {Name: "s1"}},
				}}, wg, waits))
				request := &cache.Request{Node: node, TypeUrl: test.rejectedType.URL()}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				var response cache.Response
				select {
				case response = <-responses:
				case <-time.After(5 * time.Second):
					t.Fatal("no response for ", request.TypeUrl)
				}
				rejected, err := response.GetDiscoveryResponse()
				require.NoError(t, err)
				rejected.Nonce = "rejected"
				c.completionCbs.OnStreamResponse(response.GetContext(), 1, request, rejected)

				// This transaction does not reuse an unchanged pending value, so it
				// has no await-current-version dependency on the rejected transaction.
				// Only reference consistency can expand the rollback to its resource.
				newer := test.updated(t)
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, test.updatedType, test.updatedName, newer, nil, nil))
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: request.TypeUrl, ResponseNonce: rejected.Nonce,
					ErrorDetail: &status.Status{Message: "rejected original transaction"},
				}))
				require.ErrorContains(t, wg.Wait(), "rejected original transaction")

				// All still-current changes from the NACKed transaction, including
				// its unrelated Secret, must be reverted in either mode.
				for typeURL, name := range map[typeurl.Index]string{
					typeurl.Listener: "l1", typeurl.Route: "r1", typeurl.Cluster: "c1", typeurl.Endpoint: "e1", typeurl.Secret: "s1",
				} {
					require.Equal(t, !strict && typeURL == test.updatedType && name == test.updatedName, c.GetResource(nodeID, typeURL, name) != nil,
						"%s %s", typeURL.URL(), name)
				}
				current := c.GetResource(nodeID, test.updatedType, test.updatedName)
				require.Equal(t, !strict, current != nil, "only strict ADS may revert the independent newer resource")
				if !strict {
					require.Same(t, newer, current)
					require.Nil(t, c.getNodeState(nodeID).strictRefs, "non-strict rollback must not build a reference index")
				}
			})
		}
	}
}

func TestStrictADSResponseRevertClosesDependencies(t *testing.T) {
	for _, test := range []struct {
		name         string
		rejectedType typeurl.Index
		updatedType  typeurl.Index
		updatedName  string
		updated      func(*testing.T) proto.Message
	}{
		{
			name: "route-nack-newer-listener", rejectedType: typeurl.Route,
			updatedType: typeurl.Listener, updatedName: "l1",
			updated: func(t *testing.T) proto.Message {
				listener := strictTestListener(t, "l1", "r1")
				listener.TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
				return listener
			},
		},
		{
			name: "route-nack-new-dependent-listener", rejectedType: typeurl.Route,
			updatedType: typeurl.Listener, updatedName: "dependent",
			updated: func(t *testing.T) proto.Message { return strictTestListener(t, "dependent", "r1") },
		},
		{
			name: "secret-nack-newer-route", rejectedType: typeurl.Secret,
			updatedType: typeurl.Route, updatedName: "r1",
			updated: func(*testing.T) proto.Message {
				return &envoy_config_route.RouteConfiguration{Name: "r1", IgnorePortInHostMatching: true}
			},
		},
		{
			name: "secret-nack-newer-endpoint", rejectedType: typeurl.Secret,
			updatedType: typeurl.Endpoint, updatedName: "e1",
			updated: func(*testing.T) proto.Message {
				return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "e1", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
					Locality: &envoy_config_core.Locality{Region: "newer"},
				}}}
			},
		},
		{
			name: "listener-nack-newer-endpoint", rejectedType: typeurl.Listener,
			updatedType: typeurl.Endpoint, updatedName: "e1",
			updated: func(*testing.T) proto.Message {
				return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "e1", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
					Locality: &envoy_config_core.Locality{Region: "newer"},
				}}}
			},
		},
	} {
		for _, newerACKed := range []bool{false, true} {
			name := test.name + "/pending"
			if newerACKed {
				name = test.name + "/acked"
			}
			t.Run(name, func(t *testing.T) {
				c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs("node1"))
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				responses := make(chan cache.Response, 1)
				watch := func(typeURL typeurl.Index) cache.Response {
					request := &cache.Request{Node: node, TypeUrl: typeURL.URL()}
					if typeURL == typeurl.Secret {
						request.ResourceNames = []string{"s1"}
					}
					cancel, err := c.CreateWatch(request,
						stream.NewSotwSubscription(request.GetResourceNames(), true), responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case response := <-responses:
						return response
					case <-time.After(5 * time.Second):
						t.Fatal("no response for ", typeURL.URL())
						return nil
					}
				}
				wg := completion.NewWaitGroup(t.Context())
				t.Cleanup(wg.Cancel)
				var waits TypeURLCallbacks
				waits.Set(test.rejectedType, nil)
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": strictTestListener(t, "l1", "r1")},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": {Name: "r1"}},
					Clusters:  map[string]*envoy_config_cluster.Cluster{"c1": strictTestEDSCluster("c1", "e1")},
					Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"e1": {ClusterName: "e1"}},
					Secrets:   map[string]*envoy_config_tls.Secret{"s1": {Name: "s1"}},
				}}, wg, waits))
				response := watch(test.rejectedType)
				rejected, err := response.GetDiscoveryResponse()
				require.NoError(t, err)
				rejected.Nonce = "rejected"
				c.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(), rejected)

				// Capture the rejected response before B changes a dependent resource.
				// B may even be ACKed before A is NACKed; the resulting resource set
				// must remain consistent in either ordering.
				later, err := c.ApplyResourceWithRollback(t.Context(), nodeID, test.updatedType, test.updatedName, test.updated(t), nil, nil)
				require.NoError(t, err)
				if newerACKed {
					response := watch(test.updatedType)
					acknowledgeResponse(t, c.(*cacheImpl), 1, response, "newer")
				}
				unrelated := strictTestListener(t, "unrelated", "unrelated")
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"unrelated": unrelated},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"unrelated": {Name: "unrelated"}},
				}}, nil, TypeURLCallbacks{}))

				require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: test.rejectedType.URL(), ResponseNonce: rejected.Nonce,
					ErrorDetail: &status.Status{Message: "rejected original transaction"},
				}))
				require.ErrorContains(t, wg.Wait(), "rejected original transaction")
				for typeURL, name := range map[typeurl.Index]string{
					typeurl.Listener: "l1", typeurl.Route: "r1", typeurl.Cluster: "c1", typeurl.Endpoint: "e1", typeurl.Secret: "s1",
				} {
					require.Nil(t, c.GetResource(nodeID, typeURL, name), "%s %s must be reverted", typeURL.URL(), name)
				}
				require.Nil(t, c.GetResource(nodeID, typeurl.Listener, "dependent"))
				listener := c.GetResource(nodeID, typeurl.Listener, "unrelated")
				require.NotNil(t, listener)
				require.Same(t, unrelated, listener, "unrelated transactions must not be reverted")

				// A stale caller rollback for B cannot resurrect a resource whose
				// dependency has just been removed by the response rollback.
				require.NoError(t, later.Revert())
				watch(test.rejectedType)
				snapshot, err := c.GetSnapshot(nodeID)
				require.NoError(t, err)
				require.NoError(t, CheckSnapshotConsistency(snapshot))
			})
		}
	}
}

func TestStrictADSResponseRevertWithLaterReferences(t *testing.T) {
	r0 := &envoy_config_route.RouteConfiguration{Name: "r0"}
	r1 := &envoy_config_route.RouteConfiguration{Name: "r1"}
	r2 := &envoy_config_route.RouteConfiguration{Name: "r2"}
	l0 := strictTestListener(t, "l0", "r0")
	l1r0 := strictTestListener(t, "l1", "r0")
	l1r1 := strictTestListener(t, "l1", "r1")
	l1r1Newer := strictTestListener(t, "l1", "r1")
	l1r1Newer.TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
	l1r2 := strictTestListener(t, "l1", "r2")
	for _, test := range []struct {
		name         string
		rejectedType typeurl.Index
		initial      xds.Resources
		rejected     ResourceMutations
		later        ResourceMutations
		expected     xds.Resources
	}{
		{
			name: "route-configuration-only", rejectedType: typeurl.Route,
			initial: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": r1},
			},
			rejected: ResourceMutations{Upserted: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
				"r1": {Name: "r1", IgnorePortInHostMatching: true},
			}}},
			later: ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1Newer}}},
			expected: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1Newer},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": r1},
			},
		},
		{
			name: "route-restoration-no-longer-referenced", rejectedType: typeurl.Route,
			initial: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			},
			rejected: ResourceMutations{
				Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"r0": r0}},
				Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": r1},
				},
			},
			later: ResourceMutations{
				Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"r1": r1}},
				Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r2},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r2": r2},
				},
			},
			expected: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r2},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r2": r2},
			},
		},
		{
			name: "restored-listener-route-later-removed", rejectedType: typeurl.Listener,
			initial: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l0": l0, "l1": l1r0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			},
			rejected: ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": r1},
			}},
			later: ResourceMutations{Removed: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l0": l0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			}},
		},
		{
			name: "orphan-outside-rejected-transaction", rejectedType: typeurl.Listener,
			initial: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l0": l0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			},
			rejected: ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r0}}},
			later:    ResourceMutations{Removed: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"l0": l0}}},
		},
		{
			name: "restore-newer-listener-previous-reference", rejectedType: typeurl.Route,
			initial: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			},
			rejected: ResourceMutations{
				Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"r0": r0}},
				Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r1},
					Routes:    map[string]*envoy_config_route.RouteConfiguration{"r1": r1},
				},
			},
			later: ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
				"l1": l1r1Newer, "l2": strictTestListener(t, "l2", "r1"),
			}}},
			expected: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"l1": l1r0},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"r0": r0},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs("node1"))
			const nodeID = "node1"
			node := &envoy_config_core.Node{Id: nodeID}
			responses := make(chan cache.Response, 1)
			watch := func(typeURL typeurl.Index, version string) cache.Response {
				cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: typeURL.URL(), VersionInfo: version},
					stream.NewSotwSubscription(nil, true), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				select {
				case response := <-responses:
					return response
				case <-time.After(5 * time.Second):
					t.Fatal("no response for ", typeURL.URL())
					return nil
				}
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: test.initial}, nil, TypeURLCallbacks{}))
			var acceptedVersion string
			for _, typeURL := range []typeurl.Index{typeurl.Listener, typeurl.Route} {
				response := watch(typeURL, "")
				acknowledgeResponse(t, c.(*cacheImpl), 1, response, "initial")
				if typeURL == test.rejectedType {
					acceptedVersion = response.GetResponseVersion()
				}
			}

			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			var waits TypeURLCallbacks
			waits.Set(test.rejectedType, nil)
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, test.rejected, wg, waits))
			response := watch(test.rejectedType, acceptedVersion)
			rejected, err := response.GetDiscoveryResponse()
			require.NoError(t, err)
			rejected.Nonce = "rejected"
			c.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(), rejected)
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, test.later, nil, TypeURLCallbacks{}))

			// Rollback must account for the current references, not assume that
			// every child affected by it belonged to the rejected transaction.
			require.NoError(t, c.GetCompletionCallbacks().OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: node, TypeUrl: test.rejectedType.URL(), VersionInfo: acceptedVersion, ResponseNonce: rejected.Nonce,
				ErrorDetail: &status.Status{Message: "rejected reference change"},
			}))
			require.ErrorContains(t, wg.Wait(), "rejected reference change")
			listeners := maps.Collect(c.Listeners(nodeID))
			routes := maps.Collect(c.Routes(nodeID))
			require.Len(t, listeners, len(test.expected.Listeners))
			require.Len(t, routes, len(test.expected.Routes))
			for name, listener := range test.expected.Listeners {
				require.Same(t, listener, listeners[name])
			}
			for name, route := range test.expected.Routes {
				require.Same(t, route, routes[name])
			}
			watch(test.rejectedType, rejected.VersionInfo)
			snapshot, err := c.GetSnapshot(nodeID)
			require.NoError(t, err)
			require.NoError(t, CheckSnapshotConsistency(snapshot))
		})
	}
}

func TestResourceRevisionAdvancesWhileRevertRestoresTransaction(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		t.Run(api, func(t *testing.T) {
			c := newCoverageCache(t)
			const nodeID, name = "coverage-node", "resource"
			state := c.getNodeState(nodeID)
			apply := func(value *envoy_config_listener.Listener) Rollback {
				t.Helper()
				var rollback Rollback
				var err error
				if api == "single" {
					rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, name, value, nil, nil)
				} else {
					mutations := ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{name: value}}}
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, mutations, nil, TypeURLCallbacks{})
				}
				require.NoError(t, err)
				return rollback
			}
			// Check source positions so the API/revert sequence stays readable.
			checkEntry := func(value *envoy_config_listener.Listener, revision, transaction callbacks.Generation) {
				t.Helper()
				entry := state.resourceWaitEntry(typeurl.Listener, name)
				require.Equal(t, revision.Revision(), entry.revision)
				require.Equal(t, transaction.TransactionID(), entry.transaction)
				if value == nil {
					require.Nil(t, entry.resource)
				} else {
					require.Same(t, value, entry.resource)
				}
			}
			a := &envoy_config_listener.Listener{Name: name, PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
			b := &envoy_config_listener.Listener{Name: name, PerConnectionBufferLimitBytes: wrapperspb.UInt32(2)}
			third := &envoy_config_listener.Listener{Name: name, PerConnectionBufferLimitBytes: wrapperspb.UInt32(3)}
			insert := apply(a)
			checkEntry(a, 1, 1)
			update := apply(b)
			checkEntry(b, 2, 2)
			require.NoError(t, update.Revert())
			checkEntry(a, 3, 1)
			require.Nil(t, apply(proto.Clone(a).(*envoy_config_listener.Listener)), "semantic no-ops preserve both properties")
			checkEntry(a, 3, 1)
			update = apply(third)
			checkEntry(third, 4, 4)
			removal := apply(nil)
			checkEntry(nil, 5, 5)
			require.NoError(t, removal.Revert())
			checkEntry(third, 6, 4)
			// The restored transaction, not the fresh revision, lets the older
			// lifecycle match its original change and continue the inverse chain.
			require.NoError(t, update.Revert())
			checkEntry(a, 7, 1)
			require.NoError(t, insert.Revert())
			checkEntry(nil, 8, 0)
			require.NotContains(t, state.resources[typeurl.Listener], name, "restored absence needs no persistent tombstone")
		})
	}
}

func TestCallerRevertRestoresPreviouslyAbsentResources(t *testing.T) {
	for _, mode := range []string{"single", "bulk"} {
		t.Run(mode, func(t *testing.T) {
			const nodeID = "node1"
			c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs(nodeID))
			cluster := &envoy_config_cluster.Cluster{Name: "resource"}
			secret := &envoy_config_tls.Secret{Name: "resource"}
			typeURLs := typeurl.NewSet(typeurl.Cluster)
			var rollback Rollback
			var err error
			if mode == "single" {
				rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Cluster, cluster.Name, cluster, nil, nil)
			} else {
				typeURLs.Insert(typeurl.Secret)
				rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Clusters: map[string]*envoy_config_cluster.Cluster{cluster.Name: cluster},
					Secrets:  map[string]*envoy_config_tls.Secret{secret.Name: secret},
				}}, nil, TypeURLCallbacks{})
			}
			require.NoError(t, err)
			require.NotNil(t, rollback)
			for typeURL := range typeURLs.Members() {
				require.NotNil(t, c.GetResource(nodeID, typeURL, "resource"))
			}

			// Both the inline inverse and its map-backed counterpart must retain
			// prior absence as an explicit zero entry. Dropping that entry would
			// leave the newly added resource behind when the caller reverts.
			require.NoError(t, rollback.Revert())
			_, err = c.GetSnapshot(nodeID)
			require.Error(t, err, "reverting desired state must not eagerly publish a snapshot")

			// The first watch finalizes the reverted desired state, not the
			// resources added before the caller rollback.
			responses := make(chan cache.Response, 1)
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Cluster.URL(),
			}, stream.NewSotwSubscription(nil, true), responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			select {
			case response := <-responses:
				require.Empty(t, response.GetReturnedResources())
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for reverted snapshot")
			}
			snapshot, err := c.GetSnapshot(nodeID)
			require.NoError(t, err)
			for typeURL := range typeURLs.Members() {
				require.Nil(t, c.GetResource(nodeID, typeURL, "resource"))
				require.Empty(t, snapshot.GetResources(typeURL.URL()))
			}
		})
	}
}
