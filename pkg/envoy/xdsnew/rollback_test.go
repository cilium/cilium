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

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
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
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

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
				rollback := make(rollbackResources)
				for name, entry := range targets {
					rollback[name] = rollbackEntry{previous: entry, expectedTransaction: callbacks.Generation(10).TransactionID()}
				}
				changes = rollback.resourceRevert(state, typeurl.NetworkPolicy)
			}
			require.Len(t, changes.more, 3)
			require.Equal(t, current, state.resourceEntries(typeurl.NetworkPolicy), "preparation must not mutate entries")
			state.commitResourceMutation(changes)
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

func TestFailedCallerRevertReleasesRemovalTombstone(t *testing.T) {
	for _, api := range []string{"ApplyResourceWithRollback", "ApplyResourcesWithRollback"} {
		t.Run(api, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(mock)
			var logs strings.Builder
			c.logger = slog.New(slog.NewTextHandler(&logs, nil))
			const nodeID = "node1"
			route := &envoy_config_route.RouteConfiguration{Name: "removed"}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Route, route.Name, route, nil, nil))
			acceptPublishedSnapshotVersions(t, c, 1, &envoy_config_core.Node{Id: nodeID}, mustSnapshot(t, c, nodeID))

			var rollback Rollback
			var err error
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
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)
	cancel()

	require.NoError(t, rollback.Revert())
	require.Nil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"))
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
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)),
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

func TestFirstUntrackedSnapshotNACKRevertsColdStartResources(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1")).(*cacheImpl)
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
	policyRollback := state.typeStates[typeurl.NetworkPolicy].rollbacks.unsent
	require.NotNil(t, policyRollback)
	require.NotNil(t, policyRollback.resources)
	coldStartRollback := policyRollback.resources
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

func TestResourceUpdateRevertibleIsNoOpAfterFirstCall(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1")).(*cacheImpl)
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
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a", "node-b")).(*cacheImpl)
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
	resource = c.GetResource("node-b", typeurl.NetworkPolicy, "policy")
	require.NotNil(t, resource)
	require.Equal(t, uint64(2), resource.(*cilium.NetworkPolicy).EndpointId, "rollback must leave the other node unchanged")
}

func TestApplyResourcesRevertOnlyRestoresOwnedResourceVersions(t *testing.T) {
	newCache := func(t *testing.T) *cacheImpl {
		t.Helper()
		return NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a")).(*cacheImpl)
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
			response := publishedResponseForTest(t, c, node, typeurl.Route)
			c.completionCbs.OnStreamResponse(response.GetContext(), 1,
				response.GetRequest(),
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
					VersionInfo:   baseline.GetVersion(envoy_resource.RouteType),
					ResponseNonce: "rejected-routes",
					ErrorDetail:   &status.Status{Message: "rejected routes"},
				}))
			} else {
				require.NoError(t, rollback.Revert())
			}
			require.Equal(t, "3", c.GetResource("node-a", typeurl.Route, "newer").(*envoy_config_route.RouteConfiguration).Name,
				"a revert must not overwrite a resource changed by a newer generation")
			require.Equal(t, "1", c.GetResource("node-a", typeurl.Route, "unchanged").(*envoy_config_route.RouteConfiguration).Name,
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
		require.Nil(t, c.GetResource("node-a", typeurl.Route, "newer"),
			"a newer removal must not be mistaken for the removal being reverted")
		require.Equal(t, "1", c.GetResource("node-a", typeurl.Route, "unchanged").(*envoy_config_route.RouteConfiguration).Name)
	})
}

func TestApplyResourcesRevertCoversEnvoyResourceTypes(t *testing.T) {
	c := NewCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a")).(*cacheImpl)
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
			c := NewCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
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
			snapshot, err := c.GetSnapshot(nodeID)
			require.NoError(t, err)
			for typeURL := range typeURLs.Members() {
				require.Nil(t, c.GetResource(nodeID, typeURL, "resource"))
				require.Empty(t, snapshot.GetResources(typeURL.URL()))
			}
		})
	}
}
func TestAcceptedRemovalsReleaseTombstones(t *testing.T) {
	for _, test := range []struct {
		name      string
		resources int
		tracked   bool
		names     []string
	}{
		{name: "many-untracked", resources: 100, names: []string{"*"}},
		{name: "single-tracked", resources: 1, tracked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newCoverageCache(t)
			const nodeID = "coverage-node"
			ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancelContext)
			for id := range test.resources {
				name := strconv.Itoa(id)
				rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeurl.NetworkPolicy,
					name, &cilium.NetworkPolicy{EndpointId: uint64(id)}, nil, nil)
				require.NoError(t, err)
				rollback.Finalize()
			}
			s := coverageStream{cache: c, id: 1, typeURL: NetworkPolicyTypeURL}
			initial := s.receive(t, test.names...)
			s.reply(t, initial, "", test.names...)

			var wg *completion.WaitGroup
			var responses chan cache.Response
			if test.tracked {
				wg = completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				responses = make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(&cache.Request{
					Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: NetworkPolicyTypeURL,
					VersionInfo: initial.VersionInfo, ResourceNames: test.names,
				}, s.sub, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
			}
			for id := range test.resources {
				name := strconv.Itoa(id)
				rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeurl.NetworkPolicy, name, nil, wg, nil)
				require.NoError(t, err)
				rollback.Finalize()
				require.Nil(t, c.getNodeState(nodeID).resources[typeurl.NetworkPolicy][name].resource)
			}
			var response *discovery.DiscoveryResponse
			if test.tracked {
				require.NotEmpty(t, c.getNodeState(nodeID).typeStates[typeurl.NetworkPolicy].rollbacks.owners,
					"caller finalization must leave the response-owned removal rollback live")
				response = s.deliver(t, <-responses)
			} else {
				response = s.receive(t, test.names...)
			}
			require.Empty(t, response.Resources)
			s.reply(t, response, "", test.names...)
			if wg != nil {
				require.NoError(t, wg.Wait())
			}
			state := c.getNodeState(nodeID)
			require.Empty(t, state.resources[typeurl.NetworkPolicy], "the accepted removals release their tombstones")
			state.requireNoRollbackOwners(t)
			c.completionCbs.OnStreamClosed(1, &envoy_config_core.Node{Id: nodeID})
			require.Same(t, state, c.getNodeState(nodeID), "known nodes remain after all resources and streams are gone")
			require.Empty(t, state.resources[typeurl.NetworkPolicy])
			state.requireNoRollbackOwners(t)
			state.requireNoUnsentRollbacks(t)
		})
	}
}
func TestRollbackSurvivesCallerAndResponseResolution(t *testing.T) {
	for _, api := range []struct {
		name        string
		typeURL     typeurl.Index
		original    proto.Message
		replacement proto.Message
		bulk        bool
	}{
		{"policy-single", typeurl.NetworkPolicy, &cilium.NetworkPolicy{EndpointId: 1}, &cilium.NetworkPolicy{EndpointId: 2}, false},
		{"cluster-single", typeurl.Cluster, &envoy_config_cluster.Cluster{Name: "resource"}, &envoy_config_cluster.Cluster{Name: "resource", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}, false},
		{"cluster-bulk", typeurl.Cluster, &envoy_config_cluster.Cluster{Name: "resource"}, &envoy_config_cluster.Cluster{Name: "resource", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}, true},
	} {
		for _, test := range []struct {
			name        string
			remove      bool
			tracked     bool
			cancelWait  bool
			callerFirst bool
			closeStream bool
			reject      bool
			revert      bool
		}{
			{name: "removal-with-live-wait", remove: true, tracked: true, callerFirst: true, reject: true},
			{name: "replacement-with-canceled-wait", tracked: true, cancelWait: true, callerFirst: true, reject: true},
			{name: "ACK-before-caller-finalize", remove: true},
			{name: "ACK-before-caller-revert", remove: true, revert: true},
			{name: "ACK-disconnect-before-caller-finalize", remove: true, closeStream: true},
			{name: "ACK-disconnect-before-caller-revert", remove: true, closeStream: true, revert: true},
			{name: "NACK-before-caller-finalize", remove: true, reject: true},
		} {
			t.Run(api.name+"/"+test.name, func(t *testing.T) {
				c := newCoverageCache(t)
				const nodeID = "coverage-node"
				ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancelContext)
				caller, err := c.ApplyResourceWithRollback(ctx, nodeID, api.typeURL, "resource", api.original, nil, nil)
				require.NoError(t, err)
				caller.Finalize()
				s := coverageStream{cache: c, id: 1, typeURL: api.typeURL.URL()}
				s.reply(t, s.receive(t), "")
				responses := s.watch(t)

				waitCtx, cancelWait := context.WithCancel(ctx)
				t.Cleanup(cancelWait)
				var wg *completion.WaitGroup
				if test.tracked {
					wg = completion.NewWaitGroup(waitCtx)
					t.Cleanup(wg.Cancel)
				}
				var next proto.Message
				if !test.remove {
					next = api.replacement
				}
				if api.bulk {
					var mutations ResourceMutations
					if test.remove {
						mutations.Removed.Clusters = map[string]*envoy_config_cluster.Cluster{"resource": nil}
					} else {
						mutations.Upserted.Clusters = map[string]*envoy_config_cluster.Cluster{"resource": next.(*envoy_config_cluster.Cluster)}
					}
					var waits TypeURLCallbacks
					if wg != nil {
						waits.Set(api.typeURL, nil)
					}
					caller, err = c.ApplyResourcesWithRollback(ctx, nodeID, mutations, wg, waits)
				} else {
					caller, err = c.ApplyResourceWithRollback(ctx, nodeID, api.typeURL, "resource", next, wg, nil)
				}
				require.NoError(t, err)
				require.NotNil(t, caller)
				t.Cleanup(func() {
					if caller != nil {
						caller.Finalize()
					}
				})
				// Finalize removals before delivery, and replacements after the
				// caller's wait is canceled. Response recovery must survive both.
				if test.callerFirst && !test.cancelWait {
					caller.Finalize()
					caller = nil
				}
				response := s.deliver(t, <-responses)
				if test.remove {
					require.Empty(t, response.Resources)
				}
				if test.cancelWait {
					cancelWait()
					require.ErrorIs(t, wg.Wait(), context.Canceled)
					caller.Finalize()
					caller = nil
				}
				if test.remove {
					require.Nil(t, c.GetResource(nodeID, api.typeURL, "resource"))
				} else {
					require.Same(t, next, c.GetResource(nodeID, api.typeURL, "resource"))
				}
				rejection := ""
				if test.reject {
					rejection = "resource rejected"
				}
				s.reply(t, response, rejection)
				if test.closeStream {
					c.completionCbs.OnStreamClosed(s.id, &envoy_config_core.Node{Id: nodeID})
				}
				if caller != nil {
					if test.revert {
						require.NoError(t, caller.Revert())
					} else {
						caller.Finalize()
					}
					caller = nil
				}
				if test.reject || test.revert {
					require.Same(t, api.original, c.GetResource(nodeID, api.typeURL, "resource"),
						"the remaining owner must still be able to restore the resource")
				} else {
					require.Nil(t, c.GetResource(nodeID, api.typeURL, "resource"))
					require.Nil(t, c.getNodeState(nodeID).resources[api.typeURL], "the final owner releases the tombstone map")
				}
				if wg != nil && !test.cancelWait {
					if test.reject {
						require.ErrorContains(t, wg.Wait(), rejection)
					} else {
						require.NoError(t, wg.Wait())
					}
				}
				c.getNodeState(nodeID).requireNoRollbackOwners(t)
			})
		}
	}
}
