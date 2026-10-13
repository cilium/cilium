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
	"github.com/cilium/cilium/pkg/revert"
)

func TestPreparedResourceRevertsCarryTargetEntries(t *testing.T) {
	for _, mode := range []string{"caller", "response"} {
		t.Run(mode, func(t *testing.T) {
			targets := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 1}, revision: callbacks.Generation(3).Revision(), transaction: callbacks.Generation(3).TransactionID()},
				"added":      {},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 3}, revision: callbacks.Generation(4).Revision(), transaction: callbacks.Generation(4).TransactionID()},
			}
			current := map[string]resourceEntry{
				"updated":    {resource: &cilium.NetworkPolicy{EndpointId: 10}, revision: callbacks.Generation(12).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"added":      {resource: &cilium.NetworkPolicy{EndpointId: 11}, revision: callbacks.Generation(10).Revision(), transaction: callbacks.Generation(10).TransactionID()},
				"superseded": {resource: &cilium.NetworkPolicy{EndpointId: 13}, revision: callbacks.Generation(11).Revision(), transaction: callbacks.Generation(11).TransactionID()},
			}
			state := &nodeState{}
			state.resources[typeurl.NetworkPolicy] = maps.Clone(current)
			var changes resourceChanges
			if mode == "caller" {
				var inverse resources
				inverse.entries[typeurl.NetworkPolicy] = targets
				lifecycle := callerRollback{state: state, transaction: callbacks.Generation(10).TransactionID(), inverse: inverse}
				changes = lifecycle.prepareRevertLocked()
			} else {
				rollback := make(rollbackResources)
				for name, entry := range targets {
					rollback[name] = rollbackEntry{previous: entry, expectedTransaction: callbacks.Generation(10).TransactionID()}
				}
				changes = rollback.resourceRevert(state, typeurl.NetworkPolicy)
			}
			require.Len(t, changes.more, 1)
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
			require.NotContains(t, entries, "added", "reverting an addition restores absence")
		})
	}
}

func TestCallerRevertAfterCancellation(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove=%t", remove), func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			const nodeID = "node1"
			// The mock leaves this watch open so the revert publishes synchronously.
			// Otherwise it only commits unpublished compensation and never exercises
			// delivery with the canceled caller's context.
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.NetworkPolicyURL,
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			policy := &cilium.NetworkPolicy{EndpointId: 1}
			var next proto.Message = policy
			if remove {
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", policy, nil))
				next = nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeurl.NetworkPolicy, "policy", next, nil)
			require.NoError(t, err)
			cancel()

			publications := len(mock.setSnapshotCalls)
			require.NoError(t, rollback.Revert())
			require.Len(t, mock.setSnapshotCalls, publications+1)
			if remove {
				require.Same(t, policy, c.GetResource(nodeID, typeurl.NetworkPolicy, "policy"))
			} else {
				require.Nil(t, c.GetResource(nodeID, typeurl.NetworkPolicy, "policy"))
			}
			// The expired mutation context must not cancel corrective delivery.
			require.NoError(t, mock.setSnapshotCalls[len(mock.setSnapshotCalls)-1].Err())
		})
	}
}

func TestCallerRollbackAfterFailedMutation(t *testing.T) {
	for _, mode := range []string{"single", "bulk", "mixed-no-op-removal", "mixed-no-op-upsert"} {
		t.Run(mode, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			const nodeID, name = "node1", "resource"
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Route.URL(),
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
			original := &envoy_config_route.RouteConfiguration{Name: name}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Route, name, original, nil))
			if mode == "mixed-no-op-upsert" {
				updated := &envoy_config_route.RouteConfiguration{Name: name, IgnorePortInHostMatching: true}
				rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, name, updated, nil)
				require.NoError(t, err)
				publicationErr := errors.New("publication failed")
				mock.setSnapshotErr = publicationErr
				err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Routes: map[string]*envoy_config_route.RouteConfiguration{
						name: proto.Clone(updated).(*envoy_config_route.RouteConfiguration), "other": {Name: "other"},
					},
				}}, nil, typeurl.Set{})
				require.ErrorIs(t, err, publicationErr)
				mock.setSnapshotErr = nil
				require.NoError(t, rollback.Revert())
				require.Same(t, original, c.GetResource(nodeID, typeurl.Route, name), "failed admission must not supersede caller recovery")
				require.Nil(t, c.GetResource(nodeID, typeurl.Route, "other"))
				return
			}
			removed, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, name, nil, nil)
			require.NoError(t, err)
			var replacement Rollback = revert.Noop
			if mode != "mixed-no-op-removal" {
				replacement, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, name,
					&envoy_config_route.RouteConfiguration{Name: name, IgnorePortInHostMatching: true}, nil)
				require.NoError(t, err)
			}
			publicationErr := errors.New("publication failed")
			mock.setSnapshotErr = publicationErr
			if mode == "single" {
				err = c.ApplyResource(t.Context(), nodeID, typeurl.Route, name, nil, nil)
			} else {
				mutations := ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{name: nil}}}
				if mode == "mixed-no-op-removal" {
					mutations.Upserted.Routes = map[string]*envoy_config_route.RouteConfiguration{"other": {Name: "other"}}
				}
				err = c.ApplyResources(t.Context(), nodeID, mutations, nil, typeurl.Set{})
			}
			require.ErrorIs(t, err, publicationErr)
			mock.setSnapshotErr = nil
			require.NoError(t, replacement.Revert())
			require.Nil(t, c.GetResource(nodeID, typeurl.Route, name))
			require.NoError(t, removed.Revert())
			require.Same(t, original, c.GetResource(nodeID, typeurl.Route, name), "failed admission cannot supersede a caller's removal claim")
			require.Nil(t, c.GetResource(nodeID, typeurl.Route, "other"))
		})
	}
}

func TestCallerRemovalRollbackBypassesNACKedPredecessor(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		for _, haveBaseline := range []bool{false, true} {
			t.Run(fmt.Sprintf("bulk=%t/baseline=%t", bulk, haveBaseline), func(t *testing.T) {
				c := newCoverageCache(t)
				const nodeID, name = "coverage-node", "resource"
				s := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
				var baseline *envoy_config_cluster.Cluster
				if haveBaseline {
					baseline = &envoy_config_cluster.Cluster{Name: name}
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, name, baseline, nil))
					s.reply(t, s.receive(t), "")
				}
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, name,
					&envoy_config_cluster.Cluster{Name: name, AltStatName: "rejected"}, nil))
				response := s.receive(t)
				var removed Rollback
				var err error
				if bulk {
					// A second deleted value exercises the multi-entry caller payload
					// and must remain eligible when only the first value is NACKed.
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "other", &envoy_config_cluster.Cluster{Name: "other"}, nil))
					removed, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{
						Removed: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{name: nil, "other": nil}},
					}, nil, typeurl.Set{})
				} else {
					removed, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Cluster, name, nil, nil)
				}
				require.NoError(t, err)
				s.reply(t, response, "rejected cluster")
				require.NoError(t, removed.Revert())
				if baseline == nil {
					require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, name))
				} else {
					require.Same(t, baseline, c.GetResource(nodeID, typeurl.Cluster, name))
				}
				if bulk {
					require.NotNil(t, c.GetResource(nodeID, typeurl.Cluster, "other"))
				}
			})
		}
	}
}

func TestNetworkPolicyWaitCompletesWhenLastListenerIsReverted(t *testing.T) {
	observer := &testNPDSListenerObserver{
		nodeID: "node1",
		matches: func(listener *envoy_config_listener.Listener) bool {
			return listener.GetName() == "npds-listener"
		},
	}
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithListenerObserver(observer), WithNodeIDs("node1"))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	listenerRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.Listener, "npds-listener",
		&envoy_config_listener.Listener{Name: "npds-listener"}, nil)

	require.NoError(t, err)
	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, wg)

	require.NoError(t, err)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())

	require.NoError(t, listenerRollback.Revert())
	require.Zero(t, observer.count)
	require.NoError(t, wg.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NotNil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"))
}

func TestFirstUntrackedSnapshotNACKRevertsColdStartResources(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)

	// Initial endpoint policies are populated before Envoy connects and do not
	// have WaitGroups. Caller finalization must leave the coalesced response
	// rollback intact so the first response can still be NACKed safely.
	for id := uint64(1); id <= 2; id++ {
		name := strconv.FormatUint(id, 10)
		rollback, err := c.ApplyResourceWithRollback(
			ctx, "node1", typeurl.NetworkPolicy,
			name, &cilium.NetworkPolicy{EndpointId: id}, nil)

		require.NoError(t, err)
		require.NotNil(t, rollback)
		rollback.Finalize()
	}

	state := c.getNodeState("node1")
	require.NotNil(t, state.pendingPublication)
	coldStartRollback, exists := state.pendingPublication.rollbacks.Get(typeurl.NetworkPolicy)
	require.True(t, exists)
	require.True(t, state.rollbacks.responses.Empty(), "unpublished state needs no response lifecycle")
	require.Len(t, coldStartRollback, 2)
	for _, rollback := range coldStartRollback {
		require.Nil(t, rollback.previous.resource,
			"cold-start rollback must not retain a protobuf that did not exist")
		require.Zero(t, rollback.previous.revision)
	}

	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: typeurl.NetworkPolicyURL,
	}
	responses := make(chan cache.Response, 1)
	cancelWatch, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	response := <-responses

	const nonce = "cold-start-response"
	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     typeurl.NetworkPolicyURL,
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          request.Node,
		TypeUrl:       typeurl.NetworkPolicyURL,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Message: "rejected initial policies"},
	}))

	for _, name := range []string{"1", "2"} {
		require.Nil(t, c.GetResource("node1", typeurl.NetworkPolicy, name),
			"a NACK of the first response must remove every seeded policy")
	}
}

func TestResourceUpdateRevertibleIsNoOpAfterFirstCall(t *testing.T) {
	for _, tt := range []struct {
		name          string
		failedRemoval bool
		bulk          bool
		superseded    bool
		remove        bool
	}{
		{name: "finalized-update"},
		{name: "superseded-update", superseded: true},
		{name: "superseded-removal", superseded: true, remove: true},
		{name: "failed-single-removal", failedRemoval: true},
		{name: "failed-bulk-removal", failedRemoval: true, bulk: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			var logs strings.Builder
			c.logger = slog.New(slog.NewTextHandler(&logs, nil))
			const nodeID, name = "node1", "route"
			// Keep a consumer so failed recovery must attempt publication.
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Route.URL(),
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			initialRollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, name,
				&envoy_config_route.RouteConfiguration{Name: name}, nil)
			require.NoError(t, err)
			initialRollback.Finalize()
			acceptPublishedSnapshotVersions(t, c, 1, &envoy_config_core.Node{Id: nodeID}, mustSnapshot(t, c, nodeID))

			var desired proto.Message = &envoy_config_route.RouteConfiguration{Name: name, IgnorePortInHostMatching: true}
			if tt.failedRemoval || tt.remove {
				desired = nil
			}
			var rollback Rollback
			if tt.bulk {
				rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID,
					ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{name: nil}}},
					nil, typeurl.Set{})
			} else {
				rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, name, desired, nil)
			}
			require.NoError(t, err)
			if tt.superseded {
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Route, name, desired, nil))
				logs.Reset()
				require.NoError(t, rollback.Revert())
				require.NotContains(t, logs.String(), "level=WARN", "an empty outstanding handle is still valid")
			} else if tt.failedRemoval {
				publicationErr := errors.New("snapshot publication failed")
				mock.setSnapshotErr = publicationErr
				require.ErrorIs(t, rollback.Revert(), publicationErr)
				mock.setSnapshotErr = nil
			} else {
				rollback.Finalize()
			}
			require.True(t, c.getNodeState(nodeID).rollbacks.callers.Empty(), "even failed recovery is terminal")
			generation := c.resourceGeneration
			logs.Reset()
			require.NoError(t, rollback.Revert())
			require.Contains(t, logs.String(), "level=WARN")
			require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
			logs.Reset()
			rollback.Finalize()
			require.Contains(t, logs.String(), "level=WARN")
			require.Contains(t, logs.String(), "Ignoring duplicate resource update rollback resolution")
			require.Equal(t, generation, c.resourceGeneration, "duplicate resolution must not publish an update")
			if desired == nil {
				require.Nil(t, c.GetResource(nodeID, typeurl.Route, name))
			} else {
				require.Same(t, desired, c.GetResource(nodeID, typeurl.Route, name))
			}
		})
	}
}

func TestApplyResourcesOwnsGlobalGenerationAndPerNodeReverts(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a", "node-b"))
	apply := func(nodeID string, endpointID uint64) Rollback {
		t.Helper()
		rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil)
		require.NoError(t, err)
		return rollback
	}
	applyPlain := func(nodeID string, endpointID uint64) {
		t.Helper()
		err := c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: endpointID}, nil)
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
		return newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a", "node-b"))
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
		rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node-a", mutations, nil, typeurl.Set{})
		require.NoError(t, err)
		require.NotNil(t, rollback)
		return rollback
	}
	applyPlain := func(t *testing.T, c *cacheImpl, mutations ResourceMutations) {
		t.Helper()
		err := c.ApplyResources(t.Context(), "node-a", mutations, nil, typeurl.Set{})
		require.NoError(t, err)
	}

	for _, tt := range []struct {
		name         string
		callerRevert bool
		reuse        bool
		withRollback bool
	}{
		{name: "NACK-driven"},
		{name: "caller-driven", callerRevert: true},
		{name: "caller-driven-reuse", callerRevert: true, reuse: true},
		{name: "caller-driven-reuse-with-rollback", callerRevert: true, reuse: true, withRollback: true},
		{name: "NACK-driven-reuse-with-rollback", reuse: true, withRollback: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
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
			if !tt.callerRevert {
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
			latest := map[string]uint64{"newer": 3}
			if tt.reuse {
				latest = map[string]uint64{"newer": 2, "other": 3}
			}
			var laterRollback Rollback
			if tt.withRollback {
				laterRollback = apply(t, c, routes(latest))
				t.Cleanup(func() {
					if laterRollback != nil {
						laterRollback.Finalize()
					}
				})
			} else {
				applyPlain(t, c, routes(latest))
			}

			if !tt.callerRevert {
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
			expectedNewer, revision, transaction := "3", callbacks.Generation(3), callbacks.Generation(3)
			if tt.reuse {
				if tt.callerRevert {
					expectedNewer, revision, transaction = "2", 2, 2
				} else {
					expectedNewer, revision, transaction = "1", 4, 1
				}
			}
			require.Equal(t, expectedNewer, c.GetResource("node-a", typeurl.Route, "newer").(*envoy_config_route.RouteConfiguration).Name,
				"caller recovery must preserve reused values; response recovery still rejects them")
			require.Equal(t, "1", c.GetResource("node-a", typeurl.Route, "unchanged").(*envoy_config_route.RouteConfiguration).Name,
				"the same revert must still restore resources untouched by newer API transactions")
			entries := c.getNodeState(node.Id).resources[typeurl.Route]
			require.Equal(t, revision.Revision(), entries["newer"].revision)
			require.Equal(t, transaction.TransactionID(), entries["newer"].transaction)
			require.Equal(t, callbacks.Generation(4).Revision(), entries["unchanged"].revision)
			require.Equal(t, callbacks.Generation(1).TransactionID(), entries["unchanged"].transaction)
			if tt.withRollback {
				require.NoError(t, laterRollback.Revert())
				laterRollback = nil
				require.Nil(t, c.GetResource("node-a", typeurl.Route, "other"))
				require.Equal(t, expectedNewer, c.GetResource("node-a", typeurl.Route, "newer").(*envoy_config_route.RouteConfiguration).Name,
					"the later mixed transaction did not change the reused value")
			}
		})
	}

	for _, api := range []string{"single", "bulk"} {
		for _, test := range []struct {
			name     string
			expected string
		}{
			{"no-later-change", "1"},
			{"newer-upsert", "3"},
			{"upsert-then-delete", ""},
			{"repeated-single-removal", ""},
			{"repeated-typed-nil-removal", ""},
			{"repeated-bulk-removal", ""},
			{"repeated-bulk-nil-upsert", ""},
			{"mixed-bulk-no-op-removal", ""},
			{"unrelated-name-removal", "1"},
			{"other-type-removal", "1"},
			{"other-node-removal", "1"},
		} {
			t.Run("removed/"+api+"/"+test.name, func(t *testing.T) {
				c := newCache(t)
				applyPlain(t, c, routes(map[string]uint64{"newer": 1, "unchanged": 1}))
				var rollback Rollback
				var err error
				if api == "single" {
					rollback, err = c.ApplyResourceWithRollback(t.Context(), "node-a", typeurl.Route, "newer", nil, nil)
				} else {
					removed := xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"newer": nil, "unchanged": nil}}
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), "node-a", ResourceMutations{Removed: removed}, nil, typeurl.Set{})
				}
				require.NoError(t, err)
				switch test.name {
				case "newer-upsert", "upsert-then-delete":
					applyPlain(t, c, routes(map[string]uint64{"newer": 3}))
					if test.name == "upsert-then-delete" {
						applyPlain(t, c, ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"newer": nil}}})
					}
				case "repeated-single-removal", "repeated-typed-nil-removal":
					var value proto.Message
					if test.name == "repeated-typed-nil-removal" {
						value = (*envoy_config_route.RouteConfiguration)(nil)
					}
					repeated, err := c.ApplyResourceWithRollback(t.Context(), "node-a", typeurl.Route, "newer", value, nil)
					require.NoError(t, err)
					repeated.Finalize()
				case "repeated-bulk-removal", "repeated-bulk-nil-upsert", "mixed-bulk-no-op-removal":
					var mutations ResourceMutations
					if test.name == "repeated-bulk-nil-upsert" {
						mutations.Upserted.Routes = map[string]*envoy_config_route.RouteConfiguration{"newer": nil}
					} else {
						mutations.Removed.Routes = map[string]*envoy_config_route.RouteConfiguration{"newer": nil}
						if test.name == "mixed-bulk-no-op-removal" {
							mutations.Upserted = routes(map[string]uint64{"other": 4}).Upserted
						}
					}
					applyPlain(t, c, mutations)
				case "unrelated-name-removal":
					applyPlain(t, c, ResourceMutations{Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"absent": nil}}})
				case "other-type-removal":
					require.NoError(t, c.ApplyResource(t.Context(), "node-a", typeurl.Cluster, "newer", nil, nil))
				case "other-node-removal":
					require.NoError(t, c.ApplyResource(t.Context(), "node-b", typeurl.Route, "newer", nil, nil))
				}

				require.NoError(t, rollback.Revert())
				actual := c.GetResource("node-a", typeurl.Route, "newer")
				if test.expected == "" {
					require.Nil(t, actual, "later deletions supersede the earlier restoration claim")
				} else {
					require.Equal(t, test.expected, actual.(*envoy_config_route.RouteConfiguration).Name)
				}
				require.Equal(t, "1", c.GetResource("node-a", typeurl.Route, "unchanged").(*envoy_config_route.RouteConfiguration).Name)
				require.True(t, c.getNodeState("node-a").rollbacks.callers.Empty(), "terminal resolution releases even fully superseded removal claims")
			})
		}
	}
}

func TestApplyResourcesRevertCoversEnvoyResourceTypes(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node-a"))
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
	applyPlain := func(resources xds.Resources) {
		t.Helper()
		err := c.ApplyResources(t.Context(), "node-a", ResourceMutations{Upserted: resources}, nil, typeurl.Set{})
		require.NoError(t, err)
	}

	baseline := resources(1, "newer", "unchanged", "removed")
	applyPlain(baseline)
	revert, err := c.ApplyResourcesWithRollback(t.Context(), "node-a", ResourceMutations{
		Removed: resources(1, "removed"), Upserted: resources(2, "newer", "unchanged"),
	}, nil, typeurl.Set{})
	require.NoError(t, err)
	require.NotNil(t, revert)
	newer := resources(3, "newer")
	applyPlain(newer)

	require.NoError(t, revert.Revert())
	for _, resource := range []struct {
		typeURL typeurl.Index
		newer   cache_types.Resource
		older   cache_types.Resource
		removed cache_types.Resource
	}{
		{typeurl.Listener, newer.Listeners["newer"], baseline.Listeners["unchanged"], baseline.Listeners["removed"]},
		{typeurl.Route, newer.Routes["newer"], baseline.Routes["unchanged"], baseline.Routes["removed"]},
		{typeurl.Cluster, newer.Clusters["newer"], baseline.Clusters["unchanged"], baseline.Clusters["removed"]},
		{typeurl.Endpoint, newer.Endpoints["newer"], baseline.Endpoints["unchanged"], baseline.Endpoints["removed"]},
		{typeurl.Secret, newer.Secrets["newer"], baseline.Secrets["unchanged"], baseline.Secrets["removed"]},
	} {
		actual := c.GetResource("node-a", resource.typeURL, "newer")
		require.NotNil(t, actual)
		require.Same(t, resource.newer, actual)
		actual = c.GetResource("node-a", resource.typeURL, "unchanged")
		require.NotNil(t, actual)
		require.Same(t, resource.older, actual)
		require.Same(t, resource.removed, c.GetResource("node-a", resource.typeURL, "removed"))
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
					rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, name, value, nil)
				} else {
					mutations := ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{name: value}}}
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, mutations, nil, typeurl.Set{})
				}
				require.NoError(t, err)
				return rollback
			}
			// Check source positions so the API/revert sequence stays readable.
			checkEntry := func(value *envoy_config_listener.Listener, revision, transaction callbacks.Generation) {
				t.Helper()
				expectedTransaction := transaction.TransactionID()
				entry := state.resourceWaitEntry(typeurl.Listener, name)
				require.Equal(t, revision.Revision(), entry.revision)
				require.Equal(t, expectedTransaction, entry.transaction)
				if value == nil {
					require.Nil(t, entry.resource)
				} else {
					require.Same(t, value, entry.resource)
				}
				pending, _ := state.pendingPublication.rollbacks.Get(typeurl.Listener)
				if inverse, exists := pending[name]; exists {
					require.Equal(t, expectedTransaction, inverse.expectedTransaction,
						"an unpublished rollback must follow the API value restored by a caller revert")
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
			update = apply(third)
			checkEntry(third, 4, 4)
			// The restored transaction, not the fresh revision, lets the older
			// lifecycle match its original change and continue the inverse chain.
			require.NoError(t, update.Revert())
			checkEntry(a, 5, 1)
			require.NoError(t, insert.Revert())
			checkEntry(nil, 6, 0)
			insert = apply(third)
			checkEntry(third, 7, 7)
			removal := apply(nil)
			require.NotNil(t, removal)
			removal.Finalize()
			require.NoError(t, insert.Revert())
			require.Equal(t, callbacks.Generation(8), c.resourceGeneration, "an older upsert rollback cannot undo a removal")
			require.Nil(t, c.GetResource(nodeID, typeurl.Listener, name))
			require.Empty(t, state.resources[typeurl.Listener], "removals retain no desired entries")
		})
	}
}

func TestCallerRevertRestoresPreviouslyAbsentResources(t *testing.T) {
	for _, test := range []struct {
		name           string
		bulk           bool
		priorRemoval   bool
		nack           bool
		skipRemovalACK bool
	}{
		{name: "single"},
		{name: "bulk", bulk: true},
		{name: "single/prior-ACKed-removal", priorRemoval: true},
		{name: "bulk/prior-ACKed-removal", bulk: true, priorRemoval: true},
		{name: "single/NACK-after-ACKed-removal", priorRemoval: true, nack: true},
		{name: "bulk/NACK-after-ACKed-removal", bulk: true, priorRemoval: true, nack: true},
		{name: "single/prior-unacknowledged-removal", priorRemoval: true, skipRemovalACK: true},
		{name: "bulk/prior-unacknowledged-removal", bulk: true, priorRemoval: true, skipRemovalACK: true},
		{name: "single/NACK-after-unacknowledged-removal", priorRemoval: true, nack: true, skipRemovalACK: true},
		{name: "bulk/NACK-after-unacknowledged-removal", bulk: true, priorRemoval: true, nack: true, skipRemovalACK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const nodeID = "coverage-node"
			c := newCoverageCache(t)
			cluster := &envoy_config_cluster.Cluster{Name: "resource", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
			secret := testSecret("resource", "current")
			typeURLs := typeurl.NewSet(typeurl.Cluster)
			if test.bulk {
				typeURLs.Insert(typeurl.Secret)
			}
			if test.priorRemoval {
				var removed xds.Resources
				removed.Clusters = map[string]*envoy_config_cluster.Cluster{"resource": {Name: "resource"}}
				if test.bulk {
					removed.Secrets = map[string]*envoy_config_tls.Secret{"resource": testSecret("resource", "previous")}
				}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: removed}, nil, typeurl.Set{}))
				for typeURL := range typeURLs.Members() {
					s := coverageStream{cache: c, id: 1, typeURL: typeURL.URL()}
					s.reply(t, s.receive(t, "resource"), "", "resource")
				}
				previousRemoval, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{Removed: removed}, nil, typeurl.Set{})
				require.NoError(t, err)
				previousRemoval.Finalize()
				if !test.skipRemovalACK {
					// Resolve the preceding response before replacement.
					for typeURL := range typeURLs.Members() {
						s := coverageStream{cache: c, id: 1, typeURL: typeURL.URL()}
						s.reply(t, s.receive(t, "resource"), "", "resource")
					}
				}
			}
			var rollback Rollback
			var err error
			if !test.bulk {
				rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Cluster, cluster.Name, cluster, nil)
			} else {
				rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Clusters: map[string]*envoy_config_cluster.Cluster{cluster.Name: cluster},
					Secrets:  map[string]*envoy_config_tls.Secret{secret.Name: secret},
				}}, nil, typeurl.Set{})
			}
			require.NoError(t, err)
			require.NotNil(t, rollback)
			for typeURL := range typeURLs.Members() {
				require.NotNil(t, c.GetResource(nodeID, typeURL, "resource"))
			}

			if test.nack {
				for typeURL := range typeURLs.Members() {
					s := coverageStream{cache: c, id: 1, typeURL: typeURL.URL()}
					s.reply(t, s.receive(t, "resource"), "invalid replacement", "resource")
				}
				rollback.Finalize()
			} else {
				// Both the inline inverse and its map-backed counterpart must
				// retain absence; otherwise the new value survives caller revert.
				require.NoError(t, rollback.Revert())
			}
			snapshot := requestSnapshotForTest(t, c, nodeID, typeurl.Cluster)
			for typeURL := range typeURLs.Members() {
				require.Nil(t, c.GetResource(nodeID, typeURL, "resource"))
				require.Empty(t, snapshot.GetResources(typeURL.URL()))
				require.Empty(t, c.getNodeState(nodeID).resources[typeURL], "restoring absence must not retain an entry")
			}
		})
	}
}
func TestFinalizedRemovalsNeedNoLifecycleBeforeResponse(t *testing.T) {
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
					name, &cilium.NetworkPolicy{EndpointId: uint64(id)}, nil)
				require.NoError(t, err)
				rollback.Finalize()
			}
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.NetworkPolicyURL}
			initial := s.receive(t, test.names...)
			s.reply(t, initial, "", test.names...)

			var wg *completion.WaitGroup
			var responses chan cache.Response
			if test.tracked {
				wg = completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				responses = make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(&cache.Request{
					Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.NetworkPolicyURL,
					VersionInfo: initial.VersionInfo, ResourceNames: test.names,
				}, s.sub, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
			}
			for id := range test.resources {
				name := strconv.Itoa(id)
				rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeurl.NetworkPolicy, name, nil, wg)
				require.NoError(t, err)
				require.NotNil(t, rollback)
				rollback.Finalize()
				require.Nil(t, c.getNodeState(nodeID).resources[typeurl.NetworkPolicy][name].resource)
			}
			var response *discovery.DiscoveryResponse
			if test.tracked {
				require.Empty(t, c.getNodeState(nodeID).resources[typeurl.NetworkPolicy],
					"admitted removals retain no entries while awaiting a response")
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
			require.Empty(t, state.resources[typeurl.NetworkPolicy])
			c.completionCbs.OnStreamClosed(1, &envoy_config_core.Node{Id: nodeID})
			require.Same(t, state, c.getNodeState(nodeID), "known nodes remain after all resources and streams are gone")
			require.Empty(t, state.resources[typeurl.NetworkPolicy])
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
			{name: "removal-with-live-wait", remove: true, tracked: true, reject: true},
			{name: "removal-ACK", remove: true},
			{name: "removal-ACK-disconnect", remove: true, closeStream: true},
			{name: "removal-NACK", remove: true, reject: true},
			{name: "removal-ACK-before-caller-revert", remove: true, revert: true},
			{name: "removal-NACK-before-caller-revert", remove: true, reject: true, revert: true},
			{name: "removal-ACK-disconnect-before-caller-revert", remove: true, closeStream: true, revert: true},
			{name: "replacement-with-canceled-wait", tracked: true, cancelWait: true, callerFirst: true, reject: true},
			{name: "ACK-before-caller-finalize"},
			{name: "ACK-before-caller-revert", revert: true},
			{name: "ACK-disconnect-before-caller-finalize", closeStream: true},
			{name: "ACK-disconnect-before-caller-revert", closeStream: true, revert: true},
			{name: "NACK-before-caller-finalize", reject: true},
			{name: "NACK-before-caller-revert", reject: true, revert: true},
		} {
			t.Run(api.name+"/"+test.name, func(t *testing.T) {
				c := newCoverageCache(t)
				const nodeID = "coverage-node"
				ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancelContext)
				caller, err := c.ApplyResourceWithRollback(ctx, nodeID, api.typeURL, "resource", api.original, nil)
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
					var waits typeurl.Set
					if wg != nil {
						waits.Insert(api.typeURL)
					}
					caller, err = c.ApplyResourcesWithRollback(ctx, nodeID, mutations, wg, waits)
				} else {
					caller, err = c.ApplyResourceWithRollback(ctx, nodeID, api.typeURL, "resource", next, wg)
				}
				require.NoError(t, err)
				require.NotNil(t, caller)
				t.Cleanup(func() { caller.Finalize() })
				// Replacement recovery must survive even a canceled caller wait.
				if test.callerFirst && !test.cancelWait {
					caller.Finalize()
					caller = revert.Noop
				}
				response := s.deliver(t, <-responses)
				if test.remove {
					require.Empty(t, response.Resources)
				}
				if test.cancelWait {
					cancelWait()
					require.ErrorIs(t, wg.Wait(), context.Canceled)
					caller.Finalize()
					caller = revert.Noop
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
				if test.remove && test.reject && wg != nil {
					require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "a removal wait survives NACK")
					s.reply(t, s.receive(t), "")
				}
				if test.closeStream {
					c.completionCbs.OnStreamClosed(s.id, &envoy_config_core.Node{Id: nodeID})
				}
				if test.revert {
					require.NoError(t, caller.Revert())
				} else {
					caller.Finalize()
				}
				caller = revert.Noop
				if test.remove && !test.revert {
					require.Nil(t, c.GetResource(nodeID, api.typeURL, "resource"))
					require.Nil(t, c.getNodeState(nodeID).resources[api.typeURL])
				} else if test.revert || test.reject {
					require.Same(t, api.original, c.GetResource(nodeID, api.typeURL, "resource"),
						"the remaining owner must still be able to restore the resource")
				} else {
					require.Same(t, next, c.GetResource(nodeID, api.typeURL, "resource"))
				}
				if wg != nil && !test.cancelWait {
					if test.reject && !test.remove {
						require.ErrorContains(t, wg.Wait(), rejection)
					} else {
						require.NoError(t, wg.Wait())
					}
				}
			})
		}
	}
}
