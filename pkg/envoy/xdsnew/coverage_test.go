// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
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

func TestNoOpUpdateWaitsForResourceOutcome(t *testing.T) {
	for _, api := range []struct {
		name  string
		index typeurl.Index
		value proto.Message
		bulk  bool
	}{
		{name: "listener-single", index: typeurl.Listener, value: &listener.Listener{Name: "resource"}},
		{name: "listener-bulk", index: typeurl.Listener, value: &listener.Listener{Name: "resource"}, bulk: true},
		{name: "policy-single", index: typeurl.NetworkPolicy, value: &cilium.NetworkPolicy{EndpointId: 1}},
	} {
		for _, withRollback := range []bool{false, true} {
			for _, samePointer := range []bool{false, true} {
				for _, outcome := range []struct {
					name             string
					phase            string
					rejection        string
					publishUnrelated bool
				}{
					{name: "before-response/ack", phase: "before-response"},
					{name: "before-response/nack", phase: "before-response", rejection: "invalid resource"},
					{name: "after-response/ack", phase: "after-response"},
					{name: "after-response/nack", phase: "after-response", rejection: "invalid resource"},
					{name: "after-ack", phase: "after-ack"},
					{name: "after-nack", phase: "after-nack", rejection: "invalid resource"},
					{name: "after-unrelated-publication/ack", phase: "after-response", publishUnrelated: true},
					{name: "after-unrelated-publication/nack", phase: "after-response", rejection: "invalid resource", publishUnrelated: true},
					{name: "delayed-response/ack", phase: "delayed-response", publishUnrelated: true},
					{name: "delayed-response/nack", phase: "delayed-response", rejection: "invalid resource", publishUnrelated: true},
				} {
					t.Run(fmt.Sprintf("%s/rollback=%t/same-pointer=%t/%s", api.name, withRollback, samePointer, outcome.name), func(t *testing.T) {
						c := newCoverageCache(t)
						var caller Rollback = revert.Noop
						var err error
						if outcome.phase == "after-nack" {
							// A plain upsert survives rejection, so resubmitting it is
							// still a no-op and must use the known NACK outcome.
							err = c.ApplyResource(t.Context(), "coverage-node", api.index, "resource", api.value, nil)
						} else {
							caller, err = c.ApplyResourceWithRollback(t.Context(), "coverage-node", api.index, "resource", api.value, nil)
						}
						require.NoError(t, err)
						t.Cleanup(func() {
							if caller != nil {
								caller.Finalize()
							}
						})
						s := coverageStream{cache: c, id: 1, typeURL: api.index.URL()}
						var response *discovery.DiscoveryResponse
						var queued chan cache.Response
						switch outcome.phase {
						case "before-response":
						case "delayed-response":
							queued = s.watch(t)
							require.Len(t, queued, 1)
						default:
							response = s.receive(t)
						}
						if outcome.publishUnrelated {
							before := mustSnapshot(t, c, "coverage-node")
							require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Secret, "unrelated", testSecret("unrelated", "value"), nil))
							other := coverageStream{cache: c, id: s.id, typeURL: typeurl.Secret.URL()}
							other.reply(t, other.receive(t, "unrelated"), "", "unrelated")
							after := mustSnapshot(t, c, "coverage-node")
							require.NotEqual(t, before.GetVersion(typeurl.Secret.URL()), after.GetVersion(typeurl.Secret.URL()))
							require.Equal(t, before.GetVersion(api.index.URL()), after.GetVersion(api.index.URL()))
						}
						if queued != nil {
							// Deliver the captured response after another type has advanced
							// the publication boundary, before registering the no-op wait.
							response = s.deliver(t, <-queued)
						}
						if outcome.phase == "after-ack" || outcome.phase == "after-nack" {
							s.reply(t, response, outcome.rejection)
						}

						published, _ := c.GetSnapshot("coverage-node")
						ctx, cancel := context.WithTimeout(t.Context(), time.Second)
						t.Cleanup(cancel)
						wg := completion.NewWaitGroup(ctx)
						t.Cleanup(wg.Cancel)
						candidate := api.value
						if !samePointer {
							candidate = proto.Clone(candidate)
						}
						var reused Rollback
						if api.bulk {
							waits := typeurl.NewSet(api.index)
							mutations := ResourceMutations{Upserted: xds.Resources{
								Listeners: map[string]*listener.Listener{"resource": candidate.(*listener.Listener)},
							}}
							if withRollback {
								reused, err = c.ApplyResourcesWithRollback(ctx, "coverage-node", mutations, wg, waits)
							} else {
								err = c.ApplyResources(ctx, "coverage-node", mutations, wg, waits)
							}
						} else if withRollback {
							reused, err = c.ApplyResourceWithRollback(ctx, "coverage-node", api.index, "resource", candidate, wg)
						} else {
							err = c.ApplyResource(ctx, "coverage-node", api.index, "resource", candidate, wg)
						}
						require.NoError(t, err)
						t.Cleanup(func() {
							if reused != nil {
								reused.Finalize()
							}
						})
						// Reusing this value prevents the first caller from undoing
						// it. The later caller made no change to undo either.
						require.NoError(t, caller.Revert())
						caller = nil
						if reused != nil {
							require.NoError(t, reused.Revert())
							reused = nil
						}
						currentSnapshot, _ := c.GetSnapshot("coverage-node")
						if published == nil {
							require.Nil(t, currentSnapshot, "a pending no-op must not publish")
						} else {
							require.Same(t, published, currentSnapshot, "a semantic no-op must not publish")
						}
						current := c.GetResource("coverage-node", api.index, "resource")
						require.NotNil(t, current)
						require.Same(t, api.value, current,
							"neither caller's rollback may remove the reused value")
						if outcome.phase != "after-ack" && outcome.phase != "after-nack" {
							require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
							if response == nil {
								response = s.receive(t)
							}
							s.reply(t, response, outcome.rejection)
						} else {
							require.Zero(t, c.completionCbs.PendingCompletionCount(), "a known outcome must resolve the no-op without another response")
						}
						if outcome.rejection == "" {
							require.NoError(t, wg.Wait())
						} else {
							require.ErrorContains(t, wg.Wait(), outcome.rejection)
							if outcome.phase != "after-nack" && withRollback {
								require.Nil(t, c.GetResource("coverage-node", api.index, "resource"),
									"caller supersession must preserve opted-in response recovery")
							} else {
								require.Same(t, api.value, c.GetResource("coverage-node", api.index, "resource"),
									"a plain upsert or reuse must remain non-revertible")
							}
						}
						require.Zero(t, c.completionCbs.PendingCompletionCount())
					})
				}
			}
		}
	}
}

func TestNoOpUpdateAfterFailedNACKCompletesWithRejection(t *testing.T) {
	c := newCoverageCache(t)
	first := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", first, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.NetworkPolicy.URL()}
	s.reply(t, s.receive(t), "")
	rejected := &cilium.NetworkPolicy{EndpointId: 2}
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", rejected, nil))
	response := s.receive(t)
	published := mustSnapshot(t, c, "coverage-node")

	// A failed corrective publication leaves the rejected entry in desired
	// state. A no-op submitted before stream closure must fail immediately,
	// rather than await an ACK for a version Envoy already rejected.
	publicationErr := errors.New("corrective publication failed")
	restore := c.replaceSnapshotCache(t, &mockSnapshotCache{
		snapshots: map[string]cache.ResourceSnapshot{"coverage-node": published}, setSnapshotErr: publicationErr,
	})
	// Keep a policy watch available so response recovery attempts publication
	// now. Otherwise the compensation commits unpublished changes for the next watch.
	cancelWatch, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.typeURL, VersionInfo: response.VersionInfo,
	}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	require.ErrorIs(t, c.completionCbs.OnStreamRequest(s.id, &discovery.DiscoveryRequest{
		TypeUrl: s.typeURL, VersionInfo: s.version, ResponseNonce: response.Nonce,
		ErrorDetail: &status.Status{Message: "invalid policy"},
	}), publicationErr)
	restore()
	current := c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy")
	require.NotNil(t, current)
	require.Same(t, rejected, current)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.applyRevertibleResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
		proto.Clone(rejected), wg))
	require.ErrorContains(t, wg.Wait(), "invalid policy")
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.Same(t, published, mustSnapshot(t, c, "coverage-node"))
}

func TestUntrackedUpdateResolvesEarlierWait(t *testing.T) {
	for _, delivery := range []string{"open-watch", "immediate-watch"} {
		t.Run(delivery, func(t *testing.T) {
			for _, rejection := range []string{"", "invalid policy"} {
				outcome := "ack"
				if rejection != "" {
					outcome = "nack"
				}
				t.Run(outcome, func(t *testing.T) {
					c := newCoverageCache(t)
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					t.Cleanup(cancel)
					wg := completion.NewWaitGroup(ctx)
					t.Cleanup(wg.Cancel)
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
						&cilium.NetworkPolicy{EndpointId: 1}, wg))
					done := waitForCoverageCompletion(wg)
					s := coverageStream{cache: c, id: 1, typeURL: typeurl.NetworkPolicy.URL()}
					responses := make(chan cache.Response, 1)
					if delivery == "open-watch" {
						previous := s.receive(t)
						// The first response is still unacknowledged. Open the next
						// watch at its version, so publication supplies the response.
						request := &cache.Request{Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.typeURL, VersionInfo: previous.VersionInfo}
						cancel, err := c.CreateWatch(request, s.sub, responses)
						require.NoError(t, err)
						t.Cleanup(cancel)
					}
					latest := &cilium.NetworkPolicy{EndpointId: 2}
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy", latest, nil))
					requireCoveragePending(t, done)
					var response *discovery.DiscoveryResponse
					if delivery == "open-watch" {
						select {
						case queued := <-responses:
							response = s.deliver(t, queued)
						default:
							t.Fatal("publication did not answer the open watch")
						}
					} else {
						response = s.receive(t)
					}
					require.Len(t, response.Resources, 1)
					var delivered cilium.NetworkPolicy
					require.NoError(t, response.Resources[0].UnmarshalTo(&delivered))
					require.True(t, proto.Equal(latest, &delivered))
					s.reply(t, response, rejection)
					if rejection == "" {
						require.NoError(t, <-done)
					} else {
						require.ErrorContains(t, <-done, rejection)
						require.Same(t, latest, c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy"), "plain upserts remain desired after a NACK")
					}
					require.Zero(t, c.completionCbs.PendingCompletionCount())
				})
			}
		})
	}
}

func TestBulkNACKRollbackRequiresOptIn(t *testing.T) {
	for _, tt := range []struct {
		name     string
		waits    typeurl.Set
		wait     bool
		finalize bool
	}{
		{name: "zero-selector"},
		{name: "empty-selector", waits: typeurl.NewSet()},
		{name: "explicit-selector", waits: typeurl.NewSet(typeurl.Listener, typeurl.Route)},
		{name: "caller-finalized", finalize: true},
		{name: "caller-finalized-explicit-selector", finalize: true, waits: typeurl.NewSet(typeurl.Listener, typeurl.Route)},
		{name: "caller-finalized-with-wait-group", finalize: true, wait: true, waits: typeurl.NewSet(typeurl.Listener, typeurl.Route)},
		{name: "zero-selector-with-wait-group", wait: true},
		{name: "empty-selector-with-wait-group", wait: true, waits: typeurl.NewSet()},
		{name: "explicit-selector-with-wait-group", wait: true, waits: typeurl.NewSet(typeurl.Listener, typeurl.Route)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t)
			mutations := ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*listener.Listener{"l1": {Name: "l1"}},
				Routes:    map[string]*route.RouteConfiguration{"r1": {Name: "r1"}},
			}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			var wg *completion.WaitGroup
			if tt.wait {
				wg = completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
			}
			if tt.finalize {
				rollback, err := c.ApplyResourcesWithRollback(ctx, "coverage-node", mutations, wg, tt.waits)
				require.NoError(t, err)
				require.NotNil(t, rollback)
				rollback.Finalize()
			} else {
				require.NoError(t, c.ApplyResources(ctx, "coverage-node", mutations, wg, tt.waits))
			}
			// Reusing the value with the same API preserves its rollback policy,
			// independently of whether this call supplies a WaitGroup.
			if tt.finalize {
				require.NoError(t, c.applyRevertibleResources(ctx, "coverage-node", mutations, nil, tt.waits))
			} else {
				require.NoError(t, c.ApplyResources(ctx, "coverage-node", mutations, nil, tt.waits))
			}
			if !tt.wait || tt.waits.Empty() {
				require.Zero(t, c.completionCbs.PendingCompletionCount())
				if wg != nil {
					require.NoError(t, wg.Wait(), "an empty selector needs no ACK")
				}
			} else {
				require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
			}
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			response := s.receive(t, "l1")
			s.reply(t, response, "invalid listener", "l1")
			if tt.wait && !tt.waits.Empty() {
				require.ErrorContains(t, wg.Wait(), "invalid listener")
			}
			if tt.finalize {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "l1"))
			} else {
				require.Same(t, mutations.Upserted.Listeners["l1"], c.GetResource("coverage-node", typeurl.Listener, "l1"))
			}
			require.Same(t, mutations.Upserted.Routes["r1"], c.GetResource("coverage-node", typeurl.Route, "r1"),
				"an LDS NACK must leave RDS unchanged, even within one bulk transaction")
		})
	}
}

func TestPermanentUpsertsFenceResponseRollback(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		for _, phase := range []struct {
			name     string
			delivery string
			noop     bool
			fail     bool
		}{
			{name: "unpublished"},
			{name: "published-unsent", delivery: "unsent"},
			{name: "sent", delivery: "sent"},
			{name: "publication-fails", delivery: "sent", fail: true},
			{name: "unpublished-noop", noop: true},
			{name: "published-unsent-noop", delivery: "unsent", noop: true},
			{name: "sent-noop", delivery: "sent", noop: true},
			{name: "failed-mixed-noop", delivery: "sent", noop: true, fail: true},
		} {
			if !bulk && phase.noop && phase.fail {
				continue // Failed mixed admission necessarily uses the bulk API.
			}
			for _, sameName := range []bool{false, true} {
				for _, reject := range []bool{false, true} {
					t.Run(fmt.Sprintf("bulk=%t/%s/same-name=%t/nack=%t", bulk, phase.name, sameName, reject), func(t *testing.T) {
						c := newCoverageCache(t)
						old := &listener.Listener{Name: "internal", StatPrefix: "old-revertible"}
						originalCaller, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, old.Name, old, nil)
						require.NoError(t, err)
						t.Cleanup(func() { originalCaller.Finalize() })
						if phase.delivery == "sent" {
							s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
							s.receive(t)
						} else if phase.delivery == "unsent" {
							require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Cluster, "unrelated", &cluster.Cluster{Name: "unrelated"}, nil))
							s := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
							s.reply(t, s.receive(t), "")
						}

						wg := completion.NewWaitGroup(t.Context())
						t.Cleanup(wg.Cancel)
						permanent := &listener.Listener{Name: old.Name, StatPrefix: "permanent"}
						expectedPermanent := permanent
						if phase.noop {
							permanent = proto.Clone(old).(*listener.Listener)
							expectedPermanent = old
						}
						waits := typeurl.NewSet(typeurl.Listener)
						var publicationErr error
						backend := c.snapshotCache
						if phase.fail {
							failed := newMockSnapshotCache()
							failed.snapshots["coverage-node"] = mustSnapshot(t, c, "coverage-node")
							publicationErr = errors.New("permanent publication failed")
							failed.setSnapshotErr = publicationErr
							c.snapshotCache = failed
							cancelWatch, err := c.CreateWatch(&cache.Request{
								Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(),
								VersionInfo: failed.snapshots["coverage-node"].GetVersion(typeurl.Listener.URL()),
							}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
							require.NoError(t, err)
							defer cancelWatch()
						}
						if bulk {
							upserted := xds.Resources{Listeners: map[string]*listener.Listener{permanent.Name: permanent}}
							if phase.noop && phase.fail {
								upserted.Listeners["other"] = &listener.Listener{Name: "other"}
							}
							err = c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{Upserted: upserted}, wg, waits)
						} else {
							err = c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, permanent.Name, permanent, wg)
						}
						c.snapshotCache = backend
						if publicationErr != nil {
							require.ErrorIs(t, err, publicationErr)
							require.ErrorIs(t, wg.Wait(), publicationErr)
							require.Same(t, old, c.GetResource("coverage-node", typeurl.Listener, old.Name))
						} else {
							require.NoError(t, err)
							if phase.noop {
								require.NoError(t, originalCaller.Revert(), "adoption fences an older caller handle without changing its transaction")
								originalCaller = revert.Noop
								require.Same(t, old, c.GetResource("coverage-node", typeurl.Listener, old.Name))
							}
						}

						name := "cec"
						if sameName {
							name = old.Name
						}
						cec := &listener.Listener{Name: name, StatPrefix: "cec"}
						cecWG := completion.NewWaitGroup(t.Context())
						t.Cleanup(cecWG.Cancel)
						rollback, err := c.ApplyResourcesWithRollback(t.Context(), "coverage-node", ResourceMutations{Upserted: xds.Resources{
							Listeners: map[string]*listener.Listener{name: cec},
						}}, cecWG, waits)
						require.NoError(t, err)
						s := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
						response := s.receive(t)
						if reject {
							s.reply(t, response, "invalid CEC listener")
							require.ErrorContains(t, cecWG.Wait(), "invalid CEC listener")
							if publicationErr == nil {
								require.ErrorContains(t, wg.Wait(), "invalid CEC listener")
								require.Same(t, expectedPermanent, c.GetResource("coverage-node", typeurl.Listener, old.Name), "permanent updates break both pending and unsent recovery chains")
							} else {
								require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, old.Name), "failed admission must preserve the original response rollback")
							}
							if !sameName {
								require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, name))
							}
							require.NoError(t, rollback.Revert())
						} else {
							s.reply(t, response, "")
							require.NoError(t, cecWG.Wait())
							if publicationErr == nil {
								require.NoError(t, wg.Wait())
							}
							require.Same(t, cec, c.GetResource("coverage-node", typeurl.Listener, name))
							rollback.Finalize()
						}
					})
				}
			}
		}
	}
}

func TestBulkNoOpWaitUsesMatchingResourceRevision(t *testing.T) {
	for _, mode := range []string{"upsert", "remove-and-upsert", "absent-resource", "unmentioned-types"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			first := &listener.Listener{Name: "l1"}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "l1", first, nil))
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			// The first response covers l1 and the absence of "missing".
			// A later mutation must not change that response's generation.
			response := s.receive(t, "l1", "missing")
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "l2",
				&listener.Listener{Name: "l2"}, nil))
			var mutations ResourceMutations
			switch mode {
			case "upsert", "remove-and-upsert":
				mutations.Upserted.Listeners = map[string]*listener.Listener{"l1": proto.Clone(first).(*listener.Listener)}
				if mode == "remove-and-upsert" {
					mutations.Removed.Listeners = map[string]*listener.Listener{"l1": nil}
				}
			case "absent-resource":
				mutations.Removed.Listeners = map[string]*listener.Listener{"missing": nil}
			}
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			waits := typeurl.NewSet(typeurl.Listener)
			pending := 1
			if mode == "unmentioned-types" {
				waits = typeurl.All()
				pending = 0
			}
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
			require.Equal(t, pending, c.completionCbs.PendingCompletionCount())
			s.reply(t, response, "", "l1", "missing")
			require.Zero(t, c.completionCbs.PendingCompletionCount(), "ACK must complete the matching bulk wait")
			require.NoError(t, wg.Wait())
		})
	}
}

func TestBulkNACKAndCallerRollbackHaveIndependentScopes(t *testing.T) {
	for _, rejectedType := range []typeurl.Index{typeurl.Listener, typeurl.Route, typeurl.Cluster, typeurl.Endpoint, typeurl.Secret} {
		for _, acknowledged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/other-types-acked=%t", rejectedType.URL(), acknowledged), func(t *testing.T) {
				c := newCoverageCache(t)
				mutations := ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*listener.Listener{"resource": {Name: "resource"}},
					Routes:    map[string]*route.RouteConfiguration{"resource": {Name: "resource"}},
					Clusters:  map[string]*cluster.Cluster{"resource": {Name: "resource"}},
					Endpoints: map[string]*endpoint.ClusterLoadAssignment{"resource": {ClusterName: "resource"}},
					Secrets:   map[string]*secret.Secret{"resource": {Name: "resource"}},
				}}
				caller, err := c.ApplyResourcesWithRollback(t.Context(), "coverage-node", mutations, nil, typeurl.NewSet())
				require.NoError(t, err)
				t.Cleanup(func() { caller.Finalize() })
				values := typeurl.Slots[proto.Message]{
					typeurl.Listener: mutations.Upserted.Listeners["resource"],
					typeurl.Route:    mutations.Upserted.Routes["resource"],
					typeurl.Cluster:  mutations.Upserted.Clusters["resource"],
					typeurl.Endpoint: mutations.Upserted.Endpoints["resource"],
					typeurl.Secret:   mutations.Upserted.Secrets["resource"],
				}
				if acknowledged {
					for index, value := range values {
						if value == nil || typeurl.Index(index) == rejectedType {
							continue
						}
						s := coverageStream{cache: c, id: 1, typeURL: typeurl.Index(index).URL()}
						s.reply(t, s.receive(t, "resource"), "", "resource")
					}
				}
				s := coverageStream{cache: c, id: 1, typeURL: rejectedType.URL()}
				s.reply(t, s.receive(t, "resource"), "invalid resource", "resource")
				for index, value := range values {
					if value == nil {
						continue
					}
					current := c.GetResource("coverage-node", typeurl.Index(index), "resource")
					if typeurl.Index(index) == rejectedType {
						require.Nil(t, current)
					} else {
						require.Same(t, value, current, "NACK recovery must be TypeURL-local")
					}
				}
				// Caller failure still undoes all upserts in the API transaction,
				// including resources already accepted by Envoy.
				require.NoError(t, caller.Revert())
				caller = revert.Noop
				for index, value := range values {
					if value != nil {
						require.Nil(t, c.GetResource("coverage-node", typeurl.Index(index), "resource"))
					}
				}
				require.True(t, c.getNodeState("coverage-node").rollbacks.callers.Empty())
			})
		}
	}
}

func TestPartialResponsesAtSameGenerationAccumulate(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-second=%t", reject), func(t *testing.T) {
			c := newCoverageCache(t)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			waits := typeurl.NewSet()
			waits.Insert(typeurl.Endpoint)
			require.NoError(t, c.applyRevertibleResources(t.Context(), "coverage-node", ResourceMutations{
				Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
					"a": {ClusterName: "a"}, "b": {ClusterName: "b"},
				}},
			}, wg, waits))
			first := coverageStream{cache: c, id: 1}
			second := coverageStream{cache: c, id: 2}
			a := first.receive(t, "a")
			b := second.receive(t, "b")
			require.Equal(t, a.VersionInfo, b.VersionInfo)
			first.reply(t, a, "", "a")
			require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
			if reject {
				second.reply(t, b, "invalid b", "b")
				require.ErrorContains(t, wg.Wait(), "invalid b")
				require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"),
					"the ACKed named response has its own outcome")
				require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
			} else {
				second.reply(t, b, "", "b")
				require.NoError(t, wg.Wait())
			}
		})
	}
}

func TestPartialResponseNoOpWaitsForItsOwnResource(t *testing.T) {
	c := newCoverageCache(t)
	a, aDone := upsertCoverageEndpoint(t, c, "a")
	b, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	// Attach a semantic no-op after response delivery, but before the ACK.
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "b", b, wg))
	noOp := waitForCoverageCompletion(wg)
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)
	requireCoveragePending(t, noOp)
	// A is already accepted; its no-op must not wait for B's later response,
	// nor complete B's existing wait as a side effect.
	acceptedWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(acceptedWG.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", a, acceptedWG))
	require.NoError(t, acceptedWG.Wait())
	requireCoveragePending(t, bDone)
	requireCoveragePending(t, noOp)
	response = s.receive(t, "a", "b")
	s.reply(t, response, "", "a", "b")
	require.NoError(t, <-bDone)
	require.NoError(t, <-noOp)
}

func TestNoOpWaitAfterClearSnapshot(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			for _, rejection := range []string{"", "listener response rejected"} {
				t.Run(fmt.Sprintf("bulk=%t/existing=%t/nack=%t", bulk, existing, rejection != ""), func(t *testing.T) {
					c := newCoverageCache(t)
					policy := &cilium.NetworkPolicy{EndpointId: 1}
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil))
					var resource *listener.Listener
					if existing {
						resource = &listener.Listener{Name: "listener"}
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil))
					}
					c.ClearSnapshot("coverage-node")
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					t.Cleanup(cancel)
					wg := completion.NewWaitGroup(ctx)
					t.Cleanup(wg.Cancel)
					if bulk {
						var waits typeurl.Set
						waits.Insert(typeurl.Listener)
						require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{Upserted: xds.Resources{
							Listeners: map[string]*listener.Listener{"listener": resource},
						}}, wg, waits))
					} else {
						require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "listener", resource, wg))
					}
					require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
					_, err := c.GetSnapshot("coverage-node")
					require.Error(t, err, "a no-op must not force publication")
					s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
					response := s.receive(t)
					require.Equal(t, existing, len(response.Resources) != 0)
					require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
					s.reply(t, response, rejection)
					if rejection != "" && !existing {
						require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
						s.reply(t, s.receive(t), "")
					}
					if rejection == "" || !existing {
						require.NoError(t, wg.Wait())
					} else {
						require.ErrorContains(t, wg.Wait(), rejection)
					}
					current := c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy")
					require.NotNil(t, current)
					require.Same(t, policy, current, "an LDS outcome must not revert the unrelated policy")
				})
			}
		}
	}
}

func TestInitialBulkMutationCanAwaitUnchangedType(t *testing.T) {
	for _, tt := range []struct {
		name    string
		pending int
	}{
		{name: "removal", pending: 1},
		{name: "unmentioned-types"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			waits := typeurl.All()
			waits.Remove(typeurl.Cluster)
			// The first real mutation can also require ACK evidence for an unchanged
			// type. Preparing that wait must not require an already published snapshot.
			resource := &cluster.Cluster{Name: "cluster"}
			mutations := ResourceMutations{
				Upserted: xds.Resources{Clusters: map[string]*cluster.Cluster{resource.Name: resource}},
			}
			if tt.pending != 0 {
				mutations.Removed.Listeners = map[string]*listener.Listener{"absent": nil}
			}
			require.NoError(t, c.ApplyResources(ctx, "coverage-node", mutations, wg, waits))
			require.Equal(t, tt.pending, c.completionCbs.PendingCompletionCount())
			if tt.pending != 0 {
				s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
				response := s.receive(t)
				require.Empty(t, response.Resources)
				require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				s.reply(t, response, "")
			}
			require.NoError(t, wg.Wait())
			current := c.GetResource("coverage-node", typeurl.Cluster, resource.Name)
			require.NotNil(t, current)
			require.Same(t, resource, current)
		})
	}
}

func TestNoOpWaitAfterClearRequiresFreshACK(t *testing.T) {
	c := newCoverageCache(t)
	resource := &listener.Listener{Name: "listener"}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	s.reply(t, s.receive(t), "")
	c.ClearSnapshot("coverage-node")
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, wg))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	// Republishing identical contents must not restore cleared acceptance
	// evidence. The wait still needs an ACK for the new response.
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(),
	}, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "publication alone must not complete the wait")
	require.Len(t, responses, 1)
	response := s.deliver(t, <-responses)
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "response delivery alone must not complete the wait")
	s.reply(t, response, "")
	require.NoError(t, wg.Wait())
}

func TestFailedPublicationPreservesPartialACKForNoOp(t *testing.T) {
	c := newCoverageCache(t)
	a, aDone := upsertCoverageEndpoint(t, c, "a")
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)

	// A subset ACK is the only evidence that A was accepted. A failed removal
	// must restore both desired state and that evidence: recording a candidate
	// snapshot too early would prune A's sparse ACK entry irreversibly.
	previous, err := c.GetSnapshot("coverage-node")
	require.NoError(t, err)
	publicationErr := errors.New("snapshot publication failed")
	failed := newMockSnapshotCache()
	failed.snapshots["coverage-node"] = previous
	failed.setSnapshotErr = publicationErr
	restore := c.replaceSnapshotCache(t, failed)
	// Keep an EDS watch open so failure is exercised by this mutation, not
	// deferred to a later request. The mock never consumes this watch.
	cancelWatch, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Endpoint.URL(),
		ResourceNames: []string{"a"}, VersionInfo: previous.GetVersion(typeurl.Endpoint.URL()),
	}, stream.NewSotwSubscription([]string{"a"}, false), make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	err = c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", nil, nil)
	restore()
	require.ErrorIs(t, err, publicationErr)
	current := c.GetResource("coverage-node", typeurl.Endpoint, "a")
	require.NotNil(t, current)
	require.Same(t, a, current)

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", a, wg))
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "only B may still be waiting after failed publication")
	require.NoError(t, wg.Wait())
	requireCoveragePending(t, bDone)
	response = s.receive(t, "b")
	s.reply(t, response, "", "b")
	require.NoError(t, <-bDone)
}

func TestNoOpRemovalDoesNotWaitForUnrelatedListenerACK(t *testing.T) {
	for _, mode := range []string{"single", "single-typed-nil", "bulk-removal", "bulk-nil-upsert"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			for _, name := range []string{"a", "b"} {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, name,
					&listener.Listener{Name: name}, nil))
			}
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			response := s.receive(t)
			s.reply(t, response, "")
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", nil, nil))
			response = s.receive(t)
			s.reply(t, response, "")

			// A's removal is already ACKed. A newer, in-flight response changing
			// B must not make another removal of A wait for B's ACK. In bulk input,
			// a typed nil upsert has the same removal semantics as an explicit delete.
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "b",
				&listener.Listener{Name: "b", TrafficDirection: core.TrafficDirection_OUTBOUND}, wg))
			bDone := waitForCoverageCompletion(wg)
			response = s.receive(t)
			requireCoveragePending(t, bDone)

			removalWG := completion.NewWaitGroup(t.Context())
			t.Cleanup(removalWG.Cancel)
			if mode == "single" {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", nil, removalWG))
			} else if mode == "single-typed-nil" {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", (*listener.Listener)(nil), removalWG))
			} else {
				mutations := ResourceMutations{}
				if mode == "bulk-removal" {
					mutations.Removed.Listeners = map[string]*listener.Listener{"a": nil}
				} else {
					mutations.Upserted.Listeners = map[string]*listener.Listener{"a": nil}
				}
				waits := typeurl.NewSet()
				waits.Insert(typeurl.Listener)
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, removalWG, waits))
			}
			require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "an already-ACKed removal adds no wait")
			require.NoError(t, removalWG.Wait())
			requireCoveragePending(t, bDone)
			s.reply(t, response, "")
			require.NoError(t, <-bDone)
		})
	}
}

func TestRepeatedRemovalWaitsForPendingOutcome(t *testing.T) {
	for _, mode := range []string{"single-nil", "single-typed-nil", "bulk-removal", "bulk-nil-upsert"} {
		for _, phase := range []struct {
			name             string
			publishUnrelated bool
			delayResponse    bool
			successiveNACKs  bool
		}{
			{name: "before-response"},
			{name: "after-response"},
			{name: "after-ack"},
			{name: "old-value-response"},
			{name: "old-absence-response"},
			{name: "delayed-old-value-response"},
			{name: "after-unrelated-publication", publishUnrelated: true},
			{name: "delayed-unrelated-publication", publishUnrelated: true, delayResponse: true},
			{name: "after-successive-nacks", successiveNACKs: true},
			{name: "after-successive-nacks-with-delayed-absence-ack", successiveNACKs: true},
		} {
			for _, reject := range []bool{false, true} {
				if phase.name == "after-ack" && reject {
					continue
				}
				for _, withRollback := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/reject=%t/rollback=%t", mode, phase.name, reject, withRollback), func(t *testing.T) {
						c := newCoverageCache(t)
						original := &listener.Listener{Name: "a"}
						other := &listener.Listener{Name: "b"}
						baselineOther := other
						for _, resource := range []*listener.Listener{original, other} {
							if phase.successiveNACKs && resource == original {
								continue
							}
							require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil))
						}
						s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
						s.reply(t, s.receive(t), "")

						ctx, cancel := context.WithTimeout(t.Context(), time.Second)
						t.Cleanup(cancel)
						remove := func(wg *completion.WaitGroup, withRollback bool) (Rollback, error) {
							switch mode {
							case "single-nil":
								if withRollback {
									return c.ApplyResourceWithRollback(ctx, "coverage-node", typeurl.Listener, "a", nil, wg)
								}
								return revert.Noop, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "a", nil, wg)
							case "single-typed-nil":
								if withRollback {
									return c.ApplyResourceWithRollback(ctx, "coverage-node", typeurl.Listener, "a", (*listener.Listener)(nil), wg)
								}
								return revert.Noop, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "a", (*listener.Listener)(nil), wg)
							default:
								var mutations ResourceMutations
								if mode == "bulk-removal" {
									mutations.Removed.Listeners = map[string]*listener.Listener{"a": nil}
								} else {
									mutations.Upserted.Listeners = map[string]*listener.Listener{"a": nil}
								}
								var waits typeurl.Set
								waits.Insert(typeurl.Listener)
								if withRollback {
									return c.ApplyResourcesWithRollback(ctx, "coverage-node", mutations, wg, waits)
								}
								return revert.Noop, c.ApplyResources(ctx, "coverage-node", mutations, wg, waits)
							}
						}
						first, second := completion.NewWaitGroup(ctx), completion.NewWaitGroup(ctx)
						t.Cleanup(first.Cancel)
						t.Cleanup(second.Cancel)
						var older *discovery.DiscoveryResponse
						var delayed cache.Response
						var oldValue *discovery.DiscoveryResponse
						otherStream := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
						if phase.successiveNACKs {
							if phase.name == "after-successive-nacks-with-delayed-absence-ack" {
								older = otherStream.receive(t)
							}
							// Supersede both rejected updates before their NACKs. Neither
							// rollback changes desired state, so no corrective revision can
							// hide a lost removal fence behind a newer absence requirement.
							require.NoError(t, c.applyRevertibleResource(ctx, "coverage-node", typeurl.Listener, "a", original, nil))
							rejected := s.receive(t)
							_, err := remove(nil, false)
							require.NoError(t, err)
							s.reply(t, rejected, "invalid a response")
							require.NoError(t, c.applyRevertibleResource(ctx, "coverage-node", typeurl.Listener, "b", &listener.Listener{Name: "b", StatPrefix: "rejected"}, nil))
							rejected = s.receive(t)
							other = &listener.Listener{Name: "b", StatPrefix: "updated"}
							require.NoError(t, c.applyRevertibleResource(ctx, "coverage-node", typeurl.Listener, "b", other, nil))
							// This NACK omits A. It must not discard A's earlier fence,
							// whether the old absence ACK arrived already or is delayed.
							s.reply(t, rejected, "invalid b response")
						}
						if phase.name == "old-absence-response" {
							_, err := remove(nil, false)
							require.NoError(t, err)
							older = otherStream.receive(t)
						}
						if phase.name == "old-value-response" || phase.name == "old-absence-response" || phase.name == "delayed-old-value-response" {
							require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a", StatPrefix: "updated"}, nil))
							switch phase.name {
							case "old-absence-response":
								oldValue = s.receive(t)
							case "delayed-old-value-response":
								// The cache has collected this response, but the
								// callback handler has not observed delivery yet.
								delayed = <-otherStream.watch(t)
							default:
								older = otherStream.receive(t)
							}
						}
						caller, err := remove(first, true)
						require.NoError(t, err)
						t.Cleanup(func() { caller.Finalize() })
						firstDone := waitForCoverageCompletion(first)
						requireCoveragePending(t, firstDone)
						require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"))
						var response *discovery.DiscoveryResponse
						var queued cache.Response
						if phase.delayResponse {
							queued = <-s.watch(t)
						} else if phase.name == "after-response" || phase.name == "after-ack" || phase.publishUnrelated {
							response = s.receive(t)
						}
						if phase.publishUnrelated {
							// Advance the publication boundary without changing LDS.
							// Its earlier absence response must still satisfy the wait.
							require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "unrelated", testSecret("unrelated", "value"), nil))
							secretStream := coverageStream{cache: c, id: s.id, typeURL: typeurl.Secret.URL()}
							secretStream.reply(t, secretStream.receive(t, "unrelated"), "", "unrelated")
						}
						if phase.name == "after-ack" {
							s.reply(t, response, "")
						}
						published := mustSnapshot(t, c, "coverage-node")
						// Reusing absence supersedes the earlier caller's restoration claim
						// without changing the ACK requirement or response-owned recovery.
						reused, err := remove(second, withRollback)
						require.NoError(t, err)
						require.NoError(t, reused.Revert())
						require.NoError(t, caller.Revert())
						caller = revert.Noop
						require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"), "neither caller may undo the reused absence")
						secondDone := waitForCoverageCompletion(second)
						if phase.name == "after-ack" {
							require.Zero(t, c.completionCbs.PendingCompletionCount())
						} else {
							require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
						}
						require.Same(t, published, mustSnapshot(t, c, "coverage-node"))
						if queued != nil {
							response = s.deliver(t, queued)
						}
						if delayed != nil {
							older = otherStream.deliver(t, delayed)
						}
						if older != nil {
							otherStream.reply(t, older, "")
							requireCoveragePending(t, firstDone)
							requireCoveragePending(t, secondDone)
						}
						if oldValue != nil {
							s.reply(t, oldValue, "")
							requireCoveragePending(t, firstDone)
							requireCoveragePending(t, secondDone)
						}
						if response == nil {
							response = s.receive(t)
						}
						require.Len(t, response.Resources, 1)
						rejection := ""
						if reject {
							rejection = "invalid listener response"
						}
						if phase.name != "after-ack" {
							s.reply(t, response, rejection)
						}
						if reject {
							requireCoveragePending(t, firstDone)
							requireCoveragePending(t, secondDone)
							require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"), "NACK must leave removals intact")
							// go-control-plane responds again to the last accepted
							// version after a NACK.
							retry := s.receive(t)
							if phase.successiveNACKs {
								// The final NACK also reverts B's pending upsert. The
								// removal waits survive that correction and its new version.
								require.NotEqual(t, response.VersionInfo, retry.VersionInfo)
								other = baselineOther
							} else {
								require.Equal(t, response.VersionInfo, retry.VersionInfo)
							}
							s.reply(t, response, "stale NACK")
							requireCoveragePending(t, firstDone)
							s.reply(t, retry, "")
						}
						for _, done := range []<-chan error{firstDone, secondDone} {
							require.NoError(t, <-done)
						}
						current := c.GetResource("coverage-node", typeurl.Listener, "a")
						require.Nil(t, current)
						current = c.GetResource("coverage-node", typeurl.Listener, "b")
						require.NotNil(t, current)
						require.Same(t, other, current)
						require.Zero(t, c.completionCbs.PendingCompletionCount())
						if phase.successiveNACKs || reject {
							afterACK := completion.NewWaitGroup(ctx)
							t.Cleanup(afterACK.Cancel)
							_, err := remove(afterACK, false)
							require.NoError(t, err)
							require.Zero(t, c.completionCbs.PendingCompletionCount(), "fresh ACK evidence satisfies subsequent removals")
							require.NoError(t, afterACK.Wait())
						}
					})
				}
			}
		}
	}
}

func TestBulkMixedChangesWaitForEachResourceOutcome(t *testing.T) {
	for _, outcome := range []string{"ack-unchanged-first", "ack-changed-first", "ack-unchanged-already-accepted", "nack-changed"} {
		t.Run(outcome, func(t *testing.T) {
			c := newCoverageCache(t)
			originalA := &endpoint.ClusterLoadAssignment{ClusterName: "a"}
			originalB := &endpoint.ClusterLoadAssignment{ClusterName: "b"}
			require.NoError(t, c.applyRevertibleResources(t.Context(), "coverage-node", ResourceMutations{
				Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{"a": originalA, "b": originalB}},
			}, nil, typeurl.Set{}))
			first := coverageStream{cache: c, id: 1}
			baseline := first.receive(t, "a", "b")
			first.reply(t, baseline, "", "a", "b")
			changedA := proto.Clone(originalA).(*endpoint.ClusterLoadAssignment)
			changedA.Policy = &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(140)}
			require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", changedA, nil))
			olderResponse := first.receive(t, "a")
			if outcome == "ack-unchanged-already-accepted" {
				first.reply(t, olderResponse, "", "a")
			}

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			var waits typeurl.Set
			waits.Insert(typeurl.Endpoint)
			changedB := proto.Clone(originalB).(*endpoint.ClusterLoadAssignment)
			changedB.Policy = &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(150)}
			// A is semantically unchanged; B really changes. If A is still
			// unACKed, this wait must preserve their different value revisions.
			require.NoError(t, c.applyRevertibleResources(ctx, "coverage-node", ResourceMutations{
				Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
					"a": proto.Clone(changedA).(*endpoint.ClusterLoadAssignment), "b": changedB,
				}},
			}, wg, waits))
			current := c.GetResource("coverage-node", typeurl.Endpoint, "a")
			require.NotNil(t, current)
			require.Same(t, changedA, current, "no-op must preserve the canonical resource")
			second := coverageStream{cache: c, id: 2, version: baseline.VersionInfo}
			newerResponse := second.receive(t, "b")
			require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
			switch outcome {
			case "ack-unchanged-first":
				first.reply(t, olderResponse, "", "a")
				require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				second.reply(t, newerResponse, "", "b")
			case "ack-changed-first":
				second.reply(t, newerResponse, "", "b")
				require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				// ACKing A's earlier response must suffice even though the bulk
				// transaction itself was registered at B's newer generation.
				first.reply(t, olderResponse, "", "a")
			case "ack-unchanged-already-accepted":
				second.reply(t, newerResponse, "", "b")
			case "nack-changed":
				second.reply(t, newerResponse, "invalid b", "b")
			}
			if outcome == "nack-changed" {
				require.ErrorContains(t, wg.Wait(), "invalid b")
				first.reply(t, olderResponse, "", "a")
			} else {
				require.NoError(t, wg.Wait())
			}
			current = c.GetResource("coverage-node", typeurl.Endpoint, "a")
			require.NotNil(t, current)
			require.Same(t, changedA, current, "A belongs to an earlier independent mutation")
			current = c.GetResource("coverage-node", typeurl.Endpoint, "b")
			require.NotNil(t, current)
			if outcome == "nack-changed" {
				require.Same(t, originalB, current)
			} else {
				require.Same(t, changedB, current)
			}
			require.Zero(t, c.completionCbs.PendingCompletionCount())
		})
	}
}

func TestPartialResponseVersionOnlyReconnectDoesNotAcceptUnsentName(t *testing.T) {
	c := newCoverageCache(t)
	_, aDone := upsertCoverageEndpoint(t, c, "a")
	b, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	c.completionCbs.OnStreamClosed(1, nil)
	require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Endpoint.URL(),
		VersionInfo: response.VersionInfo, ResourceNames: []string{"b"},
	}))
	requireCoveragePending(t, bDone)
	require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "b", b, true, callbacks.Revision{}))
	// Nor may that unverified version short-circuit a newly registered no-op
	// wait through the type-level accepted-version fallback.
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "b", b, wg))
	noOp := waitForCoverageCompletion(wg)
	requireCoveragePending(t, noOp)
	second := coverageStream{cache: c, id: 2, version: response.VersionInfo}
	response = second.receive(t, "b")
	second.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-bDone, "invalid b")
	require.ErrorContains(t, <-noOp, "invalid b")
}

func TestPartialLDSReconnectWithWildcardDoesNotAcceptUnsentName(t *testing.T) {
	c := newCoverageCache(t)
	aWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(aWG.Cancel)
	bWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(bWG.Cancel)
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, aWG))
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Listener, "b", &listener.Listener{Name: "b"}, bWG))
	aDone, bDone := waitForCoverageCompletion(aWG), waitForCoverageCompletion(bWG)
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t, "a")
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	c.completionCbs.OnStreamClosed(1, nil)
	// Even wildcard LDS cannot infer full acceptance from an echoed version:
	// that version may have been learned from an earlier named subscription.
	require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(), VersionInfo: response.VersionInfo,
	}))
	requireCoveragePending(t, bDone)
	second := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL(), version: response.VersionInfo}
	response = second.receive(t)
	second.reply(t, response, "invalid b")
	require.ErrorContains(t, <-bDone, "invalid b")
	require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "b"), "B's unsent inverse must survive reconnection until an actual ACK/NACK")
}

func TestDelayedPartialACKDoesNotAcceptNewerSameName(t *testing.T) {
	c := newCoverageCache(t)
	a, oldDone := upsertCoverageEndpoint(t, c, "a")
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	updated := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", updated, wg))
	done := waitForCoverageCompletion(wg)
	s.reply(t, response, "", "a")
	require.NoError(t, <-oldDone)
	requireCoveragePending(t, done)
	requireCoveragePending(t, bDone)
	require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}))
	require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", updated, true, callbacks.Revision{}))
	response = s.receive(t, "a", "b")
	s.reply(t, response, "", "a", "b")
	require.NoError(t, <-done)
	require.NoError(t, <-bDone)
}

func TestCallerRevertKeepsUnrelatedResourceAccepted(t *testing.T) {
	c := newCoverageCache(t)
	unchanged := &listener.Listener{Name: "unchanged"}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, unchanged.Name, unchanged, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t, unchanged.Name)
	s.reply(t, response, "", unchanged.Name)
	rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, "reverted", &listener.Listener{Name: "reverted"}, nil)
	require.NoError(t, err)
	require.NoError(t, rollback.Revert())

	// The type's corrective wire version does not invalidate ACK evidence for
	// a resource whose desired entry was not restored by this rollback.
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, unchanged.Name, proto.Clone(unchanged), wg))
	require.NoError(t, wg.Wait())
}

func TestPartialNACKKeepsUnrequestedCoalescedNames(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	waits := typeurl.NewSet()
	waits.Insert(typeurl.Endpoint)
	require.NoError(t, c.applyRevertibleResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
			"a": {ClusterName: "a"}, "b": {ClusterName: "b"},
		}},
	}, wg, waits))
	_, unrelatedDone := upsertCoverageEndpoint(t, c, "unrelated")
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Endpoint, "a",
		&endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}, wg))
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount(), "only the unrelated resource's wait remains")
	require.ErrorContains(t, wg.Wait(), "invalid a")
	require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
	require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
	requireCoveragePending(t, unrelatedDone)
	require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "unrelated"))
}

func TestPartialNACKKeepsOtherTypeURLInTransaction(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	waits := typeurl.NewSet()
	waits.Insert(typeurl.Endpoint)
	waits.Insert(typeurl.Cluster)
	require.NoError(t, c.applyRevertibleResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{
			Endpoints: map[string]*endpoint.ClusterLoadAssignment{"a": {ClusterName: "a"}},
			Clusters:  map[string]*cluster.Cluster{"cluster-a": {Name: "cluster-a"}},
		},
	}, wg, waits))
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
	require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
	require.NotNil(t, c.GetResource("coverage-node", typeurl.Cluster, "cluster-a"))
	cds := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
	cds.reply(t, cds.receive(t), "")
	require.Zero(t, c.completionCbs.PendingCompletionCount(), "CDS must still be independently ACKable")
	require.ErrorContains(t, wg.Wait(), "invalid a")
}

func TestPartialNACKPreservesNewerUnrequestedTransactionSibling(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	waits := typeurl.NewSet()
	waits.Insert(typeurl.Endpoint)
	require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
			"a": {ClusterName: "a"}, "b": {ClusterName: "b"},
		}},
	}, wg, waits))
	newer := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
	aWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(aWG.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", newer, aWG))
	aDone := waitForCoverageCompletion(aWG)
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "b")
	s.reply(t, response, "invalid b", "b")
	requireCoveragePending(t, aDone)
	actual := c.GetResource("coverage-node", typeurl.Endpoint, "a")
	require.NotNil(t, actual)
	require.Same(t, newer, actual)
	response = s.receive(t, "a")
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	require.ErrorContains(t, wg.Wait(), "invalid b")
}

func TestNamedFullPositiveResponseDoesNotAcceptUnrequestedRemoval(t *testing.T) {
	c := newCoverageCache(t)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t, "a")
	s.reply(t, response, "", "a")
	// All positive resources were delivered, but the named request proves
	// nothing about an absent name outside that subscription.
	require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Listener, "b", nil, false, callbacks.Revision{}))
	require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, true, callbacks.Revision{}))
}

func TestPartialResponseKeepsUnrequestedTransactionPending(t *testing.T) {
	for _, test := range []struct {
		name               string
		firstAlreadyACKed  bool
		firstRejection     string
		replyNames         []string
		mutateSubscription bool
		secondRejection    string
	}{
		{name: "ack-expands-subscription", replyNames: []string{"a", "b"}, secondRejection: "invalid b"},
		{name: "nack-preserves-independent-transaction", firstRejection: "invalid a", replyNames: []string{"a"}},
		{name: "subscription-mutated-before-ack", replyNames: []string{"b"}, mutateSubscription: true},
		{name: "ack-unrelated-response-keeps-coalescing", firstAlreadyACKed: true, replyNames: []string{"a"}, secondRejection: "invalid b"},
		{name: "nack-unrelated-response-keeps-coalescing", firstAlreadyACKed: true, firstRejection: "invalid a", replyNames: []string{"a"}, secondRejection: "invalid b"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newCoverageCache(t)
			a, aDone := upsertCoverageEndpoint(t, c, "a")
			s := coverageStream{cache: c, id: 1}
			if test.firstAlreadyACKed {
				s.reply(t, s.receive(t, "a"), "", "a")
			}
			b, bDone := upsertCoverageEndpoint(t, c, "b")
			response := s.receive(t, "a")
			if test.mutateSubscription {
				// Evidence for a constructed response must survive changes to the
				// subscription's returned-resource map before ACK processing.
				s.sub.SetResourceSubscription([]string{"b"})
			}
			s.reply(t, response, test.firstRejection, test.replyNames...)
			if test.firstRejection == "" || test.firstAlreadyACKed {
				require.NoError(t, <-aDone)
				require.Same(t, a, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
				require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}))
			} else {
				require.ErrorContains(t, <-aDone, test.firstRejection)
				require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			}
			requireCoveragePending(t, bDone)
			require.Same(t, b, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
			require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "b", b, true, callbacks.Revision{}))

			if test.firstAlreadyACKed {
				// Neither ACK nor NACK of unchanged A can claim B's rollback.
				// A later revertible B update must still coalesce back to its
				// original absence.
				b = &endpoint.ClusterLoadAssignment{ClusterName: "b", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
				require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Endpoint, "b", b, nil))
			}
			response = s.receive(t, "b")
			s.reply(t, response, test.secondRejection, "b")
			if test.secondRejection == "" {
				require.NoError(t, <-bDone)
			} else {
				require.ErrorContains(t, <-bDone, test.secondRejection)
				require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
				require.Same(t, a, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			}
		})
	}
}
func TestNoOpAfterCallerRevertWaitsForCorrectiveACK(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		for _, delivery := range []struct {
			name   string
			absent bool
		}{
			{name: "one-stream"},
			{name: "two-streams"},
			{name: "delayed-response"},
			{name: "previously-accepted"},
			{name: "restored-absence", absent: true},
		} {
			t.Run(api+"/"+delivery.name, func(t *testing.T) {
				c := newCoverageCache(t)
				const name = "resource"
				var a *listener.Listener
				var names []string
				if !delivery.absent {
					names = []string{name}
					a = &listener.Listener{Name: name, PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, name, a, nil))
				}
				b := &listener.Listener{Name: name, PerConnectionBufferLimitBytes: wrapperspb.UInt32(2)}
				first := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
				second := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
				var original *discovery.DiscoveryResponse
				if delivery.name != "one-stream" && !delivery.absent {
					original = first.receive(t, names...)
				}
				rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, name, b, nil)
				require.NoError(t, err)
				rejected := &first
				if original != nil {
					rejected = &second
				}
				var outdated *discovery.DiscoveryResponse
				var held cache.Response
				if delivery.name == "delayed-response" {
					request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(), ResourceNames: []string{name}}
					require.NoError(t, c.completionCbs.OnStreamRequest(rejected.id, request))
					rejected.sub = stream.NewSotwSubscription(request.ResourceNames, true)
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(request, rejected.sub, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					select {
					case held = <-responses:
					default:
						t.Fatal("expected immediate B response")
					}
				} else {
					outdated = rejected.receive(t, names...)
				}
				if delivery.name == "previously-accepted" {
					first.reply(t, original, "", names...)
				}
				require.NoError(t, rollback.Revert())
				if delivery.absent {
					require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, name))
				} else {
					require.Same(t, a, c.GetResource("coverage-node", typeurl.Listener, name))
				}

				wg := completion.NewWaitGroup(t.Context())
				t.Cleanup(wg.Cancel)
				var candidate proto.Message
				if a != nil {
					candidate = proto.Clone(a)
				}
				if api == "single" {
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, name, candidate, wg))
				} else {
					var waits typeurl.Set
					waits.Insert(typeurl.Listener)
					var mutations ResourceMutations
					if delivery.absent {
						mutations.Removed.Listeners = map[string]*listener.Listener{name: nil}
					} else {
						mutations.Upserted.Listeners = map[string]*listener.Listener{name: candidate.(*listener.Listener)}
					}
					require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
				}
				require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				if held != nil {
					outdated = rejected.deliver(t, held)
				}
				rejected.reply(t, outdated, "", names...)
				require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				if original != nil && delivery.name != "previously-accepted" {
					first.reply(t, original, "", names...)
					require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
				}
				// Even the stream which accepted the original A must receive a new
				// corrective publication, rather than reuse that historical ACK.
				corrected := first.receive(t, names...)
				if delivery.absent {
					require.Empty(t, corrected.Resources)
				}
				if original != nil {
					require.NotEqual(t, original.VersionInfo, corrected.VersionInfo)
				}
				first.reply(t, corrected, "", names...)
				require.NoError(t, wg.Wait())
			})
		}
	}
}
func TestMixedRemovalAndUpsertNACK(t *testing.T) {
	for _, mode := range []string{"permanent", "response-only", "caller-finalize", "caller-revert", "separate-upsert", "other-type-upsert", "other-type-upsert-caller-revert"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			otherTypeUpsert := mode == "other-type-upsert" || mode == "other-type-upsert-caller-revert"
			original := &listener.Listener{Name: "a"}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", original, nil))
			if otherTypeUpsert {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "c", &listener.Listener{Name: "c"}, nil))
			}
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			s.reply(t, s.receive(t), "")
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			waits := typeurl.NewSet(typeurl.Listener)
			mutations := ResourceMutations{
				Removed: xds.Resources{Listeners: map[string]*listener.Listener{"a": nil}},
			}
			if otherTypeUpsert {
				mutations.Removed.Listeners["c"] = nil
				mutations.Upserted.Clusters = map[string]*cluster.Cluster{"b": {Name: "b"}}
				waits.Insert(typeurl.Cluster)
			} else if mode != "separate-upsert" {
				mutations.Upserted.Listeners = map[string]*listener.Listener{"b": {Name: "b"}}
			}
			var caller Rollback = revert.Noop
			if mode == "caller-finalize" || mode == "caller-revert" || mode == "other-type-upsert-caller-revert" {
				var err error
				caller, err = c.ApplyResourcesWithRollback(t.Context(), "coverage-node", mutations, wg, waits)
				require.NoError(t, err)
				t.Cleanup(func() { caller.Finalize() })
			} else if mode == "response-only" {
				require.NoError(t, c.applyRevertibleResources(t.Context(), "coverage-node", mutations, wg, waits))
			} else {
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
			}
			if mode == "separate-upsert" {
				require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Listener, "b", &listener.Listener{Name: "b"}, nil))
			}
			done := waitForCoverageCompletion(wg)
			if otherTypeUpsert {
				// The same transaction has a CDS upsert and an LDS removal. ACK
				// CDS first: an LDS NACK must leave only its removal wait pending.
				cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
				cds.reply(t, cds.receive(t), "")
				requireCoveragePending(t, done)
			}
			const rejection = "listener response rejected"
			s.reply(t, s.receive(t), rejection)
			require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"), "NACK leaves desired removals intact")
			if otherTypeUpsert {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "c"), "NACK preserves every removal of this type")
				require.Same(t, mutations.Upserted.Clusters["b"], c.GetResource("coverage-node", typeurl.Cluster, "b"),
					"a removal-only LDS NACK must leave the transaction's CDS upsert intact")
			} else if mode == "permanent" {
				require.Same(t, mutations.Upserted.Listeners["b"], c.GetResource("coverage-node", typeurl.Listener, "b"), "NACK leaves a plain upsert intact")
			} else {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "b"), "NACK still reverts the upsert")
			}
			if mode == "separate-upsert" || otherTypeUpsert {
				// The removal-only LDS wait survives this NACK and completes
				// only when the retry is ACKed.
				requireCoveragePending(t, done)
				retry := s.receive(t)
				require.Empty(t, retry.Resources)
				s.reply(t, retry, "")
				require.NoError(t, <-done)
			} else {
				require.ErrorContains(t, <-done, rejection)
			}
			if mode == "caller-revert" || mode == "other-type-upsert-caller-revert" {
				require.NoError(t, caller.Revert())
			} else {
				caller.Finalize()
			}
			if mode == "caller-revert" || mode == "other-type-upsert-caller-revert" {
				require.Same(t, original, c.GetResource("coverage-node", typeurl.Listener, "a"))
			} else {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"))
			}
			caller = revert.Noop
			if mode == "other-type-upsert-caller-revert" {
				require.NotNil(t, c.GetResource("coverage-node", typeurl.Listener, "c"))
				require.Nil(t, c.GetResource("coverage-node", typeurl.Cluster, "b"), "caller rollback still undoes the upsert")
			}
		})
	}
}

func TestSotWRemovalOutcomes(t *testing.T) {
	for _, resource := range []struct {
		name       string
		index      typeurl.Index
		resource   proto.Message
		referenced bool
	}{
		{"listener", typeurl.Listener, &listener.Listener{Name: "a"}, false},
		{"cluster", typeurl.Cluster, &cluster.Cluster{Name: "a"}, false},
		{"endpoint", typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "a"}, false},
		{"route", typeurl.Route, &route.RouteConfiguration{Name: "a"}, false},
		{"secret", typeurl.Secret, &secret.Secret{Name: "a"}, false},
		{"policy", typeurl.NetworkPolicy, &cilium.NetworkPolicy{EndpointId: 1}, false},
		{"policy-hosts", typeurl.NetworkPolicyHosts, &cilium.NetworkPolicyHosts{Policy: 1}, false},
		{"referenced-endpoint", typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(123)}}, true},
	} {
		omissionDeletes := resource.index == typeurl.Listener || resource.index == typeurl.Cluster ||
			resource.index == typeurl.NetworkPolicy || resource.index == typeurl.NetworkPolicyHosts
		observable := omissionDeletes || resource.referenced
		for _, outcome := range []struct {
			name     string
			oldValue bool
			delayed  bool
			api      string
		}{
			{name: "named-ack"},
			{name: "nack-then-ack"},
			{name: "nack-disconnect-ack"},
			{name: "nack-cancel"},
			{name: "nack-deadline"},
			{name: "old-value-response", oldValue: true},
			{name: "delayed-old-value-response", oldValue: true, delayed: true},
			{name: "old-value-response/single-typed-nil", oldValue: true, api: "single-typed-nil"},
			{name: "old-value-response/bulk-removal", oldValue: true, api: "bulk-removal"},
			{name: "old-value-response/bulk-nil-upsert", oldValue: true, api: "bulk-nil-upsert"},
		} {
			if outcome.oldValue && observable || outcome.name == "nack-deadline" && resource.index != typeurl.Listener {
				continue
			}
			t.Run(resource.name+"/"+outcome.name, func(t *testing.T) {
				c := newCoverageCache(t)
				if resource.referenced {
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Cluster, "parent", testEDSCluster("parent", "a"), nil))
					parent := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
					parent.reply(t, parent.receive(t), "")
				}
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", resource.index, "a", resource.resource, nil))
				s := coverageStream{cache: c, id: 1, typeURL: resource.index.URL()}
				// The ACK cases use named requests. NACK cases also exercise
				// wildcard EDS/RDS; SDS requires an explicit name.
				var names []string
				if outcome.name == "named-ack" || outcome.oldValue || resource.index == typeurl.Secret {
					names = []string{"a"}
				}
				response := s.receive(t, names...)
				s.reply(t, response, "", names...)
				var oldValue *discovery.DiscoveryResponse
				var delayed cache.Response
				var typedNil proto.Message
				var removed xds.Resources
				other := coverageStream{cache: c, id: 2, typeURL: resource.index.URL()}
				if outcome.oldValue {
					updated := proto.Clone(resource.resource)
					switch value := updated.(type) {
					case *endpoint.ClusterLoadAssignment:
						value.Policy = &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(140)}
						value.Endpoints = []*endpoint.LocalityLbEndpoints{{LbEndpoints: []*endpoint.LbEndpoint{{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{Endpoint: &endpoint.Endpoint{Address: &core.Address{
								Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
									Address: "127.0.0.1", PortSpecifier: &core.SocketAddress_PortValue{PortValue: 8080},
								}},
							}}},
						}}}}
						typedNil = (*endpoint.ClusterLoadAssignment)(nil)
						removed.Endpoints = map[string]*endpoint.ClusterLoadAssignment{"a": nil}
					case *route.RouteConfiguration:
						value.ValidateClusters = wrapperspb.Bool(true)
						typedNil = (*route.RouteConfiguration)(nil)
						removed.Routes = map[string]*route.RouteConfiguration{"a": nil}
					case *secret.Secret:
						value.Type = testSecret("a", "updated").Type
						typedNil = (*secret.Secret)(nil)
						removed.Secrets = map[string]*secret.Secret{"a": nil}
					}
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", resource.index, "a", updated, nil))
					if outcome.delayed {
						delayed = <-other.watch(t, names...)
					} else {
						oldValue = other.receive(t, names...)
					}
				}
				waitCtx := t.Context()
				if outcome.name == "nack-deadline" {
					var cancel context.CancelFunc
					waitCtx, cancel = context.WithTimeout(waitCtx, 10*time.Millisecond)
					t.Cleanup(cancel)
				}
				wg := completion.NewWaitGroup(waitCtx)
				t.Cleanup(wg.Cancel)
				remove := func() {
					switch outcome.api {
					case "bulk-removal", "bulk-nil-upsert":
						mutations := ResourceMutations{Removed: removed}
						if outcome.api == "bulk-nil-upsert" {
							mutations = ResourceMutations{Upserted: removed}
						}
						waits := typeurl.NewSet(resource.index)
						require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
					case "single-typed-nil":
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", resource.index, "a", typedNil, wg))
					default:
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", resource.index, "a", nil, wg))
					}
				}
				remove()
				if outcome.oldValue {
					// Removals retain no desired entries. A repeated removal must
					// still reject an ACK for the older response containing the live resource.
					require.Empty(t, c.getNodeState("coverage-node").resources[resource.index])
					remove()
					require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
					if delayed != nil {
						oldValue = other.deliver(t, delayed)
					}
					other.reply(t, oldValue, "", names...)
					require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
				}
				response = s.receive(t, names...)
				if resource.referenced {
					require.Len(t, response.Resources, 1)
					var empty endpoint.ClusterLoadAssignment
					require.NoError(t, response.Resources[0].UnmarshalTo(&empty))
					require.Equal(t, "a", empty.ClusterName)
					require.Empty(t, empty.Endpoints)
				} else {
					require.Empty(t, response.Resources)
				}
				if outcome.name != "named-ack" && !outcome.oldValue {
					s.reply(t, response, "response rejected", names...)
					require.Equal(t, 1, c.completionCbs.PendingCompletionCount())
					require.Nil(t, c.GetResource("coverage-node", resource.index, "a"), "NACK must not restore desired removals")
					// A no-op removal after NACK joins the retry, rather than
					// completing immediately with the rejected-version error.
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", resource.index, "a", nil, wg))
					require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
					if outcome.name == "nack-cancel" || outcome.name == "nack-deadline" {
						cause := context.DeadlineExceeded
						if outcome.name == "nack-cancel" {
							wg.Cancel()
							cause = context.Canceled
						}
						require.ErrorIs(t, wg.Wait(), cause)
						require.Zero(t, c.completionCbs.PendingCompletionCount())
						return
					}
					if outcome.name == "nack-disconnect-ack" {
						c.completionCbs.OnStreamClosed(s.id, &core.Node{Id: "coverage-node"})
						s = coverageStream{cache: c, id: 2, typeURL: resource.index.URL()}
					}
					rejected := response
					response = s.receive(t, names...)
					if outcome.name == "nack-then-ack" {
						s.reply(t, rejected, "", names...)
						require.Equal(t, 2, c.completionCbs.PendingCompletionCount())
					}
				}
				s.reply(t, response, "", names...)
				if observable {
					require.NoError(t, wg.Wait())
				} else {
					// EDS/RDS/SDS omission establishes neither acceptance nor
					// rejection of the caller's removal.
					require.Positive(t, c.completionCbs.PendingCompletionCount())
				}
				require.Equal(t, omissionDeletes,
					c.completionCbs.ResourceAccepted("coverage-node", resource.index, "a", nil, false, callbacks.Revision{}))
				c.getNodeState("coverage-node").requireNoUnsentRollbacks(t)
			})
		}
	}
}
