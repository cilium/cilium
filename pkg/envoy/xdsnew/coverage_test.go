// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
)

// coverageStream uses the production cache and go-control-plane response
// filtering, rather than manufacturing a callback with an empty resource list.
// The request names and the names actually delivered can therefore differ.
type coverageStream struct {
	cache   *cacheImpl
	id      int64
	nonce   uint64
	sub     stream.Subscription
	version string
	typeURL string
}

func (s *coverageStream) resourceType() string {
	if s.typeURL == "" {
		return typeurl.Endpoint.URL()
	}
	return s.typeURL
}

func (s *coverageStream) receive(t *testing.T, names ...string) *discovery.DiscoveryResponse {
	t.Helper()
	request := &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.resourceType(), ResourceNames: names, VersionInfo: s.version,
	}
	require.NoError(t, s.cache.completionCbs.OnStreamRequest(s.id, request))
	if s.nonce == 0 {
		s.sub = stream.NewSotwSubscription(names, s.resourceType() != typeurl.Secret.URL())
	} else {
		s.sub.SetResourceSubscription(names)
	}
	responses := make(chan cache.Response, 1)
	cancel, err := s.cache.CreateWatch(request, s.sub, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	var response cache.Response
	select {
	case response = <-responses:
	default:
		t.Fatal("expected immediate response")
	}
	return s.deliver(t, response)
}

func (s *coverageStream) deliver(t *testing.T, response cache.Response) *discovery.DiscoveryResponse {
	t.Helper()
	out, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	s.nonce++
	out.Nonce = fmt.Sprint(s.nonce)
	s.sub.SetReturnedResources(response.GetReturnedResources())
	s.cache.completionCbs.OnStreamResponse(response.GetContext(), s.id, response.GetRequest(), out)
	return out
}

func (s *coverageStream) reply(t *testing.T, response *discovery.DiscoveryResponse, rejection string, names ...string) {
	t.Helper()
	request := &discovery.DiscoveryRequest{
		TypeUrl: s.resourceType(), VersionInfo: response.GetVersionInfo(),
		ResponseNonce: response.GetNonce(), ResourceNames: names,
	}
	if rejection != "" {
		request.VersionInfo = ""
		request.ErrorDetail = &status.Status{Message: rejection}
	}
	require.NoError(t, s.cache.completionCbs.OnStreamRequest(s.id, request))
	if rejection == "" {
		s.version = response.GetVersionInfo()
	}
	s.sub.SetResourceSubscription(names)
}

func newCoverageCache(t *testing.T) *cacheImpl {
	t.Helper()
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("coverage-node")).(*cacheImpl)
	t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil); c.completionCbs.OnStreamClosed(2, nil) })
	return c
}

func upsertCoverageEndpoint(t *testing.T, c *cacheImpl, name string) (*endpoint.ClusterLoadAssignment, <-chan error) {
	t.Helper()
	resource := &endpoint.ClusterLoadAssignment{ClusterName: name}
	done := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, name, resource, wg,
		func(err error) { done <- err }))
	return resource, done
}

func requireCoveragePending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("uncovered resource completed: %v", err)
	default:
	}
}

func TestNoOpUpdateWaitsForResourceOutcome(t *testing.T) {
	for _, api := range []struct {
		name  string
		index typeurl.Index
		value proto.Message
	}{
		{"listener-single", typeurl.Listener, &listener.Listener{Name: "resource"}},
		{"listener-bulk", typeurl.Listener, &listener.Listener{Name: "resource"}},
		{"listener-whole-type", typeurl.Listener, &listener.Listener{Name: "resource"}},
		{"policy-single", typeurl.NetworkPolicy, &cilium.NetworkPolicy{EndpointId: 1}},
	} {
		for _, outcome := range []struct {
			name      string
			phase     string
			rejection string
		}{
			{"before-response/ack", "before-response", ""},
			{"before-response/nack", "before-response", "invalid resource"},
			{"after-response/ack", "after-response", ""},
			{"after-response/nack", "after-response", "invalid resource"},
			{"after-ack", "after-ack", ""},
		} {
			t.Run(api.name+"/"+outcome.name, func(t *testing.T) {
				c := newCoverageCache(t)
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", api.index, "resource", api.value, nil, nil))
				s := coverageStream{cache: c, id: 1, typeURL: api.index.URL()}
				var response *discovery.DiscoveryResponse
				if outcome.phase != "before-response" {
					response = s.receive(t)
				}
				if outcome.phase == "after-ack" {
					s.reply(t, response, "")
				}

				published, _ := c.GetSnapshot("coverage-node")
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				done := make(chan error, 1)
				callback := func(err error) { done <- err }
				candidate := proto.Clone(api.value)
				if api.name != "policy-single" && api.name != "listener-single" {
					var waits TypeURLCallbacks
					waits.Set(api.index, callback)
					var mutations ResourceMutations
					if api.name == "listener-bulk" {
						mutations.Upserted.Listeners = map[string]*listener.Listener{"resource": candidate.(*listener.Listener)}
					}
					require.NoError(t, c.ApplyResources(ctx, "coverage-node", mutations, wg, waits))
				} else {
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", api.index, "resource", candidate, wg, callback))
				}
				currentSnapshot, _ := c.GetSnapshot("coverage-node")
				if published == nil {
					require.Nil(t, currentSnapshot, "a pending no-op must not publish")
				} else {
					require.Same(t, published, currentSnapshot, "a semantic no-op must not publish")
				}
				current := c.GetResource("coverage-node", api.index, "resource")
				require.NotNil(t, current)
				require.Same(t, api.value, current, "a no-op must keep the canonical protobuf")
				if outcome.phase != "after-ack" {
					requireCoveragePending(t, done)
					if response == nil {
						response = s.receive(t)
					}
					s.reply(t, response, outcome.rejection)
				}
				if outcome.rejection == "" {
					require.NoError(t, wg.Wait())
					require.NoError(t, <-done)
				} else {
					require.ErrorContains(t, wg.Wait(), outcome.rejection)
					require.ErrorContains(t, <-done, outcome.rejection)
				}
				require.Empty(t, done, "the callback must run exactly once")
				require.Zero(t, c.completionCbs.PendingCompletionCount())
			})
		}
	}
}

func TestNoOpUpdateAfterFailedNACKCompletesWithRejection(t *testing.T) {
	c := newCoverageCache(t)
	first := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", first, nil, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.NetworkPolicy.URL()}
	s.reply(t, s.receive(t), "")
	rejected := &cilium.NetworkPolicy{EndpointId: 2}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", rejected, nil, nil))
	response := s.receive(t)
	published := mustSnapshot(t, c, "coverage-node")

	// A failed corrective publication leaves the rejected entry in desired
	// state. A no-op submitted before stream closure must fail immediately,
	// rather than await an ACK for a version Envoy already rejected.
	publicationErr := errors.New("corrective publication failed")
	backend := c.SnapshotCache
	c.SnapshotCache = &mockSnapshotCache{
		snapshots: map[string]cache.ResourceSnapshot{"coverage-node": published}, setSnapshotErr: publicationErr,
	}
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
	c.SnapshotCache = backend
	current := c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy")
	require.NotNil(t, current)
	require.Same(t, rejected, current)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
		proto.Clone(rejected), wg, func(err error) { done <- err }))
	require.ErrorContains(t, wg.Wait(), "invalid policy")
	require.ErrorContains(t, <-done, "invalid policy")
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
					done := make(chan error, 1)
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
						&cilium.NetworkPolicy{EndpointId: 1}, wg, func(err error) { done <- err }))
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
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy", latest, nil, nil))
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
						require.NoError(t, wg.Wait())
						require.NoError(t, <-done)
					} else {
						require.ErrorContains(t, wg.Wait(), rejection)
						require.ErrorContains(t, <-done, rejection)
						require.Nil(t, c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy"), "NACK must roll back the covered, unaccepted updates")
					}
					require.Zero(t, c.completionCbs.PendingCompletionCount())
				})
			}
		})
	}
}

func TestBulkUpdateWithoutWaitGroupRetainsNACKRollback(t *testing.T) {
	for _, mode := range []string{"inferred-waits", "explicit-waits", "no-waits", "caller-finalized"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			mutations := ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*listener.Listener{"l1": {Name: "l1"}},
				Routes:    map[string]*route.RouteConfiguration{"r1": {Name: "r1"}},
			}}
			var waits TypeURLCallbacks
			switch mode {
			case "explicit-waits":
				waits.Set(typeurl.Listener, func(err error) { t.Errorf("unexpected callback without a WaitGroup: %v", err) })
				waits.Set(typeurl.Route, func(err error) { t.Errorf("unexpected callback without a WaitGroup: %v", err) })
			case "no-waits":
				waits = NewTypeURLCallbacks()
			}
			if mode == "caller-finalized" {
				rollback, err := c.ApplyResourcesWithRollback(t.Context(), "coverage-node", mutations, nil, waits)
				require.NoError(t, err)
				require.NotNil(t, rollback)
				rollback.Finalize()
			} else {
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, nil, waits))
			}
			// A nil-WG no-op also needs no caller bookkeeping, but must not
			// discard the original transaction's response-owned rollback.
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, nil, waits))
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			response := s.receive(t, "l1")
			s.reply(t, response, "invalid listener", "l1")
			for _, resource := range []struct {
				index typeurl.Index
				name  string
			}{{typeurl.Listener, "l1"}, {typeurl.Route, "r1"}} {
				require.Nil(t, c.GetResource("coverage-node", resource.index, resource.name), "the entire untracked transaction must be reverted")
			}
		})
	}
}

func TestBulkNoOpWaitUsesMatchingResourceRevision(t *testing.T) {
	for _, mode := range []string{"upsert", "remove-and-upsert", "absent-resource", "whole-type"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			first := &listener.Listener{Name: "l1"}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "l1", first, nil, nil))
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			// The first response covers l1 and the absence of "missing".
			// A later mutation must not change that response's generation.
			response := s.receive(t, "l1", "missing")
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "l2",
				&listener.Listener{Name: "l2"}, nil, nil))
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
			done := make(chan error, 1)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			waits := NewTypeURLCallbacks()
			waits.Set(typeurl.Listener, func(err error) { done <- err })
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
			requireCoveragePending(t, done)
			s.reply(t, response, "", "l1", "missing")
			if mode == "whole-type" {
				// With no supplied names the wait deliberately covers the latest
				// published type, unlike a named absent resource at revision zero.
				requireCoveragePending(t, done)
				wildcard := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
				response = wildcard.receive(t)
				wildcard.reply(t, response, "")
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			default:
				t.Fatal("ACK did not complete the matching bulk wait")
			}
		})
	}
}

func TestPartialResponseACKDoesNotAcceptUnsentResources(t *testing.T) {
	c := newCoverageCache(t)
	a, aDone := upsertCoverageEndpoint(t, c, "a")
	b, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	require.Len(t, response.Resources, 1)
	// An ACK may simultaneously expand the subscription. It still acknowledges
	// only the original response, not every name in this new request.
	s.reply(t, response, "", "a", "b")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)
	require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}))
	require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "b", b, true, callbacks.Revision{}))
	// B's response-owned rollback must survive A's ACK without depending on a
	// caller WaitGroup. A subsequent response for B can still reject it.
	response = s.receive(t, "b")
	s.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-bDone, "invalid b")
	require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
	require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
}

func TestPartialResponseNACKKeepsUnrelatedTransaction(t *testing.T) {
	c := newCoverageCache(t)
	_, aDone := upsertCoverageEndpoint(t, c, "a")
	b, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	require.ErrorContains(t, <-aDone, "invalid a")
	requireCoveragePending(t, bDone)
	require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
	actual := c.GetResource("coverage-node", typeurl.Endpoint, "b")
	require.NotNil(t, actual)
	require.Same(t, b, actual)
	response = s.receive(t, "b")
	s.reply(t, response, "", "b")
	require.NoError(t, <-bDone)
}

func TestPartialResponsesAtSameGenerationAccumulate(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-second=%t", reject), func(t *testing.T) {
			c := newCoverageCache(t)
			done := make(chan error, 1)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			waits := NewTypeURLCallbacks()
			waits.Set(typeurl.Endpoint, func(err error) { done <- err })
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
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
			requireCoveragePending(t, done)
			if reject {
				second.reply(t, b, "invalid b", "b")
				require.ErrorContains(t, <-done, "invalid b")
				// A and B belong to one API transaction. A's partial ACK must
				// not discard the state needed to undo that whole transaction.
				for _, name := range []string{"a", "b"} {
					require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, name), name)
				}
			} else {
				second.reply(t, b, "", "b")
				require.NoError(t, <-done)
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
	noOp := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "b", b, wg,
		func(err error) { noOp <- err }))
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)
	requireCoveragePending(t, noOp)
	// A is already accepted; its no-op must not wait for B's later response,
	// nor complete B's existing wait as a side effect.
	accepted := make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", a, wg,
		func(err error) { accepted <- err }))
	require.NoError(t, <-accepted)
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
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil, nil))
					var resource *listener.Listener
					if existing {
						resource = &listener.Listener{Name: "listener"}
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil, nil))
					}
					c.ClearSnapshot("coverage-node")
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					t.Cleanup(cancel)
					wg := completion.NewWaitGroup(ctx)
					t.Cleanup(wg.Cancel)
					done := make(chan error, 1)
					callback := func(err error) { done <- err }
					if bulk {
						var waits TypeURLCallbacks
						waits.Set(typeurl.Listener, callback)
						require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{Upserted: xds.Resources{
							Listeners: map[string]*listener.Listener{"listener": resource},
						}}, wg, waits))
					} else {
						require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "listener", resource, wg, callback))
					}
					requireCoveragePending(t, done)
					_, err := c.GetSnapshot("coverage-node")
					require.Error(t, err, "a no-op must not force publication")
					s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
					response := s.receive(t)
					require.Equal(t, existing, len(response.Resources) != 0)
					requireCoveragePending(t, done)
					s.reply(t, response, rejection)
					if rejection == "" {
						require.NoError(t, wg.Wait())
						require.NoError(t, <-done)
					} else {
						require.ErrorContains(t, wg.Wait(), rejection)
						require.ErrorContains(t, <-done, rejection)
					}
					require.Empty(t, done)
					current := c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy")
					require.NotNil(t, current)
					require.Same(t, policy, current, "an LDS outcome must not revert the unrelated policy")
				})
			}
		}
	}
}

func TestInitialBulkMutationCanAwaitUnchangedType(t *testing.T) {
	c := newCoverageCache(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	var waits TypeURLCallbacks
	waits.Set(typeurl.Listener, func(err error) { done <- err })
	// The first real mutation can also require ACK evidence for an unchanged
	// type. Preparing that wait must not require an already published snapshot.
	resource := &cluster.Cluster{Name: "cluster"}
	require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{
		Removed:  xds.Resources{Listeners: map[string]*listener.Listener{"absent": nil}},
		Upserted: xds.Resources{Clusters: map[string]*cluster.Cluster{resource.Name: resource}},
	}, wg, waits))
	requireCoveragePending(t, done)
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t)
	require.Empty(t, response.Resources)
	requireCoveragePending(t, done)
	s.reply(t, response, "")
	require.NoError(t, wg.Wait())
	require.NoError(t, <-done)
	current := c.GetResource("coverage-node", typeurl.Cluster, resource.Name)
	require.NotNil(t, current)
	require.Same(t, resource, current)
}

func TestNoOpWaitAfterClearUsesAcceptedVersion(t *testing.T) {
	c := newCoverageCache(t)
	resource := &listener.Listener{Name: "listener"}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	s.reply(t, s.receive(t), "")
	c.ClearSnapshot("coverage-node")
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, wg,
		func(err error) { done <- err }))
	requireCoveragePending(t, done)
	// Reinstalling already ACKed contents can satisfy the wait immediately.
	// No OnStreamResponse call should be required to run that completion.
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(),
	}, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case err := <-done:
		require.NoError(t, err)
	default:
		t.Fatal("initial publication did not complete the wait for already ACKed contents")
	}
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
	backend := c.SnapshotCache
	publicationErr := errors.New("snapshot publication failed")
	failed := newMockSnapshotCache()
	failed.snapshots["coverage-node"] = previous
	failed.setSnapshotErr = publicationErr
	c.SnapshotCache = failed
	// Keep an EDS watch open so failure is exercised by this mutation, not
	// deferred to a later request. The mock never consumes this watch.
	cancelWatch, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Endpoint.URL(),
		ResourceNames: []string{"a"}, VersionInfo: previous.GetVersion(typeurl.Endpoint.URL()),
	}, stream.NewSotwSubscription([]string{"a"}, false), make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	err = c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", nil, nil, nil)
	c.SnapshotCache = backend
	require.ErrorIs(t, err, publicationErr)
	current := c.GetResource("coverage-node", typeurl.Endpoint, "a")
	require.NotNil(t, current)
	require.Same(t, a, current)

	done := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", a, wg,
		func(err error) { done <- err }))
	select {
	case err := <-done:
		require.NoError(t, err)
	default:
		t.Fatal("an already-ACKed resource must complete without another response after failed publication")
	}
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
					&listener.Listener{Name: name}, nil, nil))
			}
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			response := s.receive(t)
			s.reply(t, response, "")
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", nil, nil, nil))
			response = s.receive(t)
			s.reply(t, response, "")

			// A's removal is already ACKed. A newer, in-flight response changing
			// B must not make another removal of A wait for B's ACK. In bulk input,
			// a typed nil upsert has the same removal semantics as an explicit delete.
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			bDone := make(chan error, 1)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "b",
				&listener.Listener{Name: "b", TrafficDirection: core.TrafficDirection_OUTBOUND}, wg,
				func(err error) { bDone <- err }))
			response = s.receive(t)
			requireCoveragePending(t, bDone)

			done := make(chan error, 1)
			callback := func(err error) { done <- err }
			if mode == "single" {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", nil, wg, callback))
			} else if mode == "single-typed-nil" {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", (*listener.Listener)(nil), wg, callback))
			} else {
				mutations := ResourceMutations{}
				if mode == "bulk-removal" {
					mutations.Removed.Listeners = map[string]*listener.Listener{"a": nil}
				} else {
					mutations.Upserted.Listeners = map[string]*listener.Listener{"a": nil}
				}
				waits := NewTypeURLCallbacks()
				waits.Set(typeurl.Listener, callback)
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, wg, waits))
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			default:
				t.Fatal("an already-ACKed removal must complete without waiting for an unrelated listener")
			}
			requireCoveragePending(t, bDone)
			s.reply(t, response, "")
			require.NoError(t, <-bDone)
			require.NoError(t, wg.Wait())
		})
	}
}

func TestRepeatedRemovalWaitsForPendingOutcome(t *testing.T) {
	for _, mode := range []string{"single-nil", "single-typed-nil", "bulk-removal", "bulk-nil-upsert"} {
		for _, phase := range []string{"before-response", "after-response"} {
			for _, reject := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reject=%t", mode, phase, reject), func(t *testing.T) {
					c := newCoverageCache(t)
					original := &listener.Listener{Name: "a"}
					other := &listener.Listener{Name: "b"}
					for _, resource := range []*listener.Listener{original, other} {
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, resource.Name, resource, nil, nil))
					}
					s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
					s.reply(t, s.receive(t), "")

					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					t.Cleanup(cancel)
					remove := func(wg *completion.WaitGroup, callback func(error)) error {
						switch mode {
						case "single-nil":
							return c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "a", nil, wg, callback)
						case "single-typed-nil":
							return c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "a", (*listener.Listener)(nil), wg, callback)
						default:
							var mutations ResourceMutations
							if mode == "bulk-removal" {
								mutations.Removed.Listeners = map[string]*listener.Listener{"a": nil}
							} else {
								mutations.Upserted.Listeners = map[string]*listener.Listener{"a": nil}
							}
							var waits TypeURLCallbacks
							waits.Set(typeurl.Listener, callback)
							return c.ApplyResources(ctx, "coverage-node", mutations, wg, waits)
						}
					}
					first, second := completion.NewWaitGroup(ctx), completion.NewWaitGroup(ctx)
					t.Cleanup(first.Cancel)
					t.Cleanup(second.Cancel)
					firstDone, secondDone := make(chan error, 2), make(chan error, 2)
					require.NoError(t, remove(first, func(err error) { firstDone <- err }))
					requireCoveragePending(t, firstDone)
					require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, "a"))
					var response *discovery.DiscoveryResponse
					if phase == "after-response" {
						response = s.receive(t)
					}
					published := mustSnapshot(t, c, "coverage-node")
					// The second removal is a no-op, but its absence has not yet been
					// accepted. Typed nil must attach to the same pending outcome.
					require.NoError(t, remove(second, func(err error) { secondDone <- err }))
					requireCoveragePending(t, secondDone)
					require.Same(t, published, mustSnapshot(t, c, "coverage-node"))
					if response == nil {
						response = s.receive(t)
					}
					require.Len(t, response.Resources, 1)
					rejection := ""
					if reject {
						rejection = "invalid listener response"
					}
					s.reply(t, response, rejection)
					for _, wg := range []*completion.WaitGroup{first, second} {
						if reject {
							require.ErrorContains(t, wg.Wait(), rejection)
						} else {
							require.NoError(t, wg.Wait())
						}
					}
					for _, done := range []chan error{firstDone, secondDone} {
						if reject {
							require.ErrorContains(t, <-done, rejection)
						} else {
							require.NoError(t, <-done)
						}
						require.Empty(t, done, "callback must run exactly once")
					}
					current := c.GetResource("coverage-node", typeurl.Listener, "a")
					if reject {
						require.Same(t, original, current, "NACK must restore the removed resource")
					} else {
						require.Nil(t, current)
					}
					current = c.GetResource("coverage-node", typeurl.Listener, "b")
					require.NotNil(t, current)
					require.Same(t, other, current)
					require.Zero(t, c.completionCbs.PendingCompletionCount())
				})
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
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
				Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{"a": originalA, "b": originalB}},
			}, nil, TypeURLCallbacks{}))
			first := coverageStream{cache: c, id: 1}
			baseline := first.receive(t, "a", "b")
			first.reply(t, baseline, "", "a", "b")
			changedA := proto.Clone(originalA).(*endpoint.ClusterLoadAssignment)
			changedA.Policy = &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(140)}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", changedA, nil, nil))
			olderResponse := first.receive(t, "a")
			if outcome == "ack-unchanged-already-accepted" {
				first.reply(t, olderResponse, "", "a")
			}

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			done := make(chan error, 2)
			var waits TypeURLCallbacks
			waits.Set(typeurl.Endpoint, func(err error) { done <- err })
			changedB := proto.Clone(originalB).(*endpoint.ClusterLoadAssignment)
			changedB.Policy = &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(150)}
			// A is semantically unchanged; B really changes. If A is still
			// unACKed, this wait must preserve their different value revisions.
			require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{
				Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
					"a": proto.Clone(changedA).(*endpoint.ClusterLoadAssignment), "b": changedB,
				}},
			}, wg, waits))
			current := c.GetResource("coverage-node", typeurl.Endpoint, "a")
			require.NotNil(t, current)
			require.Same(t, changedA, current, "no-op must preserve the canonical resource")
			second := coverageStream{cache: c, id: 2, version: baseline.VersionInfo}
			newerResponse := second.receive(t, "b")
			requireCoveragePending(t, done)
			switch outcome {
			case "ack-unchanged-first":
				first.reply(t, olderResponse, "", "a")
				requireCoveragePending(t, done)
				second.reply(t, newerResponse, "", "b")
			case "ack-changed-first":
				second.reply(t, newerResponse, "", "b")
				requireCoveragePending(t, done)
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
				require.ErrorContains(t, <-done, "invalid b")
				first.reply(t, olderResponse, "", "a")
			} else {
				require.NoError(t, wg.Wait())
				require.NoError(t, <-done)
			}
			require.Empty(t, done, "callback must run exactly once")
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
	noOp := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "b", b, wg,
		func(err error) { noOp <- err }))
	requireCoveragePending(t, noOp)
	second := coverageStream{cache: c, id: 2, version: response.VersionInfo}
	response = second.receive(t, "b")
	second.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-bDone, "invalid b")
	require.ErrorContains(t, <-noOp, "invalid b")
}

func TestPartialLDSReconnectWithWildcardDoesNotAcceptUnsentName(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	aDone, bDone := make(chan error, 1), make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, wg,
		func(err error) { aDone <- err }))
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "b", &listener.Listener{Name: "b"}, wg,
		func(err error) { bDone <- err }))
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
	done := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", updated, wg,
		func(err error) { done <- err }))
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

func TestNoOpAfterCallerRevertWaitsForCorrectiveACK(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		for _, delivery := range []string{"one-stream", "two-streams", "delayed-response", "previously-accepted"} {
			t.Run(api+"/"+delivery, func(t *testing.T) {
				c := newCoverageCache(t)
				a := &listener.Listener{Name: "resource", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
				b := proto.Clone(a).(*listener.Listener)
				b.PerConnectionBufferLimitBytes = wrapperspb.UInt32(2)
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, a.Name, a, nil, nil))
				first := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
				second := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
				var original *discovery.DiscoveryResponse
				if delivery != "one-stream" {
					original = first.receive(t, a.Name)
				}
				rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, a.Name, b, nil, nil)
				require.NoError(t, err)
				rejected := &first
				if original != nil {
					rejected = &second
				}
				var outdated *discovery.DiscoveryResponse
				var held cache.Response
				if delivery == "delayed-response" {
					request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(), ResourceNames: []string{a.Name}}
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
					outdated = rejected.receive(t, a.Name)
				}
				if delivery == "previously-accepted" {
					first.reply(t, original, "", a.Name)
				}
				require.NoError(t, rollback.Revert())
				require.Same(t, a, c.GetResource("coverage-node", typeurl.Listener, a.Name))

				done := make(chan error, 1)
				wg := completion.NewWaitGroup(t.Context())
				t.Cleanup(wg.Cancel)
				callback := func(err error) { done <- err }
				candidate := proto.Clone(a).(*listener.Listener)
				if api == "single" {
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, a.Name, candidate, wg, callback))
				} else {
					var waits TypeURLCallbacks
					waits.Set(typeurl.Listener, callback)
					require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{Upserted: xds.Resources{Listeners: map[string]*listener.Listener{a.Name: candidate}}}, wg, waits))
				}
				requireCoveragePending(t, done)
				if held != nil {
					outdated = rejected.deliver(t, held)
				}
				rejected.reply(t, outdated, "", a.Name)
				requireCoveragePending(t, done)
				if original != nil && delivery != "previously-accepted" {
					first.reply(t, original, "", a.Name)
					requireCoveragePending(t, done)
				}
				// Even the stream which accepted the original A must receive a new
				// corrective publication, rather than reuse that historical ACK.
				corrected := first.receive(t, a.Name)
				if original != nil {
					require.NotEqual(t, original.VersionInfo, corrected.VersionInfo)
				}
				first.reply(t, corrected, "", a.Name)
				require.NoError(t, wg.Wait())
				require.NoError(t, <-done)
				require.Empty(t, done, "the corrective ACK must complete the wait once")
			})
		}
	}
}

func TestNoOpRemovalAfterCallerRevertWaitsForCorrectiveACK(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		t.Run(api, func(t *testing.T) {
			c := newCoverageCache(t)
			value := &listener.Listener{Name: "resource"}
			rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, value.Name, value, nil, nil)
			require.NoError(t, err)
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			outdated := s.receive(t)
			require.NoError(t, rollback.Revert())
			require.Nil(t, c.GetResource("coverage-node", typeurl.Listener, value.Name))

			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			done := make(chan error, 1)
			callback := func(err error) { done <- err }
			if api == "single" {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, value.Name, nil, wg, callback))
			} else {
				var waits TypeURLCallbacks
				waits.Set(typeurl.Listener, callback)
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{Removed: xds.Resources{Listeners: map[string]*listener.Listener{value.Name: nil}}}, wg, waits))
			}
			requireCoveragePending(t, done)
			s.reply(t, outdated, "")
			requireCoveragePending(t, done)
			corrected := s.receive(t)
			require.Empty(t, corrected.Resources)
			s.reply(t, corrected, "")
			require.NoError(t, wg.Wait())
			require.NoError(t, <-done)
		})
	}
}

func TestCallerRevertKeepsUnrelatedResourceAccepted(t *testing.T) {
	c := newCoverageCache(t)
	unchanged := &listener.Listener{Name: "unchanged"}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, unchanged.Name, unchanged, nil, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t, unchanged.Name)
	s.reply(t, response, "", unchanged.Name)
	rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Listener, "reverted", &listener.Listener{Name: "reverted"}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, rollback.Revert())

	// The type's corrective wire version does not invalidate ACK evidence for
	// a resource whose desired entry was not restored by this rollback.
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, unchanged.Name, proto.Clone(unchanged), wg, func(err error) { done <- err }))
	require.NoError(t, wg.Wait())
	require.NoError(t, <-done)
}

func TestPartialNACKRevertsCoalescedTransactionSiblings(t *testing.T) {
	c := newCoverageCache(t)
	done := make(chan error, 1)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	waits := NewTypeURLCallbacks()
	waits.Set(typeurl.Endpoint, func(err error) { done <- err })
	require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
			"a": {ClusterName: "a"}, "b": {ClusterName: "b"},
		}},
	}, wg, waits))
	_, unrelatedDone := upsertCoverageEndpoint(t, c, "unrelated")
	latestDone := make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a",
		&endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}, wg,
		func(err error) { latestDone <- err }))
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	require.ErrorContains(t, <-done, "invalid a")
	require.ErrorContains(t, <-latestDone, "invalid a")
	for _, name := range []string{"a", "b"} {
		require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, name), name)
	}
	requireCoveragePending(t, unrelatedDone)
	require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "unrelated"))
}

func TestPartialNACKRevertsCrossTypeTransaction(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	endpointDone, clusterDone := make(chan error, 1), make(chan error, 1)
	waits := NewTypeURLCallbacks()
	waits.Set(typeurl.Endpoint, func(err error) { endpointDone <- err })
	waits.Set(typeurl.Cluster, func(err error) { clusterDone <- err })
	require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{
			Endpoints: map[string]*endpoint.ClusterLoadAssignment{"a": {ClusterName: "a"}},
			Clusters:  map[string]*cluster.Cluster{"cluster-a": {Name: "cluster-a"}},
		},
	}, wg, waits))
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	require.ErrorContains(t, <-endpointDone, "invalid a")
	require.ErrorContains(t, <-clusterDone, "invalid a")
	require.Nil(t, c.GetResource("coverage-node", typeurl.Cluster, "cluster-a"))
}

func TestPartialNACKPreservesNewerUnrequestedTransactionSibling(t *testing.T) {
	c := newCoverageCache(t)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	waits := NewTypeURLCallbacks()
	waits.Set(typeurl.Endpoint, func(err error) { done <- err })
	require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
		Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
			"a": {ClusterName: "a"}, "b": {ClusterName: "b"},
		}},
	}, wg, waits))
	newer := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
	aDone := make(chan error, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", newer, wg, func(err error) { aDone <- err }))
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "b")
	s.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-done, "invalid b")
	requireCoveragePending(t, aDone)
	actual := c.GetResource("coverage-node", typeurl.Endpoint, "a")
	require.NotNil(t, actual)
	require.Same(t, newer, actual)
	response = s.receive(t, "a")
	s.reply(t, response, "", "a")
	require.NoError(t, <-aDone)
}

func TestNamedFullPositiveResponseDoesNotAcceptUnrequestedRemoval(t *testing.T) {
	c := newCoverageCache(t)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, nil, nil))
	s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
	response := s.receive(t, "a")
	s.reply(t, response, "", "a")
	// All positive resources were delivered, but the named request proves
	// nothing about an absent name outside that subscription.
	require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Listener, "b", nil, false, callbacks.Revision{}))
	require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Listener, "a", &listener.Listener{Name: "a"}, true, callbacks.Revision{}))
}

func TestPartialResponseRollbackMembershipIsBoundedBeforeConnection(t *testing.T) {
	c := newCoverageCache(t)
	for update := range 100 {
		require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{
			Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
				"a": {ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(uint32(update + 1))}},
				"b": {ClusterName: "b", Policy: &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(uint32(update + 1))}},
			}},
		}, nil, TypeURLCallbacks{}))
	}
	// Inspect only the lifetime invariant: without any connected Envoy, memory
	// must depend on the two live resources, not the hundred API transactions.
	state := c.getNodeState("coverage-node")
	state.requireNoUnsentRollbacks(t, "there is no published snapshot before the first watch")
	require.NotNil(t, state.pendingPublication)
	require.Equal(t, 1, state.pendingPublication.rollbacks.Len())
	rollback, exists := state.pendingPublication.rollbacks.Get(typeurl.Endpoint)
	require.True(t, exists)
	require.Len(t, rollback[typeurl.Endpoint], 2)
	for _, entry := range rollback[typeurl.Endpoint] {
		require.Equal(t, 1, entry.transactions.Len())
	}
	// The first response can still reject the coalesced transaction, including
	// its unrequested member. Neither an ACK waiter nor a live caller is needed.
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	s.reply(t, response, "invalid a", "a")
	for _, name := range []string{"a", "b"} {
		require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, name), name)
	}
}

func TestPartialCoverageSurvivesSubscriptionMutation(t *testing.T) {
	c := newCoverageCache(t)
	_, aDone := upsertCoverageEndpoint(t, c, "a")
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	response := s.receive(t, "a")
	// go-control-plane can mutate its returned-resource map as names change.
	// Evidence for the already constructed response must remain immutable.
	s.sub.SetResourceSubscription([]string{"b"})
	s.reply(t, response, "", "b")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)
	response = s.receive(t, "b")
	s.reply(t, response, "", "b")
	require.NoError(t, <-bDone)
}

func TestUnobservedSotWRemovalsDoNotAccumulateRollbackState(t *testing.T) {
	c := newCoverageCache(t)
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	for update := range 20 {
		name := fmt.Sprintf("a-%d", update)
		_, done := upsertCoverageEndpoint(t, c, name)
		response := s.receive(t, name)
		s.reply(t, response, "", name)
		require.NoError(t, <-done)
		require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, name, nil, nil, nil))
	}
	// B has never been requested. Its live inverse must not keep the unrelated
	// EDS removals above: omission does not convey their removal to Envoy.
	state := c.getNodeState("coverage-node")
	rollback := state.typeStates[typeurl.Endpoint].rollbacks.unsent
	require.NotNil(t, rollback)
	require.Len(t, (*rollback.resources)[typeurl.Endpoint], 1)
	require.Contains(t, (*rollback.resources)[typeurl.Endpoint], "b")
	require.Len(t, state.resources[typeurl.Endpoint], 1)
	response := s.receive(t, "b")
	s.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-bDone, "invalid b")
	for update := range 20 {
		require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, fmt.Sprintf("a-%d", update)), "NACK of B must not resurrect an unrelated removal")
	}
}

func TestSotWRemovalCoverage(t *testing.T) {
	for _, tc := range []struct {
		index    typeurl.Index
		resource proto.Message
	}{
		{typeurl.Listener, &listener.Listener{Name: "a"}},
		{typeurl.Cluster, &cluster.Cluster{Name: "a"}},
		{typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "a"}},
		{typeurl.Route, &route.RouteConfiguration{Name: "a"}},
		{typeurl.Secret, &secret.Secret{Name: "a"}},
	} {
		t.Run(tc.index.URL(), func(t *testing.T) {
			c := newCoverageCache(t)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", tc.index, "a", tc.resource, nil, nil))
			s := coverageStream{cache: c, id: 1, typeURL: tc.index.URL()}
			response := s.receive(t, "a")
			s.reply(t, response, "", "a")
			done := make(chan error, 1)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", tc.index, "a", nil, wg,
				func(err error) { done <- err }))
			response = s.receive(t, "a")
			require.Empty(t, response.Resources)
			s.reply(t, response, "", "a")
			if tc.index == typeurl.Listener || tc.index == typeurl.Cluster {
				// These SotW types signal removal by omission.
				require.NoError(t, <-done)
				require.True(t, c.completionCbs.ResourceAccepted("coverage-node", tc.index, "a", nil, false, callbacks.Revision{}))
			} else {
				// A missing EDS/RDS/SDS resource was not delivered or deleted.
				// There is no positive ACK evidence for the caller's removal.
				requireCoveragePending(t, done)
				require.False(t, c.completionCbs.ResourceAccepted("coverage-node", tc.index, "a", nil, false, callbacks.Revision{}))
			}
			// A removal-only response cannot reject a resource which was not
			// sent. Retaining its inverse/tombstone would leak removed names.
			c.getNodeState("coverage-node").requireNoUnsentRollbacks(t)
			c.getNodeState("coverage-node").requireNoRollbackOwners(t)
		})
	}
}

func TestSotWOmissionNACKDoesNotRejectRemovalWait(t *testing.T) {
	for _, tc := range []struct {
		index    typeurl.Index
		resource proto.Message
	}{
		{typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "a"}},
		{typeurl.Route, &route.RouteConfiguration{Name: "a"}},
		{typeurl.Secret, &secret.Secret{Name: "a"}},
	} {
		t.Run(tc.index.URL(), func(t *testing.T) {
			c := newCoverageCache(t)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", tc.index, "a", tc.resource, nil, nil))
			s := coverageStream{cache: c, id: 1, typeURL: tc.index.URL()}
			var names []string
			if tc.index == typeurl.Secret {
				// SDS does not support wildcard requests in this cache.
				names = []string{"a"}
			}
			response := s.receive(t, names...)
			s.reply(t, response, "", names...)
			done := make(chan error, 2)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			remove := func() {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", tc.index, "a", nil, wg,
					func(err error) { done <- err }))
			}
			remove()
			response = s.receive(t, names...)
			require.Empty(t, response.Resources)
			s.reply(t, response, "empty response rejected", names...)
			requireCoveragePending(t, done)
			// This NACK also must not become a whole-version rejection shortcut
			// for a new no-op removal wait which the empty response cannot test.
			remove()
			requireCoveragePending(t, done)
		})
	}
}
