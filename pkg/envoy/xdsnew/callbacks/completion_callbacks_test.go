// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"testing"
	"time"
	"weak"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/revert"
)

const listenerTypeURL = typeurl.Listener

var completionTypeURLs = []struct {
	name    string
	typeURL typeurl.Index
}{
	{name: "network-policy", typeURL: typeurl.NetworkPolicy},
	{name: "listener", typeURL: typeurl.Listener},
}

// finalizingTestRollback exercises callback finalization independently of the
// cache-owned rollback lifecycle.
type finalizingTestRollback struct {
	revert.RevertFunc
	finalize func()
}

func (rollback finalizingTestRollback) Finalize() {
	rollback.finalize()
}

func newTestCompletionCallbacks() *CompletionCallbacks {
	return NewCompletionCallbacks(slog.New(slog.DiscardHandler), testNACKHandler{})
}

// Callback-only tests supply synthetic inverses, not a resource cache. Cache
// tests exercise atomic composition, publication and failure restoration.
type testNACKHandler struct{}

func (testNACKHandler) HandleNACK(_ string, process func(RevertBatch) error) error {
	return process(func(rollbacks []Rollback) error {
		for _, rollback := range rollbacks {
			if err := rollback.Revert(); err != nil {
				return err
			}
		}
		return nil
	})
}

// testEDSStream exercises callback identity through the public transport hooks,
// including named subscriptions with independent stream-ID and nonce spaces.
// Versions are opaque here; generations are carried by the response context.
type testEDSStream struct {
	callbacks *CompletionCallbacks
	streamID  int64
	name      string
}

func (stream testEDSStream) open(t *testing.T) {
	t.Helper()
	require.NoError(t, stream.callbacks.OnStreamOpen(t.Context(), stream.streamID, typeurl.Endpoint.URL()))
}

func (stream testEDSStream) request(t *testing.T, generation Generation, nonce, rejection string) {
	t.Helper()
	var detail *status.Status
	if rejection != "" {
		detail = &status.Status{Message: rejection}
	}
	version := ""
	if generation != 0 {
		version = fmt.Sprintf("e1:g%d", generation)
	}
	require.NoError(t, stream.callbacks.OnStreamRequest(stream.streamID, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Endpoint.URL(), VersionInfo: version,
		ResponseNonce: nonce, ErrorDetail: detail, ResourceNames: []string{stream.name},
	}))
}

func (stream testEDSStream) respond(t *testing.T, generation Generation, nonce string) {
	t.Helper()
	stream.callbacks.OnStreamResponse(WithSnapshotGeneration(t.Context(), generation), stream.streamID,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Endpoint.URL(), ResourceNames: []string{stream.name}},
		&discovery.DiscoveryResponse{TypeUrl: typeurl.Endpoint.URL(), VersionInfo: fmt.Sprintf("e1:g%d", generation), Nonce: nonce})
}

func (stream testEDSStream) close() {
	stream.callbacks.OnStreamClosed(stream.streamID, nil)
}

func TestResponseIdentityIncludesStreamID(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			owner := testEDSStream{callbacks: cb, streamID: 1, name: "cluster"}
			other := testEDSStream{callbacks: cb, streamID: 2, name: "cluster"}
			owner.open(t)
			owner.request(t, 0, "", "")
			wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 1)
			registerTypeGenerationCompletion(t, cb, comp, pending, "e1:g1")
			reverted := false
			registerTypeGenerationRollback(t, cb, 1, typeurl.Endpoint, func() error { reverted = true; return nil })
			owner.respond(t, 1, "nonce-1")
			other.open(t)
			detail := ""
			if reject {
				detail = "foreign rejection"
			}
			other.request(t, 1, "nonce-1", detail)
			requireCompletionPending(t, comp)
			require.False(t, reverted, "an identical nonce on another stream is not this response")
			other.close()
			owner.request(t, 1, "nonce-1", "")
			require.NoError(t, wg.Wait())
			owner.close()
		})
	}
}

func TestNonACKSubscriptionKeepsInFlightResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	stream := testEDSStream{callbacks: cb, streamID: 1, name: "cluster-a"}
	stream.open(t)
	stream.request(t, 0, "", "")
	wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 1)
	registerTypeGenerationCompletion(t, cb, comp, pending, "e1:g1")
	stream.respond(t, 1, "nonce-1")
	stream.name = "cluster-b"
	stream.request(t, 0, "", "")
	requireCompletionPending(t, comp)
	stream.request(t, 1, "nonce-1", "")
	require.NoError(t, wg.Wait(), "a subscription change must not lose the pending response's ACK")
	stream.close()
}

func TestConcurrentEDSStreamResponses(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%t", reject), func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			first := testEDSStream{callbacks: cb, streamID: 1, name: "cluster-a"}
			second := testEDSStream{callbacks: cb, streamID: 2, name: "cluster-b"}
			first.open(t)
			first.request(t, 0, "", "")
			firstWG, firstComp, firstPending := cb.newTestCompletion(t, typeurl.Endpoint, 1)
			registerTypeGenerationCompletion(t, cb, firstComp, firstPending, "e1:g1")
			firstReverted := false
			registerTypeGenerationRollback(t, cb, 1, typeurl.Endpoint, func() error { firstReverted = true; return nil })
			first.respond(t, 1, "nonce-1")
			second.open(t)
			second.request(t, 0, "", "")
			secondWG, secondComp, secondPending := cb.newTestCompletion(t, typeurl.Endpoint, 2)
			registerTypeGenerationCompletion(t, cb, secondComp, secondPending, "e1:g2")
			secondReverted := false
			registerTypeGenerationRollback(t, cb, 2, typeurl.Endpoint, func() error { secondReverted = true; return nil })
			second.respond(t, 2, "nonce-1")
			detail := ""
			if reject {
				detail = "rejected older response"
			}
			first.request(t, 1, "nonce-1", detail)
			if reject {
				require.ErrorContains(t, firstWG.Wait(), detail)
			} else {
				require.NoError(t, firstWG.Wait())
			}
			require.Equal(t, reject, firstReverted)
			requireCompletionPending(t, secondComp)
			require.False(t, secondReverted, "an older response cannot reject the newer generation")
			second.request(t, 2, "nonce-1", "")
			require.NoError(t, secondWG.Wait())
			first.close()
			second.close()
		})
	}
}

func TestOlderStreamACKPreservesNewerAcceptance(t *testing.T) {
	cb := newTestCompletionCallbacks()
	first := testEDSStream{callbacks: cb, streamID: 1, name: "cluster"}
	second := testEDSStream{callbacks: cb, streamID: 2, name: "cluster"}
	first.open(t)
	first.request(t, 0, "", "")
	first.respond(t, 1, "nonce-1")
	second.open(t)
	second.request(t, 0, "", "")
	resource := &endpoint.ClusterLoadAssignment{ClusterName: "cluster"}
	snapshot, err := cache.NewSnapshot("e1:g2", map[string][]cache_types.Resource{typeurl.Endpoint.URL(): {resource}})
	require.NoError(t, err)
	cb.SetPublishedSnapshot("node-1", snapshot)
	second.respond(t, 2, "nonce-1")
	second.request(t, 2, "nonce-1", "")
	require.True(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", resource, true, Revision{}))
	// Both delayed response delivery and its ACK must preserve the
	// newer accepted baseline and immediate no-op completions.
	first.respond(t, 1, "delayed-nonce")
	wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 2)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "e1:g2", false)
	require.NoError(t, err)
	require.False(t, registered, "a delayed older response must not block an already-accepted no-op")
	comp.Complete(nil)
	require.NoError(t, wg.Wait())
	first.request(t, 1, "delayed-nonce", "")
	require.True(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", resource, true, Revision{}),
		"a delayed ACK must not invalidate the newer accepted resource group")
	first.close()
	second.close()
}

func TestClosedStreamCannotResolveOtherStreamResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	closed := testEDSStream{callbacks: cb, streamID: 1, name: "cluster"}
	live := testEDSStream{callbacks: cb, streamID: 2, name: "cluster"}
	closed.open(t)
	closed.request(t, 0, "", "")
	closed.respond(t, 1, "nonce-1")
	live.open(t)
	live.request(t, 0, "", "")
	wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 2)
	registerTypeGenerationCompletion(t, cb, comp, pending, "e1:g2")
	live.respond(t, 2, "nonce-1")
	closed.close()
	closed.request(t, 2, "nonce-1", "delayed NACK from closed stream")
	requireCompletionPending(t, comp)
	live.request(t, 2, "nonce-1", "")
	require.NoError(t, wg.Wait())
	closed.close()
	live.close()
}

func (cb *CompletionCallbacks) newTestCompletion(t *testing.T, typeURL typeurl.Index, generation Generation) (*completion.WaitGroup, *completion.Completion, *pendingCompletion) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	pending := cb.NewTypeGenerationCompletionOwner("node-1", typeURL, generation, ResourceScope{})
	return wg, wg.AddCompletionWithCallback(pending, nil), pending
}

func registerTypeGenerationRollback(t *testing.T, cb *CompletionCallbacks, generation Generation, typeURL typeurl.Index, rollback revert.RevertFunc) {
	t.Helper()
	cb.AddTypeGenerationWithRollback(generation, typeURL, "node-1", rollback, &ResourceScope{})
}

func registerTypeGenerationCompletion(t *testing.T, cb *CompletionCallbacks, comp *completion.Completion, pending *pendingCompletion, version string) {
	t.Helper()
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, version, true)
	require.NoError(t, err)
	require.True(t, registered)
}

func sendTypeGenerationResponse(cb *CompletionCallbacks, typeURL typeurl.Index, generation Generation, version string) {
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), generation), 1,
		&discovery.DiscoveryRequest{
			Node:    &core.Node{Id: "node-1"},
			TypeUrl: typeURL.URL(),
		},
		&discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     typeURL.URL(),
			Nonce:       "nonce-" + version,
		},
	)
}

func ackTypeVersionResponse(t *testing.T, cb *CompletionCallbacks, typeURL typeurl.Index, version string) {
	t.Helper()
	var nonce string
	if state := cb.typeURLState("node-1", typeURL); state != nil {
		nonce = state.response.pendingNonce
	}
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       typeURL.URL(),
		VersionInfo:   version,
		ResponseNonce: nonce,
	}))
}

func requireCompletionPending(t *testing.T, comp *completion.Completion) {
	t.Helper()
	select {
	case <-comp.Completed():
		require.Fail(t, "completion was completed unexpectedly")
	default:
	}
}

func newListenerSnapshot(t *testing.T, version string, resources ...cache_types.Resource) *cache.Snapshot {
	t.Helper()
	snapshot, err := cache.NewSnapshot(version, map[string][]cache_types.Resource{
		typeurl.Listener.URL(): resources,
	})
	require.NoError(t, err)
	return snapshot
}

func TestAcceptedResourcesDoNotRetainUnrelatedSnapshotState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	// Limit strong references to the old snapshot and secret to this scope.
	// Only its Listener group should survive in the callbacks after publication
	// advances to a new snapshot containing no secrets.
	oldSnapshot, oldSecret := func() (weak.Pointer[cache.Snapshot], weak.Pointer[tls.Secret]) {
		resource := &listener.Listener{Name: "listener-1"}
		secret := &tls.Secret{Name: "old-secret"}
		snapshot, err := cache.NewSnapshot("version-1", map[string][]cache_types.Resource{
			typeurl.Listener.URL(): {resource},
			typeurl.Secret.URL():   {secret},
		})
		require.NoError(t, err)
		cb.SetPublishedSnapshot("node-1", snapshot)
		sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
		ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
		cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
		return weak.Make(snapshot), weak.Make(secret)
	}()

	runtime.GC()
	require.Nil(t, oldSnapshot.Value(), "a type ACK must not retain the whole snapshot")
	require.Nil(t, oldSecret.Value(), "a Listener ACK must not retain unrelated Secrets")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1",
		&listener.Listener{Name: "listener-1"}, true, Revision{}))
	runtime.KeepAlive(cb)
}

func TestAcceptedResourcesDistinguishEmptyFromUnknown(t *testing.T) {
	for name, resources := range map[string]map[string]cache_types.ResourceWithTTL{
		"nil-map":   nil,
		"empty-map": {},
	} {
		t.Run(name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false, Revision{}))
			snapshot := newListenerSnapshot(t, "version-1")
			snapshot.Resources[cache_types.Listener].Items = resources
			cb.SetPublishedSnapshot("node-1", snapshot)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false, Revision{}),
				"publishing an empty group does not make its absence accepted")
			sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1",
				&listener.Listener{Name: "listener-1"}, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", typeurl.Secret, "secret-1", nil, false, Revision{}),
				"an ACK for one empty type does not accept another type")
		})
	}
}

func TestAcceptedResourcesInvalidateUnmatchedACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	a := &listener.Listener{Name: "listener-1", StatPrefix: "a"}
	b := &listener.Listener{Name: "listener-1", StatPrefix: "b"}
	c := &listener.Listener{Name: "listener-1", StatPrefix: "c"}
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-a", a))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true, Revision{}))

	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 2)
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-b")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-b")
	// A newer publication can arrive while the previous response is in flight.
	// ACKing B makes A obsolete, but must not promote the unsent C either. With
	// no matching published group, resource-level acceptance must be unknown.
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-c", c))
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-b")
	require.NoError(t, wg.Wait(), "B's ACK still completes B's waiter normally")
	for _, resource := range []*listener.Listener{a, b, c} {
		require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}),
			"must not assume acceptance for %s", resource.StatPrefix)
	}
	require.False(t, cb.ChangedResourceAccepted("node-1", listenerTypeURL, a.Name, c, true, a, true, Revision{}),
		"returning the desired resource to A must not reuse A's obsolete acceptance")

	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-c")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-c")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, c.Name, c, true, Revision{}))
	require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true, Revision{}))
}

func TestAcceptedResourcesACKAfterUnrelatedPublication(t *testing.T) {
	cb := newTestCompletionCallbacks()
	resource := &listener.Listener{Name: "listener-1"}
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	snapshot := newListenerSnapshot(t, "version-1", resource)
	snapshot.Resources[cache_types.Secret] = cache.NewResources("version-2", []cache_types.Resource{
		&tls.Secret{Name: "secret-1"},
	})
	cb.SetPublishedSnapshot("node-1", snapshot)
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}),
		"another type's newer publication does not invalidate the ACKed Listener group")
}

func TestAcceptedResourcesPreserveLastACKOnNACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	a := &listener.Listener{Name: "listener-1", StatPrefix: "a"}
	b := &listener.Listener{Name: "listener-1", StatPrefix: "b"}
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-a", a))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-b")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-a",
		ResponseNonce: "nonce-version-b",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true, Revision{}))
	require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, b.Name, b, true, Revision{}))
}

func TestAcceptedResourcesCleared(t *testing.T) {
	for _, tt := range []struct {
		name  string
		clear func(*testing.T, *CompletionCallbacks)
	}{
		{name: "snapshot-cleared", clear: func(_ *testing.T, cb *CompletionCallbacks) {
			cb.SetPublishedSnapshot("node-1", nil)
		}},
		{name: "fresh-subscription", clear: func(t *testing.T, cb *CompletionCallbacks) {
			require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL(),
			}))
		}},
		{name: "last-stream-closed", clear: func(_ *testing.T, cb *CompletionCallbacks) {
			cb.OnStreamClosed(1, &core.Node{Id: "node-1"})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			resource := &listener.Listener{Name: "listener-1"}
			cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
			sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
			tt.clear(t, cb)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, nil, false, Revision{}))
		})
	}
}

func TestDiscardUnsentTypeGenerationOnlyBeforeResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	finalized := 0
	rollback := finalizingTestRollback{finalize: func() { finalized++ }}
	cb.AddTypeGenerationWithRollback(1, typeurl.Endpoint, "node-1", rollback, &ResourceScope{})
	require.True(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 1))
	require.Nil(t, cb.typeURLState("node-1", typeurl.Endpoint).pendingGenerations)
	require.Zero(t, finalized, "the cache owns finalization after discarding the generation")

	cb.AddTypeGenerationWithRollback(2, typeurl.Endpoint, "node-1", rollback, &ResourceScope{})
	sendTypeGenerationResponse(cb, typeurl.Endpoint, 2, "version-2")
	require.False(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 2),
		"a response must retain its rollback until ACK or NACK")
	ackTypeVersionResponse(t, cb, typeurl.Endpoint, "version-2")
	require.Equal(t, 1, finalized)
}

func TestCoalescedPendingGenerationUsesNewKey(t *testing.T) {
	cb := newTestCompletionCallbacks()
	var reverted []Generation
	for _, generation := range []Generation{1, 3, 5} {
		registerTypeGenerationRollback(t, cb, generation, listenerTypeURL, func() error {
			reverted = append(reverted, generation)
			return nil
		})
	}
	state := cb.typeURLState("node-1", listenerTypeURL)
	pending := state.pendingGenerations[1]
	require.True(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 1, 4, &ResourceScope{}))
	require.NotContains(t, state.pendingGenerations, Generation(1))
	require.Same(t, pending, state.pendingGenerations[4], "coalescing must reuse the pending object")
	require.False(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 4, 5, &ResourceScope{}),
		"coalescing must not overwrite another pending generation")

	// Moving generation 1 to key 4 must keep it out of an earlier response,
	// including when finalization attaches updates to an in-flight version.
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	complete, err := cb.FinalizeTypeGeneration("node-1", listenerTypeURL, 2, "version-2", true)
	require.NoError(t, err)
	require.False(t, complete)
	for _, pending := range state.pendingGenerations {
		require.Zero(t, pending.responseGeneration)
	}
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-2")
	require.Len(t, state.pendingGenerations, 3)

	sendTypeGenerationResponse(cb, listenerTypeURL, 4, "version-4")
	require.Equal(t, Generation(4), state.pendingGenerations[3].responseGeneration)
	require.Equal(t, Generation(4), pending.responseGeneration)
	require.Zero(t, state.pendingGenerations[5].responseGeneration)
	require.False(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 4, 6, &ResourceScope{}),
		"a response-owned generation must not be moved")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-2",
		ResponseNonce: "nonce-version-4",
		ErrorDetail:   &status.Status{Message: "rejected coalesced listener"},
	}))
	// The rollback originally registered at generation 1 now represents key 4,
	// so it must run before generation 3. Generation 5 is not in this response.
	require.Equal(t, []Generation{1, 3}, reverted)
	require.Len(t, state.pendingGenerations, 1)
	require.Contains(t, state.pendingGenerations, Generation(5))

	sendTypeGenerationResponse(cb, listenerTypeURL, 5, "version-5")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-5")
	require.Nil(t, state.pendingGenerations)
	require.Equal(t, []Generation{1, 3}, reverted)
}

func TestAddTypeGenerationCompletionCompletesAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1"))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", true)
	require.NoError(t, err)
	require.False(t, registered)

	require.Zero(t, cb.PendingCompletionCount())
	comp.Complete(nil)
	require.NoError(t, wg.Wait())
}

func TestUnknownTypeURLDoesNotCreateCompletionState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	const unknownTypeURL = "type.googleapis.com/example.Unknown"

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:    &core.Node{Id: "node-1"},
		TypeUrl: unknownTypeURL,
	}))
	cb.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: unknownTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: unknownTypeURL},
	)

	require.Nil(t, cb.nodes["node-1"])
	require.Zero(t, cb.PendingCompletionCount())
}

func TestAddTypeGenerationCompletionKeepsPendingForNewVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	_, comp, pending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 2)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-2", true)
	require.NoError(t, err)
	require.True(t, registered)

	require.Equal(t, 1, cb.PendingCompletionCount())
}

func TestOnStreamResponseCompletesPendingCompletionForAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1"))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "", true)
	require.NoError(t, err)
	require.True(t, registered)
	require.Equal(t, 1, cb.PendingCompletionCount())

	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL()},
	)

	require.Zero(t, cb.PendingCompletionCount())
	require.NoError(t, wg.Wait())
}

func TestCompletionCallbacksUseStreamNodeIDWhenACKOmitsNode(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "node-1"},
	}))

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)

	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL()},
	)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     listenerTypeURL.URL(),
	}))
	require.NoError(t, wg.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestCompletionFollowsNewerResponseVersion(t *testing.T) {
	for _, tt := range completionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wg1, comp1, pending1 := cb.newTestCompletion(t, tt.typeURL, 1)
			wg2, comp2, pending2 := cb.newTestCompletion(t, tt.typeURL, 2)

			registerTypeGenerationCompletion(t, cb, comp1, pending1, "version-1")
			registerTypeGenerationCompletion(t, cb, comp2, pending2, "version-2")

			// The later response generation covers the earlier completion even
			// though the two content versions differ.
			sendTypeGenerationResponse(cb, tt.typeURL, 1, "version-1")
			sendTypeGenerationResponse(cb, tt.typeURL, 2, "version-2")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-2")

			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wg1.Wait())
			require.NoError(t, wg2.Wait())
		})
	}
}

func TestNACKRevertsAllCoalescedUpdates(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 3)

	for i, version := range []string{"version-1", "version-2", "version-3"} {
		_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, Generation(i+1))
		registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, version, true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, Generation(i+1), listenerTypeURL,
			func() error {
				reverted = append(reverted, version)
				return nil
			})
	}

	// The response for version-3 coalesces all three pending updates. A NACK
	// rejects the entire response, so all of its updates must be reverted in
	// reverse order to restore the snapshot that preceded the response.
	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-3")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-version-3",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-3", "version-2", "version-1"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestFailedNACKRollbackRetainedForNextResponse(t *testing.T) {
	for _, outcome := range []string{"NACK", "ACK"} {
		t.Run(outcome, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			publicationErr := errors.New("rollback publication failed")
			var reverted, finalized []Generation
			var waits []*completion.WaitGroup
			for i := range 3 {
				generation := Generation(i + 1)
				wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, generation)
				waits = append(waits, wg)
				registerTypeGenerationCompletion(t, cb, comp, pending, "rejected-version")
				cb.AddTypeGenerationWithRollback(generation, listenerTypeURL, "node-1", finalizingTestRollback{
					RevertFunc: func() error {
						reverted = append(reverted, generation)
						if generation == 2 {
							return publicationErr
						}
						return nil
					},
					finalize: func() { finalized = append(finalized, generation) },
				}, &ResourceScope{})
			}
			sendTypeGenerationResponse(cb, listenerTypeURL, 3, "rejected-version")
			require.ErrorIs(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL(),
				VersionInfo: "accepted-version", ResponseNonce: "nonce-rejected-version",
				ErrorDetail: &status.Status{Message: "rejected listener"},
			}), publicationErr)
			require.Equal(t, []Generation{3, 2}, reverted,
				"a failed prerequisite must stop the older rollback chain")
			require.Empty(t, finalized)
			for _, wg := range waits {
				require.ErrorContains(t, wg.Wait(), "rejected listener")
			}
			require.Zero(t, cb.PendingCompletionCount(), "NACKed waits must not wait for recovery")

			cb.OnStreamClosed(1, &core.Node{Id: "node-1"})
			publicationErr = nil
			request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()}
			require.NoError(t, cb.OnStreamRequest(2, request))
			cb.OnStreamResponse(WithSnapshotGeneration(t.Context(), 4), 2, request, &discovery.DiscoveryResponse{
				TypeUrl: listenerTypeURL.URL(), VersionInfo: "retried-version", Nonce: "retry-nonce",
			})
			request.ResponseNonce = "retry-nonce"
			if outcome == "NACK" {
				request.VersionInfo = "accepted-version"
				request.ErrorDetail = &status.Status{Message: "rejected listener again"}
			} else {
				request.VersionInfo = "retried-version"
			}
			require.NoError(t, cb.OnStreamRequest(2, request))
			if outcome == "NACK" {
				require.Equal(t, []Generation{3, 2, 3, 2, 1}, reverted,
					"a failed atomic batch retains every selected inverse")
				require.Empty(t, finalized)
			} else {
				require.Equal(t, []Generation{3, 2}, reverted)
				require.ElementsMatch(t, []Generation{1, 2, 3}, finalized,
					"accepting the desired state must release the retained recovery state")
			}
		})
	}
}

func TestFailedNACKRollbackUsesConcurrentResponseProgress(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		t.Run(fmt.Sprintf("acknowledged=%t", acknowledged), func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			publicationErr := errors.New("rollback publication failed")
			var finalized []Generation
			node := &core.Node{Id: "node-1"}
			request := &discovery.DiscoveryRequest{Node: node, TypeUrl: listenerTypeURL.URL()}
			ack := &discovery.DiscoveryRequest{
				Node: node, TypeUrl: listenerTypeURL.URL(), VersionInfo: "newer-version", ResponseNonce: "newer-nonce",
			}
			for i := range 2 {
				generation := Generation(i + 1)
				cb.AddTypeGenerationWithRollback(generation, listenerTypeURL, node.GetId(), finalizingTestRollback{
					RevertFunc: func() error {
						require.Equal(t, Generation(2), generation, "the older revert must not run after failure")
						// Stream callbacks can interleave here because cache rollback
						// must run without the completion callback mutex held.
						cb.SetPublishedSnapshot(node.GetId(), newListenerSnapshot(t, "newer-version", &listener.Listener{Name: "l1"}))
						cb.OnStreamResponse(WithSnapshotGeneration(t.Context(), 3), 2, request, &discovery.DiscoveryResponse{
							TypeUrl: listenerTypeURL.URL(), VersionInfo: "newer-version", Nonce: "newer-nonce",
						})
						if acknowledged {
							require.NoError(t, cb.OnStreamRequest(2, ack))
						}
						return publicationErr
					},
					finalize: func() { finalized = append(finalized, generation) },
				}, &ResourceScope{})
			}
			sendTypeGenerationResponse(cb, listenerTypeURL, 2, "rejected-version")
			require.ErrorIs(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: node, TypeUrl: listenerTypeURL.URL(), VersionInfo: "accepted-version",
				ResponseNonce: "nonce-rejected-version", ErrorDetail: &status.Status{Message: "rejected listener"},
			}), publicationErr)
			if !acknowledged {
				require.Empty(t, finalized)
				require.NoError(t, cb.OnStreamRequest(2, ack))
			}
			require.ElementsMatch(t, []Generation{1, 2}, finalized,
				"both already-ACKed and in-flight responses must release retained rollback state")
		})
	}
}

func TestFailedNACKRollbackRetainsUncoveredMemberAfterConcurrentACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
	node := &core.Node{Id: "node-1"}
	respond := func(streamID int64, generation Generation, name, nonce string) *discovery.DiscoveryRequest {
		version := fmt.Sprintf("version-%d", generation)
		snapshot, err := cache.NewSnapshot(version, map[string][]cache_types.Resource{
			typeurl.Endpoint.URL(): {&endpoint.ClusterLoadAssignment{ClusterName: "a"}, &endpoint.ClusterLoadAssignment{ClusterName: "b"}},
		})
		require.NoError(t, err)
		require.NoError(t, snapshotCache.SetSnapshot(t.Context(), node.GetId(), snapshot))
		cb.SetPublishedSnapshot(node.GetId(), snapshot)
		request := &discovery.DiscoveryRequest{Node: node, TypeUrl: typeurl.Endpoint.URL(), ResourceNames: []string{name}}
		response, err := snapshotCache.Fetch(t.Context(), request)
		require.NoError(t, err)
		response = WithResponseCoverage(response, generation, snapshot)
		out, err := response.GetDiscoveryResponse()
		require.NoError(t, err)
		out.Nonce = nonce
		cb.OnStreamResponse(response.GetContext(), streamID, request, out)
		return &discovery.DiscoveryRequest{
			Node: node, TypeUrl: typeurl.Endpoint.URL(), ResourceNames: []string{name}, VersionInfo: version, ResponseNonce: nonce,
		}
	}
	publicationErr := errors.New("rollback publication failed")
	var finalized int
	scope := SingleResourceScope("a", Generation(1).Revision())
	scope.Insert("b", Generation(1).Revision())
	cb.AddTypeGenerationWithRollback(1, typeurl.Endpoint, node.GetId(), finalizingTestRollback{
		RevertFunc: func() error {
			// While the inverse is temporarily out of the pending set, another
			// stream can ACK A. That newer generation does not also ACK B.
			require.NoError(t, cb.OnStreamRequest(2, respond(2, 3, "a", "accept-a")))
			return publicationErr
		},
		finalize: func() { finalized++ },
	}, &scope)
	nack := respond(1, 2, "b", "reject-b")
	nack.VersionInfo = ""
	nack.ErrorDetail = &status.Status{Message: "rejected b"}
	require.ErrorIs(t, cb.OnStreamRequest(1, nack), publicationErr)
	require.Zero(t, finalized, "A's newer partial ACK must not discard B's failed recovery")
	// Recovery remembers A's concurrent ACK, but remains actionable for B.
	// A later ACK for B completes the transaction without requesting A again.
	require.NoError(t, cb.OnStreamRequest(2, respond(2, 3, "b", "accept-b")))
	require.Equal(t, 1, finalized)
}

func TestNACKRevertsUntrackedGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 1, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-1")
			return nil
		})

	// Generation 2 has no completion of its own, but it can supersede gen 1 in
	// the snapshot response and must therefore participate in rollback.
	registerTypeGenerationRollback(t, cb, 2, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-2")
			return nil
		})

	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL.URL(),
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-2", "version-1"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestStaleNACKDoesNotAffectNewerResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg1, comp1, pending1 := cb.newTestCompletion(t, listenerTypeURL, 1)
	wg2, comp2, pending2 := cb.newTestCompletion(t, listenerTypeURL, 2)

	registerTypeGenerationCompletion(t, cb, comp1, pending1, "version-1")
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-1"})

	registerTypeGenerationCompletion(t, cb, comp2, pending2, "version-2")
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 2), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-2", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-2"})

	// go-control-plane invokes callbacks before its stale-nonce check. Ignore
	// this request rather than applying it to the newer pending generation.
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-1",
		ErrorDetail:   &status.Status{Message: "stale rejection"},
	}))
	require.Equal(t, 2, cb.PendingCompletionCount())
	requireCompletionPending(t, comp1)
	requireCompletionPending(t, comp2)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-2",
		ResponseNonce: "nonce-2",
	}))
	require.NoError(t, wg1.Wait())
	require.NoError(t, wg2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestFirstResponseNACKWithEmptyAcceptedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-1")

	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-1"})
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		ResponseNonce: "nonce-1",
		ErrorDetail:   &status.Status{Message: "rejected first response"},
	}))

	require.ErrorContains(t, wg.Wait(), "rejected first response")
	require.Zero(t, cb.PendingCompletionCount())
}

func TestWaitCancellationRetainsResponseGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	ctx, cancel := context.WithCancel(t.Context())
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1, ResourceScope{})
	comp := wg.AddCompletionWithCallback(owner, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(
		comp, owner, "version-1", true,
	)
	require.NoError(t, err)
	require.True(t, registered)
	reverted := false
	finalized := false
	cb.AddTypeGenerationWithRollback(
		2, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }}, &ResourceScope{},
	)
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")

	cancel()
	require.ErrorIs(t, wg.Wait(), context.Canceled)
	require.Zero(t, cb.PendingCompletionCount())
	require.Len(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations, 1,
		"caller cancellation must not discard response rollback state")
	require.False(t, finalized)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL.URL(),
		VersionInfo: "version-1",
		ErrorDetail: &status.Status{Message: "rejected after caller timeout"},
	}))
	require.True(t, reverted)
	require.False(t, finalized)
	require.Nil(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations)
}

func TestWaitCancellationRetainsResponseGenerationUntilACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	ctx, cancel := context.WithCancel(t.Context())
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1, ResourceScope{})
	comp := wg.AddCompletionWithCallback(owner, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, owner, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)

	reverted := false
	finalized := false
	cb.AddTypeGenerationWithRollback(
		1, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }}, &ResourceScope{},
	)
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")

	cancel()
	require.ErrorIs(t, wg.Wait(), context.Canceled)
	require.Len(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations, 1)
	require.False(t, finalized)

	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
	require.False(t, reverted)
	require.True(t, finalized)
	require.Nil(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations)
}

func TestDetachedPolicyWaitCompletesWithoutDiscardingNACKRollback(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1)
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-1")

	otherWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(otherWG.Cancel)
	otherPending := cb.NewTypeGenerationCompletionOwner("node-2", typeurl.NetworkPolicy, 2, ResourceScope{})
	otherComp := otherWG.AddCompletionWithCallback(otherPending, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(otherComp, otherPending, "version-2", true)
	require.NoError(t, err)
	require.True(t, registered)

	reverted := false
	finalized := false
	cb.AddTypeGenerationWithRollback(1, typeurl.NetworkPolicy, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }}, &ResourceScope{})
	sendTypeGenerationResponse(cb, typeurl.NetworkPolicy, 1, "version-1")

	detached := cb.TakePendingWaiters("node-1", typeurl.NetworkPolicy)
	require.Equal(t, 1, cb.PendingCompletionCount(), "another node's wait must remain registered")
	require.Len(t, cb.typeURLState("node-1", typeurl.NetworkPolicy).pendingGenerations, 1,
		"detaching a caller wait must not discard response-owned rollback")
	detached.Complete(nil)
	require.NoError(t, wg.Wait())
	require.False(t, finalized)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       typeurl.NetworkPolicy.URL(),
		ResponseNonce: "nonce-version-1",
		ErrorDetail:   &status.Status{Message: "rejected after listener removal"},
	}))
	require.True(t, reverted)
	require.False(t, finalized)
	require.Nil(t, cb.typeURLState("node-1", typeurl.NetworkPolicy).pendingGenerations)
	cb.TakePendingWaiters("node-2", typeurl.NetworkPolicy).Complete(nil)
	require.NoError(t, otherWG.Wait())
}

func TestDetachedPolicyWaitDoesNotCompleteLaterWaitForSameGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	firstWG, first, firstPending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1)
	registerTypeGenerationCompletion(t, cb, first, firstPending, "version-1")
	detached := cb.TakePendingWaiters("node-1", typeurl.NetworkPolicy)

	// An unchanged policy can register a new wait for the same resource
	// generation after a listener has been re-added. A generation cutoff would
	// incorrectly include it in the earlier listener-removal completion.
	secondWG, second, secondPending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1)
	registerTypeGenerationCompletion(t, cb, second, secondPending, "version-1")
	detached.Complete(nil)
	require.NoError(t, firstWG.Wait())
	requireCompletionPending(t, second)
	require.Equal(t, 1, cb.PendingCompletionCount())

	cb.TakePendingWaiters("node-1", typeurl.NetworkPolicy).Complete(nil)
	require.NoError(t, secondWG.Wait())
}

func TestUntrackedGenerationRetainedUntilNACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := false
	finalized := false

	// Match an immediately available first CreateWatch response: the response
	// callback can run synchronously during SetSnapshot, before the cache
	// transfers its coalesced rollback state to CompletionCallbacks.
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL()})
	cb.AddTypeGenerationWithRollback(
		1, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }}, &ResourceScope{},
	)
	complete, err := cb.FinalizeTypeGeneration("node-1", listenerTypeURL, 1, "version-1", true)
	require.NoError(t, err)
	require.False(t, complete)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL.URL(),
		ErrorDetail: &status.Status{Message: "rejected untracked first response"},
	}))
	require.True(t, reverted)
	require.False(t, finalized)
	require.Nil(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations)
}

func TestStreamCloseClearsAcceptedGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-1"})
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-1",
		ResponseNonce: "nonce-1",
	}))
	cb.OnStreamClosed(1, &core.Node{Id: "node-1"})

	_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 2)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", false)
	require.NoError(t, err)
	require.True(t, registered, "a replacement Envoy must ACK its own response")
}

func TestFreshSubscriptionClearsAcceptedGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
	require.NoError(t, cb.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node:    &core.Node{Id: "node-1"},
		TypeUrl: listenerTypeURL.URL(),
	}))

	_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 2)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", false)
	require.NoError(t, err)
	require.True(t, registered)
}

func TestNACKRollbackStopsAtLastACKedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	_, ackedComp, ackedPending := cb.newTestCompletion(t, listenerTypeURL, 1)
	registered, err := cb.AddPreparedTypeGenerationCompletion(ackedComp, ackedPending, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 1, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-1")
			return nil
		})
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")

	for i, version := range []string{"version-2", "version-3"} {
		_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, Generation(i+2))
		registered, err = cb.AddPreparedTypeGenerationCompletion(comp, pending, version, true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, Generation(i+2), listenerTypeURL,
			func() error {
				reverted = append(reverted, version)
				return nil
			})
	}

	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-3")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-1",
		ResponseNonce: "nonce-version-3",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-3", "version-2"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKRollsBackCompletionRegisteredWithoutVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1)
	reverted := false

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 1, listenerTypeURL,
		func() error {
			reverted = true
			return nil
		})

	// The response callback runs before go-control-plane sends the response. It
	// attaches the completion to the response generation before Envoy can NACK it.
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-version-1",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))

	require.True(t, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKDoesNotRollbackNewerUpdate(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	for i, version := range []string{"version-1", "version-2"} {
		_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, Generation(i+1))
		registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, version, true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, Generation(i+1), listenerTypeURL,
			func() error {
				reverted = append(reverted, version)
				return nil
			})
	}

	// version-2 is now in flight. Register version-3 after the response was sent
	// but before Envoy NACKs it; version-3 was not part of that response.
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	wg3, comp3, pending3 := cb.newTestCompletion(t, listenerTypeURL, 3)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp3, pending3, "version-3", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 3, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-3")
			return nil
		})

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-version-2",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-2", "version-1"}, reverted)
	require.Equal(t, 1, cb.PendingCompletionCount())
	requireCompletionPending(t, comp3)

	// The newer update remains pending and completes normally when
	// its own response is sent and ACKed.
	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-3")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-3")
	require.NoError(t, wg3.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKContinuesRollbackAfterSupersededGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	var reverted []string

	_, comp1, pending1 := cb.newTestCompletion(t, listenerTypeURL, 1)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp1, pending1, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 1, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-1")
			return nil
		})

	_, comp2, pending2 := cb.newTestCompletion(t, listenerTypeURL, 2)
	registered, err = cb.AddPreparedTypeGenerationCompletion(comp2, pending2, "version-2", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 2, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-2-superseded")
			return nil
		})

	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL.URL(),
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	// A superseded newer generation must not stop rollback of independent
	// resources owned by an older generation in the same response.
	require.Equal(t, []string{"version-2-superseded", "version-1"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestOlderResponseDoesNotClaimNewerCompletion(t *testing.T) {
	for _, tt := range completionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wg1, comp1, pending1 := cb.newTestCompletion(t, tt.typeURL, 1)
			wg2, comp2, pending2 := cb.newTestCompletion(t, tt.typeURL, 2)

			registerTypeGenerationCompletion(t, cb, comp1, pending1, "version-1")
			registerTypeGenerationCompletion(t, cb, comp2, pending2, "version-2")

			// An ACK for a response created before version-2 must not complete the
			// version-2 update, even though the response callback runs afterwards.
			sendTypeGenerationResponse(cb, tt.typeURL, 1, "version-1")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-1")
			require.Equal(t, 1, cb.PendingCompletionCount())
			require.NoError(t, wg1.Wait())
			requireCompletionPending(t, comp2)

			sendTypeGenerationResponse(cb, tt.typeURL, 2, "version-2")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-2")
			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wg2.Wait())
		})
	}
}

func TestResponseUsesLastMatchingVersion(t *testing.T) {
	for _, tt := range completionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wgA1, compA1, pendingA1 := cb.newTestCompletion(t, tt.typeURL, 1)
			wgB, compB, pendingB := cb.newTestCompletion(t, tt.typeURL, 2)
			wgA2, compA2, pendingA2 := cb.newTestCompletion(t, tt.typeURL, 3)

			registerTypeGenerationCompletion(t, cb, compA1, pendingA1, "version-a")
			registerTypeGenerationCompletion(t, cb, compB, pendingB, "version-b")
			registerTypeGenerationCompletion(t, cb, compA2, pendingA2, "version-a")

			// For A -> B -> A, generation 3 identifies the last A without finding
			// the last matching occurrence in a version-order slice.
			sendTypeGenerationResponse(cb, tt.typeURL, 3, "version-a")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-a")

			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wgA1.Wait())
			require.NoError(t, wgB.Wait())
			require.NoError(t, wgA2.Wait())
		})
	}
}

func TestResponseGenerationDisambiguatesRepeatedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1, pendingA1 := cb.newTestCompletion(t, listenerTypeURL, 1)
	_, compB, pendingB := cb.newTestCompletion(t, listenerTypeURL, 2)
	_, compA2, pendingA2 := cb.newTestCompletion(t, listenerTypeURL, 3)

	registerTypeGenerationCompletion(t, cb, compA1, pendingA1, "version-a")
	registerTypeGenerationCompletion(t, cb, compB, pendingB, "version-b")
	registerTypeGenerationCompletion(t, cb, compA2, pendingA2, "version-a")

	// Although generation 3 has the same content version, this response was
	// constructed from generation 1 and must not claim the later updates.
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	require.Equal(t, 2, cb.PendingCompletionCount())
	requireCompletionPending(t, compB)
	requireCompletionPending(t, compA2)
}

func TestImmediateWatchResponseUsesCapturedGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1, pendingA1 := cb.newTestCompletion(t, listenerTypeURL, 1)
	wgB, compB, pendingB := cb.newTestCompletion(t, listenerTypeURL, 2)
	wgA2, compA2, pendingA2 := cb.newTestCompletion(t, listenerTypeURL, 3)

	registerTypeGenerationCompletion(t, cb, compA1, pendingA1, "version-a")
	response := WithResponseGeneration(&cache.RawResponse{
		Request: &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		Version: "version-a", Ctx: context.Background(),
	}, 1)
	registerTypeGenerationCompletion(t, cb, compB, pendingB, "version-b")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", &listener.Listener{Name: "listener"}))
	// Register another same-TypeURL wait before publication supplies its version.
	// The delayed response must not borrow this newer generation.
	registerTypeGenerationCompletion(t, cb, compA2, pendingA2, "")

	cb.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{VersionInfo: "version-a", TypeUrl: listenerTypeURL.URL()})
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	requireCompletionPending(t, compB)
	requireCompletionPending(t, compA2)
	require.Equal(t, 2, cb.PendingCompletionCount())
	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-c")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-c")
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestResponseWithoutGenerationDoesNotClaimWaiters(t *testing.T) {
	cb := newTestCompletionCallbacks()
	_, first, firstPending := cb.newTestCompletion(t, listenerTypeURL, 1)
	_, unversioned, unversionedPending := cb.newTestCompletion(t, listenerTypeURL, 3)
	registerTypeGenerationCompletion(t, cb, first, firstPending, "version-a")
	registerTypeGenerationCompletion(t, cb, unversioned, unversionedPending, "")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-a", &listener.Listener{Name: "listener"}))
	// Neither a matching current content hash nor a versionless waiter proves
	// which snapshot produced a response whose generation was not captured.
	cb.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-a", TypeUrl: listenerTypeURL.URL()})
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	requireCompletionPending(t, first)
	requireCompletionPending(t, unversioned)
	require.Equal(t, 2, cb.PendingCompletionCount())
}

func TestWithResponseGenerationPreservesPublicationContext(t *testing.T) {
	for _, tt := range []struct {
		name       string
		ctx        context.Context
		generation Generation
	}{
		{"immediate", context.Background(), 2},
		{"published", WithSnapshotGeneration(context.Background(), 1), 1},
		{"initial-empty", WithSnapshotGeneration(context.Background(), 0), 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			_, first, firstPending := cb.newTestCompletion(t, listenerTypeURL, 1)
			_, second, secondPending := cb.newTestCompletion(t, listenerTypeURL, 2)
			registerTypeGenerationCompletion(t, cb, first, firstPending, "version-a")
			registerTypeGenerationCompletion(t, cb, second, secondPending, "version-a")
			response := WithResponseGeneration(&cache.RawResponse{
				Request: &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
				Version: "version-a", Ctx: tt.ctx,
			}, 2)
			cb.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
				&discovery.DiscoveryResponse{VersionInfo: response.GetResponseVersion(), TypeUrl: listenerTypeURL.URL()})
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
			require.Equal(t, 2-int(tt.generation), cb.PendingCompletionCount())
		})
	}
}

func TestPendingResponseAttachesInterveningGenerationsOnABA(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1, pendingA1 := cb.newTestCompletion(t, listenerTypeURL, 1)
	wgB, compB, pendingB := cb.newTestCompletion(t, listenerTypeURL, 2)
	wgA2, compA2, pendingA2 := cb.newTestCompletion(t, listenerTypeURL, 3)

	registerTypeGenerationCompletion(t, cb, compA1, pendingA1, "version-a")
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	registerTypeGenerationCompletion(t, cb, compB, pendingB, "version-b")
	registerTypeGenerationCompletion(t, cb, compA2, pendingA2, "version-a")

	// The in-flight A already contains the final desired type state. Its ACK
	// therefore also resolves B, which was coalesced without a response.
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}
