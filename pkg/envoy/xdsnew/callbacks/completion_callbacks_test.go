// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"
	"runtime"
	"testing"
	"time"
	"weak"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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
	return NewCompletionCallbacks(slog.New(slog.DiscardHandler), nil)
}

type streamLifecycleEvent struct {
	streamID int64
	nodeID   string
	mode     StreamMode
}

type testStreamLifecycleHandler struct {
	started []streamLifecycleEvent
	closed  []streamLifecycleEvent
}

func (handler *testStreamLifecycleHandler) StreamStarted(streamID int64, nodeID string, mode StreamMode) {
	handler.started = append(handler.started, streamLifecycleEvent{streamID: streamID, nodeID: nodeID, mode: mode})
}

func (handler *testStreamLifecycleHandler) StreamClosed(streamID int64, nodeID string, mode StreamMode) {
	handler.closed = append(handler.closed, streamLifecycleEvent{streamID: streamID, nodeID: nodeID, mode: mode})
}

func newTestCompletion(t *testing.T) (*completion.WaitGroup, *completion.Completion) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	return wg, wg.AddCompletionWithCallback(nil, nil)
}

func registerTypeGenerationRollback(t *testing.T, cb *CompletionCallbacks, generation uint64, typeURL typeurl.Index, rollback revert.RevertFunc) {
	t.Helper()
	registered := cb.AddTypeGenerationWithRollback(generation, typeURL, "node-1", rollback)
	require.True(t, registered)
}

func registerTypeGenerationCompletion(t *testing.T, cb *CompletionCallbacks, comp *completion.Completion, typeURL typeurl.Index, generation uint64, version string) {
	t.Helper()
	registered, err := cb.addTypeGenerationCompletion(comp, nil, generation, version, typeURL, "node-1", true)
	require.NoError(t, err)
	require.True(t, registered)
}

func sendTypeGenerationResponse(cb *CompletionCallbacks, typeURL typeurl.Index, generation uint64, version string) {
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
		cb.SetPublishedSnapshot("node-1", 1, snapshot)
		sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
		ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
		cb.SetPublishedSnapshot("node-1", 2, newListenerSnapshot(t, "version-1", resource))
		return weak.Make(snapshot), weak.Make(secret)
	}()

	runtime.GC()
	require.Nil(t, oldSnapshot.Value(), "a type ACK must not retain the whole snapshot")
	require.Nil(t, oldSecret.Value(), "a Listener ACK must not retain unrelated Secrets")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1",
		&listener.Listener{Name: "listener-1"}, true))
	runtime.KeepAlive(cb)
}

func TestAcceptedResourcesDistinguishEmptyFromUnknown(t *testing.T) {
	for name, resources := range map[string]map[string]cache_types.ResourceWithTTL{
		"nil-map":   nil,
		"empty-map": {},
	} {
		t.Run(name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false))
			snapshot := newListenerSnapshot(t, "version-1")
			snapshot.Resources[cache_types.Listener].Items = resources
			cb.SetPublishedSnapshot("node-1", 1, snapshot)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false),
				"publishing an empty group does not make its absence accepted")
			sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1",
				&listener.Listener{Name: "listener-1"}, true))
			require.False(t, cb.ResourceAccepted("node-1", typeurl.Secret, "secret-1", nil, false),
				"an ACK for one empty type does not accept another type")
		})
	}
}

func TestAcceptedResourcesInvalidateUnmatchedACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	a := &listener.Listener{Name: "listener-1", StatPrefix: "a"}
	b := &listener.Listener{Name: "listener-1", StatPrefix: "b"}
	c := &listener.Listener{Name: "listener-1", StatPrefix: "c"}
	cb.SetPublishedSnapshot("node-1", 1, newListenerSnapshot(t, "version-a", a))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true))

	wg, comp := newTestCompletion(t)
	registerTypeGenerationCompletion(t, cb, comp, listenerTypeURL, 2, "version-b")
	cb.SetPublishedSnapshot("node-1", 2, newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-b")
	// A newer publication can arrive while the previous response is in flight.
	// ACKing B makes A obsolete, but must not promote the unsent C either. With
	// no matching published group, resource-level acceptance must be unknown.
	cb.SetPublishedSnapshot("node-1", 3, newListenerSnapshot(t, "version-c", c))
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-b")
	require.NoError(t, wg.Wait(), "B's ACK still completes B's waiter normally")
	for _, resource := range []*listener.Listener{a, b, c} {
		require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true),
			"must not assume acceptance for %s", resource.StatPrefix)
	}
	require.False(t, cb.ChangedResourceAccepted("node-1", listenerTypeURL, a.Name, c, true, a, true),
		"returning the desired resource to A must not reuse A's obsolete acceptance")

	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-c")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-c")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, c.Name, c, true))
	require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true))
}

func TestAcceptedResourcesACKAfterUnrelatedPublication(t *testing.T) {
	cb := newTestCompletionCallbacks()
	resource := &listener.Listener{Name: "listener-1"}
	cb.SetPublishedSnapshot("node-1", 1, newListenerSnapshot(t, "version-1", resource))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	snapshot := newListenerSnapshot(t, "version-1", resource)
	snapshot.Resources[cache_types.Secret] = cache.NewResources("version-2", []cache_types.Resource{
		&tls.Secret{Name: "secret-1"},
	})
	cb.SetPublishedSnapshot("node-1", 2, snapshot)
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true),
		"another type's newer publication does not invalidate the ACKed Listener group")
}

func TestAcceptedResourcesPreserveLastACKOnNACK(t *testing.T) {
	cb := newTestCompletionCallbacks()
	a := &listener.Listener{Name: "listener-1", StatPrefix: "a"}
	b := &listener.Listener{Name: "listener-1", StatPrefix: "b"}
	cb.SetPublishedSnapshot("node-1", 1, newListenerSnapshot(t, "version-a", a))
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	cb.SetPublishedSnapshot("node-1", 2, newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-b")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-a",
		ResponseNonce: "nonce-version-b",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true))
	require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, b.Name, b, true))
}

func TestAcceptedResourcesCleared(t *testing.T) {
	for _, tt := range []struct {
		name  string
		clear func(*testing.T, *CompletionCallbacks)
	}{
		{name: "snapshot-cleared", clear: func(_ *testing.T, cb *CompletionCallbacks) {
			cb.SetPublishedSnapshot("node-1", 0, nil)
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
			cb.SetPublishedSnapshot("node-1", 1, newListenerSnapshot(t, "version-1", resource))
			sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true))
			tt.clear(t, cb)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, nil, false))
		})
	}
}

func TestDiscardUnsentTypeGenerationOnlyBeforeResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	finalized := 0
	rollback := finalizingTestRollback{finalize: func() { finalized++ }}
	registered := cb.AddTypeGenerationWithRollback(1, typeurl.Endpoint, "node-1", rollback)
	require.True(t, registered)
	require.True(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 1))
	require.Nil(t, cb.typeURLState("node-1", typeurl.Endpoint).pendingGenerations)
	require.Zero(t, finalized, "the cache owns finalization after discarding the generation")

	registered = cb.AddTypeGenerationWithRollback(2, typeurl.Endpoint, "node-1", rollback)
	require.True(t, registered)
	sendTypeGenerationResponse(cb, typeurl.Endpoint, 2, "version-2")
	require.False(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 2),
		"a response must retain its rollback until ACK or NACK")
	ackTypeVersionResponse(t, cb, typeurl.Endpoint, "version-2")
	require.Equal(t, 1, finalized)
}

func TestCoalescedPendingGenerationUsesNewKey(t *testing.T) {
	cb := newTestCompletionCallbacks()
	var reverted []uint64
	for _, generation := range []uint64{1, 3, 5} {
		registerTypeGenerationRollback(t, cb, generation, listenerTypeURL, func() error {
			reverted = append(reverted, generation)
			return nil
		})
	}
	state := cb.typeURLState("node-1", listenerTypeURL)
	pending := state.pendingGenerations[1]
	require.True(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 1, 4))
	require.NotContains(t, state.pendingGenerations, uint64(1))
	require.Same(t, pending, state.pendingGenerations[4], "coalescing must reuse the pending object")
	require.False(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 4, 5),
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
	require.Equal(t, uint64(4), state.pendingGenerations[3].responseGeneration)
	require.Equal(t, uint64(4), pending.responseGeneration)
	require.Zero(t, state.pendingGenerations[5].responseGeneration)
	require.False(t, cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 4, 6),
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
	require.Equal(t, []uint64{1, 3}, reverted)
	require.Len(t, state.pendingGenerations, 1)
	require.Contains(t, state.pendingGenerations, uint64(5))

	sendTypeGenerationResponse(cb, listenerTypeURL, 5, "version-5")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-5")
	require.Nil(t, state.pendingGenerations)
	require.Equal(t, []uint64{1, 3}, reverted)
}

func TestAddTypeGenerationCompletionCompletesAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.addTypeGenerationCompletion(comp, nil, 1, "version-1", typeurl.NetworkPolicy, "node-1", true)
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
	_, comp := newTestCompletion(t)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.addTypeGenerationCompletion(comp, nil, 2, "version-2", typeurl.NetworkPolicy, "node-1", true)
	require.NoError(t, err)
	require.True(t, registered)

	require.Equal(t, 1, cb.PendingCompletionCount())
}

func TestOnStreamResponseCompletesPendingCompletionForAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	registered, err := cb.addTypeGenerationCompletion(comp, nil, 1, "", typeurl.NetworkPolicy, "node-1", true)
	require.NoError(t, err)
	require.True(t, registered)
	require.Equal(t, 1, cb.PendingCompletionCount())

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: NetworkPolicyTypeURL},
	)

	require.Zero(t, cb.PendingCompletionCount())
	require.NoError(t, wg.Wait())
}

func TestCompletionCallbacksUseStreamNodeIDWhenACKOmitsNode(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "node-1"},
	}))

	registered, err := cb.addTypeGenerationCompletion(comp, nil, 1, "version-1", listenerTypeURL, "node-1", true)
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
			wg1, comp1 := newTestCompletion(t)
			wg2, comp2 := newTestCompletion(t)

			registerTypeGenerationCompletion(t, cb, comp1, tt.typeURL, 1, "version-1")
			registerTypeGenerationCompletion(t, cb, comp2, tt.typeURL, 2, "version-2")

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
		_, comp := newTestCompletion(t)
		registered, err := cb.addTypeGenerationCompletion(
			comp, nil, uint64(i+1), version, listenerTypeURL, "node-1", true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, uint64(i+1), listenerTypeURL,
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

func TestNACKRevertsUntrackedGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	_, comp := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		comp, nil, 1, "version-1", listenerTypeURL, "node-1", true)
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
	wg1, comp1 := newTestCompletion(t)
	wg2, comp2 := newTestCompletion(t)

	registerTypeGenerationCompletion(t, cb, comp1, listenerTypeURL, 1, "version-1")
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-1"})

	registerTypeGenerationCompletion(t, cb, comp2, listenerTypeURL, 2, "version-2")
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
	wg, comp := newTestCompletion(t)
	registerTypeGenerationCompletion(t, cb, comp, listenerTypeURL, 1, "version-1")

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
	owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1)
	comp := wg.AddCompletionWithCallback(owner, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(
		comp, owner, "version-1", true,
	)
	require.NoError(t, err)
	require.True(t, registered)
	reverted := false
	finalized := false
	registered = cb.AddTypeGenerationWithRollback(
		2, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }},
	)
	require.True(t, registered)
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
	owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1)
	comp := wg.AddCompletionWithCallback(owner, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, owner, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)

	reverted := false
	finalized := false
	registered = cb.AddTypeGenerationWithRollback(
		1, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }},
	)
	require.True(t, registered)
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
	wg, comp := newTestCompletion(t)
	registerTypeGenerationCompletion(t, cb, comp, typeurl.NetworkPolicy, 1, "version-1")

	otherWG, otherComp := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(otherComp, nil, 2, "version-2", typeurl.NetworkPolicy, "node-2", true)
	require.NoError(t, err)
	require.True(t, registered)

	reverted := false
	finalized := false
	registered = cb.AddTypeGenerationWithRollback(1, typeurl.NetworkPolicy, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }})
	require.True(t, registered)
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
	firstWG, first := newTestCompletion(t)
	registerTypeGenerationCompletion(t, cb, first, typeurl.NetworkPolicy, 1, "version-1")
	detached := cb.TakePendingWaiters("node-1", typeurl.NetworkPolicy)

	// An unchanged policy can register a new wait for the same resource
	// generation after a listener has been re-added. A generation cutoff would
	// incorrectly include it in the earlier listener-removal completion.
	secondWG, second := newTestCompletion(t)
	registerTypeGenerationCompletion(t, cb, second, typeurl.NetworkPolicy, 1, "version-1")
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
	registered := cb.AddTypeGenerationWithRollback(
		1, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }},
	)
	require.True(t, registered)
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

	_, comp := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		comp, nil, 2, "version-1", listenerTypeURL, "node-1", false)
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

	_, comp := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		comp, nil, 2, "version-1", listenerTypeURL, "node-1", false)
	require.NoError(t, err)
	require.True(t, registered)
}

func TestNACKRollbackStopsAtLastACKedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	_, ackedComp := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		ackedComp, nil, 1, "version-1", listenerTypeURL, "node-1", true)
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
		_, comp := newTestCompletion(t)
		registered, err = cb.addTypeGenerationCompletion(
			comp, nil, uint64(i+2), version, listenerTypeURL, "node-1", true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, uint64(i+2), listenerTypeURL,
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
	_, comp := newTestCompletion(t)
	reverted := false

	registered, err := cb.addTypeGenerationCompletion(
		comp, nil, 1, "", listenerTypeURL, "node-1", true)
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
		_, comp := newTestCompletion(t)
		registered, err := cb.addTypeGenerationCompletion(
			comp, nil, uint64(i+1), version, listenerTypeURL, "node-1", true)
		require.NoError(t, err)
		require.True(t, registered)
		registerTypeGenerationRollback(t, cb, uint64(i+1), listenerTypeURL,
			func() error {
				reverted = append(reverted, version)
				return nil
			})
	}

	// version-2 is now in flight. Register version-3 after the response was sent
	// but before Envoy NACKs it; version-3 was not part of that response.
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	wg3, comp3 := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		comp3, nil, 3, "version-3", listenerTypeURL, "node-1", true)
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

	_, comp1 := newTestCompletion(t)
	registered, err := cb.addTypeGenerationCompletion(
		comp1, nil, 1, "version-1", listenerTypeURL, "node-1", true)
	require.NoError(t, err)
	require.True(t, registered)
	registerTypeGenerationRollback(t, cb, 1, listenerTypeURL,
		func() error {
			reverted = append(reverted, "version-1")
			return nil
		})

	_, comp2 := newTestCompletion(t)
	registered, err = cb.addTypeGenerationCompletion(
		comp2, nil, 2, "version-2", listenerTypeURL, "node-1", true)
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
			wg1, comp1 := newTestCompletion(t)
			wg2, comp2 := newTestCompletion(t)

			registerTypeGenerationCompletion(t, cb, comp1, tt.typeURL, 1, "version-1")
			registerTypeGenerationCompletion(t, cb, comp2, tt.typeURL, 2, "version-2")

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
			wgA1, compA1 := newTestCompletion(t)
			wgB, compB := newTestCompletion(t)
			wgA2, compA2 := newTestCompletion(t)

			registerTypeGenerationCompletion(t, cb, compA1, tt.typeURL, 1, "version-a")
			registerTypeGenerationCompletion(t, cb, compB, tt.typeURL, 2, "version-b")
			registerTypeGenerationCompletion(t, cb, compA2, tt.typeURL, 3, "version-a")

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
	wgA1, compA1 := newTestCompletion(t)
	_, compB := newTestCompletion(t)
	_, compA2 := newTestCompletion(t)

	registerTypeGenerationCompletion(t, cb, compA1, listenerTypeURL, 1, "version-a")
	registerTypeGenerationCompletion(t, cb, compB, listenerTypeURL, 2, "version-b")
	registerTypeGenerationCompletion(t, cb, compA2, listenerTypeURL, 3, "version-a")

	// Although generation 3 has the same content version, this response was
	// constructed from generation 1 and must not claim the later updates.
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	require.Equal(t, 2, cb.PendingCompletionCount())
	requireCompletionPending(t, compB)
	requireCompletionPending(t, compA2)
}

func TestImmediateWatchResponseInfersLatestMatchingGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1 := newTestCompletion(t)
	wgB, compB := newTestCompletion(t)
	wgA2, compA2 := newTestCompletion(t)

	registerTypeGenerationCompletion(t, cb, compA1, listenerTypeURL, 1, "version-a")
	registerTypeGenerationCompletion(t, cb, compB, listenerTypeURL, 2, "version-b")
	registerTypeGenerationCompletion(t, cb, compA2, listenerTypeURL, 3, "version-a")

	// go-control-plane uses context.Background for a CreateWatch response served
	// from the current snapshot. The latest matching pending generation is the
	// unambiguous current A in this case.
	cb.OnStreamResponse(context.Background(), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		&discovery.DiscoveryResponse{VersionInfo: "version-a", TypeUrl: listenerTypeURL.URL()})
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestPendingResponseAttachesInterveningGenerationsOnABA(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1 := newTestCompletion(t)
	wgB, compB := newTestCompletion(t)
	wgA2, compA2 := newTestCompletion(t)

	registerTypeGenerationCompletion(t, cb, compA1, listenerTypeURL, 1, "version-a")
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-a")
	registerTypeGenerationCompletion(t, cb, compB, listenerTypeURL, 2, "version-b")
	registerTypeGenerationCompletion(t, cb, compA2, listenerTypeURL, 3, "version-a")

	// The in-flight A already contains the final desired type state. Its ACK
	// therefore also resolves B, which was coalesced without a response.
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestStreamLifecycleHandler(t *testing.T) {
	handler := &testStreamLifecycleHandler{}
	cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), handler)
	chained := ChainedCallbacks{cb}

	require.NoError(t, chained.OnStreamOpen(t.Context(), 7, ""))
	sotwRequest := &discovery.DiscoveryRequest{
		Node:    &core.Node{Id: "node-1"},
		TypeUrl: typeurl.NetworkPolicy.URL(),
	}
	require.NoError(t, chained.OnStreamRequest(7, sotwRequest))
	require.Equal(t, []streamLifecycleEvent{{streamID: 7, nodeID: "node-1", mode: StreamModeSotW}}, handler.started)
	// A later request on the same stream must not increment the node's stream
	// count again.
	require.NoError(t, chained.OnStreamRequest(7, sotwRequest))
	require.Len(t, handler.started, 1)

	chained.OnStreamClosed(7, nil)
	require.Equal(t, []streamLifecycleEvent{{streamID: 7, nodeID: "node-1", mode: StreamModeSotW}}, handler.closed)
}
