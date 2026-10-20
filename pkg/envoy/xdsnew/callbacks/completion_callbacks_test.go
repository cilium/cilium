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
	snapshot, err := cache.NewSnapshot(fmt.Sprintf("e1:g%d", generation), map[string][]cache_types.Resource{
		typeurl.Endpoint.URL(): {&endpoint.ClusterLoadAssignment{ClusterName: stream.name}},
	})
	require.NoError(t, err)
	sendSnapshotResponse(t, stream.callbacks, stream.streamID,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Endpoint.URL(), ResourceNames: []string{stream.name}},
		generation, snapshot, nonce)
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
			wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 1, owner.name)
			registerTypeGenerationCompletion(t, cb, comp, pending, "e1:g1")
			reverted := false
			registerTypeGenerationRollback(t, cb, 1, typeurl.Endpoint, func() error { reverted = true; return nil }, owner.name)
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
	wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 1, stream.name)
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
			firstWG, firstComp, firstPending := cb.newTestCompletion(t, typeurl.Endpoint, 1, first.name)
			registerTypeGenerationCompletion(t, cb, firstComp, firstPending, "e1:g1")
			firstReverted := false
			registerTypeGenerationRollback(t, cb, 1, typeurl.Endpoint, func() error { firstReverted = true; return nil }, first.name)
			first.respond(t, 1, "nonce-1")
			second.open(t)
			second.request(t, 0, "", "")
			secondWG, secondComp, secondPending := cb.newTestCompletion(t, typeurl.Endpoint, 2, second.name)
			registerTypeGenerationCompletion(t, cb, secondComp, secondPending, "e1:g2")
			secondReverted := false
			registerTypeGenerationRollback(t, cb, 2, typeurl.Endpoint, func() error { secondReverted = true; return nil }, second.name)
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
	for _, tt := range []struct {
		name        string
		olderSubset bool
		newerSubset bool
	}{
		{name: "full-then-full"},
		{name: "subset-then-full", olderSubset: true},
		{name: "full-then-subset", newerSubset: true},
		{name: "subset-then-subset", olderSubset: true, newerSubset: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			first := testEDSStream{callbacks: cb, streamID: 1, name: "cluster"}
			second := testEDSStream{callbacks: cb, streamID: 2, name: "cluster"}
			first.open(t)
			first.request(t, 0, "", "")
			second.open(t)
			second.request(t, 0, "", "")
			t.Cleanup(first.close)
			t.Cleanup(second.close)
			older := &endpoint.ClusterLoadAssignment{ClusterName: "cluster"}
			newer := &endpoint.ClusterLoadAssignment{ClusterName: "cluster", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
			other := &endpoint.ClusterLoadAssignment{ClusterName: "other"}
			olderSnapshot, err := cache.NewSnapshot("e1:g1", map[string][]cache_types.Resource{typeurl.Endpoint.URL(): {older, other}})
			require.NoError(t, err)
			newerSnapshot, err := cache.NewSnapshot("e1:g2", map[string][]cache_types.Resource{typeurl.Endpoint.URL(): {newer, other}})
			require.NoError(t, err)
			olderRequest := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Endpoint.URL()}
			newerRequest := &discovery.DiscoveryRequest{Node: olderRequest.Node, TypeUrl: olderRequest.TypeUrl}
			if tt.olderSubset {
				olderRequest.ResourceNames = []string{"cluster"}
			}
			if tt.newerSubset {
				newerRequest.ResourceNames = []string{"cluster"}
			}
			sendSnapshotResponse(t, cb, first.streamID, olderRequest, 1, olderSnapshot, "nonce-1")
			cb.SetPublishedSnapshot("node-1", newerSnapshot)
			sendSnapshotResponse(t, cb, second.streamID, newerRequest, 2, newerSnapshot, "nonce-2")
			second.request(t, 2, "nonce-2", "")
			require.True(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", newer, true, Generation(2).Revision()))
			// Both delayed delivery and its ACK must preserve the newer value
			// and revision used to recognize accepted semantic no-ops.
			sendSnapshotResponse(t, cb, first.streamID, olderRequest, 1, olderSnapshot, "delayed-nonce")
			require.True(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", newer, true, Generation(2).Revision()))
			first.request(t, 1, "delayed-nonce", "")
			require.True(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", newer, true, Generation(2).Revision()))
			require.False(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", older, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", typeurl.Endpoint, "cluster", newer, true, Generation(3).Revision()))
			require.Equal(t, !tt.olderSubset || !tt.newerSubset,
				cb.ResourceAccepted("node-1", typeurl.Endpoint, "other", other, true, Generation(1).Revision()),
				"the older full-group ACK still accepts names omitted from the newer subset")
		})
	}
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
	wg, comp, pending := cb.newTestCompletion(t, typeurl.Endpoint, 2, live.name)
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

func (cb *CompletionCallbacks) newTestCompletion(t *testing.T, typeURL typeurl.Index, generation Generation, name string) (*completion.WaitGroup, *completion.Completion, *resourceWait) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	scope := SingleResourceScope(name, generation.Revision())
	pending := cb.NewTypeGenerationCompletionOwner("node-1", typeURL, generation, scope, false)
	return wg, wg.AddCompletion(pending), pending
}

func registerTypeGenerationRollback(t *testing.T, cb *CompletionCallbacks, generation Generation, typeURL typeurl.Index, rollback revert.RevertFunc, names ...string) {
	t.Helper()
	var scope ResourceScope
	for _, name := range names {
		scope.Insert(name, generation.Revision())
	}
	cb.AddTypeGenerationWithRollback(generation, typeURL, "node-1", rollback, &scope)
}

func registerTypeGenerationCompletion(t *testing.T, cb *CompletionCallbacks, comp *completion.Completion, pending *resourceWait, version string) {
	t.Helper()
	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, version, true)
	require.NoError(t, err)
	require.True(t, registered)
}

// emptySnapshot also versions empty Cilium resource groups, which
// go-control-plane's concrete Snapshot does not recognize.
type emptySnapshot struct {
	cache.Snapshot
	version string
}

func (snapshot *emptySnapshot) GetVersion(string) string {
	return snapshot.version
}

func sendTypeGenerationResponse(t *testing.T, cb *CompletionCallbacks, typeURL typeurl.Index, generation Generation, version string, resources ...cache_types.Resource) {
	t.Helper()
	var snapshot cache.ResourceSnapshot = &emptySnapshot{version: version}
	if len(resources) != 0 {
		var err error
		snapshot, err = cache.NewSnapshot(version, map[string][]cache_types.Resource{typeURL.URL(): resources})
		require.NoError(t, err)
	}
	sendSnapshotResponse(t, cb, 1, &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: typeURL.URL()},
		generation, snapshot, "nonce-"+version)
}

// sendSnapshotResponse uses go-control-plane's resource selection and the same
// coverage capture as cache delivery, including for named subscriptions.
func sendSnapshotResponse(t *testing.T, cb *CompletionCallbacks, streamID int64, request *discovery.DiscoveryRequest, generation Generation, snapshot cache.ResourceSnapshot, nonce string) {
	t.Helper()
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
	require.NoError(t, snapshotCache.SetSnapshot(t.Context(), request.GetNode().GetId(), snapshot))
	response, err := snapshotCache.Fetch(WithSnapshotPublication(t.Context(), generation, snapshot), request)
	require.NoError(t, err)
	response = WithResponseCoverage(response, generation, snapshot)
	out, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	out.Nonce = nonce
	cb.OnStreamResponse(response.GetContext(), streamID, request, out)
}

func ackTypeVersionResponse(t *testing.T, cb *CompletionCallbacks, typeURL typeurl.Index, version string) {
	t.Helper()
	var nonce string
	if stream := cb.streams[streamKey{streamID: 1, mode: StreamModeSotW}]; stream != nil {
		nonce = stream.responses[typeURL].pendingNonce
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
	// Only its Listener group should survive in the callbacks after its ACK,
	// even without a newer publication replacing the snapshot.
	oldSnapshot, oldSecret := func() (weak.Pointer[cache.Snapshot], weak.Pointer[tls.Secret]) {
		resource := &listener.Listener{Name: "listener-1"}
		secret := &tls.Secret{Name: "old-secret"}
		snapshot, err := cache.NewSnapshot("version-1", map[string][]cache_types.Resource{
			typeurl.Listener.URL(): {resource},
			typeurl.Secret.URL():   {secret},
		})
		require.NoError(t, err)
		cb.SetPublishedSnapshot("node-1", snapshot)
		sendSnapshotResponse(t, cb, 1, &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
			1, snapshot, "nonce-version-1")
		ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
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
			sendSnapshotResponse(t, cb, 1, &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
				1, snapshot, "nonce-version-1")
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1", nil, false, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, "listener-1",
				&listener.Listener{Name: "listener-1"}, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", typeurl.Secret, "secret-1", nil, false, Revision{}),
				"an ACK for one empty type does not accept another type")
		})
	}
}

func TestAcceptedResourcesFollowACKedResponseAfterNewerPublication(t *testing.T) {
	cb := newTestCompletionCallbacks()
	a := &listener.Listener{Name: "listener-1", StatPrefix: "a"}
	b := &listener.Listener{Name: "listener-1", StatPrefix: "b"}
	c := &listener.Listener{Name: "listener-1", StatPrefix: "c"}
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-a", a))
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-a", a)
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true, Revision{}))

	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 2, b.Name)
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-b")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-b", b)
	// A newer publication can arrive while the previous response is in flight.
	// ACKing B accepts its exact delivered contents, replacing A's acceptance
	// without accepting the unsent C.
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-c", c))
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-b")
	require.NoError(t, wg.Wait(), "B's ACK still completes B's waiter normally")
	for _, resource := range []*listener.Listener{a, b, c} {
		require.Equal(t, resource == b, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}),
			"only the delivered B is accepted, checking %s", resource.StatPrefix)
	}
	require.False(t, cb.ChangedResourceAccepted("node-1", listenerTypeURL, a.Name, c, true, a, true, Revision{}),
		"returning the desired resource to A must not reuse A's obsolete acceptance")

	sendTypeGenerationResponse(t, cb, listenerTypeURL, 3, "version-c", c)
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-c")
	require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, c.Name, c, true, Revision{}))
	require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, a.Name, a, true, Revision{}))
}

func TestAcceptedResourcesACKAfterUnrelatedPublication(t *testing.T) {
	cb := newTestCompletionCallbacks()
	resource := &listener.Listener{Name: "listener-1"}
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1", resource)
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
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-a", a)
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", b))
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-b", b)
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			resource := &listener.Listener{Name: "listener-1"}
			cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1", resource)
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
			tt.clear(t, cb)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, nil, false, Revision{}))
			if tt.name != "snapshot-cleared" {
				_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, resource.Name)
				registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", false)
				require.NoError(t, err)
				require.True(t, registered, "a new consumer must ACK its own response")
				requireCompletionPending(t, comp)
			}
		})
	}
}

func TestDiscardUnsentTypeGenerationOnlyBeforeResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	finalized := 0
	rollback := finalizingTestRollback{finalize: func() { finalized++ }}
	cb.AddTypeGenerationWithRollback(1, typeurl.Endpoint, "node-1", rollback, nil)
	require.True(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 1))
	require.Nil(t, cb.typeURLState("node-1", typeurl.Endpoint).pendingGenerations)
	require.Zero(t, finalized, "the cache owns finalization after discarding the generation")

	cb.AddTypeGenerationWithRollback(2, typeurl.Endpoint, "node-1", rollback, &ResourceScope{})
	sendTypeGenerationResponse(t, cb, typeurl.Endpoint, 2, "version-2")
	require.False(t, cb.DiscardUnsentTypeGeneration("node-1", typeurl.Endpoint, 2),
		"a response must retain its rollback until ACK or NACK")
	ackTypeVersionResponse(t, cb, typeurl.Endpoint, "version-2")
	require.Equal(t, 1, finalized)
}

func TestCoalescedPendingGenerationUsesNewBoundary(t *testing.T) {
	cb := newTestCompletionCallbacks()
	var reverted []Generation
	// A subset response can own one rollback while another remains unclaimed.
	olderScope := SingleResourceScope("older", Generation(3).Revision())
	for _, tt := range []struct {
		generation Generation
		scope      *ResourceScope
	}{
		{generation: 1},
		{generation: 3, scope: &olderScope},
	} {
		cb.AddTypeGenerationWithRollback(tt.generation, listenerTypeURL, "node-1", revert.RevertFunc(func() error {
			reverted = append(reverted, tt.generation)
			return nil
		}), tt.scope)
	}
	state := cb.typeURLState("node-1", listenerTypeURL)
	cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 1, 4, nil)

	// Moving generation 1 to key 4 must keep it out of an earlier response.
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-2")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-2")
	require.Len(t, state.pendingGenerations, 2)

	cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 4, 4, &ResourceScope{})
	cb.AddTypeGenerationWithRollback(5, listenerTypeURL, "node-1", revert.RevertFunc(func() error {
		reverted = append(reverted, 5)
		return nil
	}), nil)
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 4, "version-4")
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
	cb.CoalesceUnsentTypeGeneration("node-1", listenerTypeURL, 5, 5, &ResourceScope{})

	sendTypeGenerationResponse(t, cb, listenerTypeURL, 5, "version-5")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-5")
	require.Nil(t, state.pendingGenerations)
	require.Equal(t, []Generation{1, 3}, reverted)
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
	_, comp, pending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 2, "policy")

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     typeurl.NetworkPolicyURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-2", true)
	require.NoError(t, err)
	require.True(t, registered)

	require.Equal(t, 1, cb.PendingCompletionCount())
}

func TestCompletionCallbacksUseStreamNodeIDWhenACKOmitsNode(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, "listener")

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node: &core.Node{Id: "node-1"},
	}))

	registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, "version-1", true)
	require.NoError(t, err)
	require.True(t, registered)

	response := WithResponseCoverage(&cache.RawResponse{
		Request: &discovery.DiscoveryRequest{TypeUrl: listenerTypeURL.URL()},
		Version: "version-1", Ctx: t.Context(),
	}, 1, newListenerSnapshot(t, "version-1"))
	cb.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-1"},
	)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		VersionInfo:   "version-1",
		TypeUrl:       listenerTypeURL.URL(),
		ResponseNonce: "nonce-1",
	}))
	require.NoError(t, wg.Wait())
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
				wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, generation, "listener")
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
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 3, "rejected-version")
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
			sendSnapshotResponse(t, cb, 2, request, 4, newListenerSnapshot(t, "retried-version"), "retry-nonce")
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
						sendSnapshotResponse(t, cb, 2, request, 3, newListenerSnapshot(t, "newer-version", &listener.Listener{Name: "l1"}), "newer-nonce")
						if acknowledged {
							require.NoError(t, cb.OnStreamRequest(2, ack))
						}
						return publicationErr
					},
					finalize: func() { finalized = append(finalized, generation) },
				}, &ResourceScope{})
			}
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "rejected-version")
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
	node := &core.Node{Id: "node-1"}
	respond := func(streamID int64, generation Generation, name, nonce string) *discovery.DiscoveryRequest {
		version := fmt.Sprintf("version-%d", generation)
		snapshot, err := cache.NewSnapshot(version, map[string][]cache_types.Resource{
			typeurl.Endpoint.URL(): {&endpoint.ClusterLoadAssignment{ClusterName: "a"}, &endpoint.ClusterLoadAssignment{ClusterName: "b"}},
		})
		require.NoError(t, err)
		cb.SetPublishedSnapshot(node.GetId(), snapshot)
		request := &discovery.DiscoveryRequest{Node: node, TypeUrl: typeurl.Endpoint.URL(), ResourceNames: []string{name}}
		sendSnapshotResponse(t, cb, streamID, request, generation, snapshot, nonce)
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

	_, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, "listener")
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

	sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-2")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-version-2",
		ErrorDetail:   &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-2", "version-1"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestUnmatchedNonceDoesNotAffectPendingResponses(t *testing.T) {
	for _, tt := range []struct {
		name       string
		version    string
		nonce      string
		rejection  string
		noResponse bool
	}{
		{name: "stale-ack", version: "version-2", nonce: "nonce-version-1"},
		{name: "stale-nack", version: "version-0", nonce: "nonce-version-1", rejection: "stale rejection"},
		{name: "missing-nonce-ack", version: "version-2"},
		{name: "missing-nonce-nack", version: "version-0", rejection: "nonce-less rejection"},
		{name: "missing-nonce-first-nack", rejection: "nonce-less first rejection"},
		{name: "nack-before-response", rejection: "rejection before response", noResponse: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			var waits []*completion.WaitGroup
			var completions []*completion.Completion
			reverted := false
			for generation := Generation(1); generation <= 2; generation++ {
				wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, generation, "listener")
				waits, completions = append(waits, wg), append(completions, comp)
				version := fmt.Sprintf("version-%d", generation)
				registerTypeGenerationCompletion(t, cb, comp, pending, version)
				registerTypeGenerationRollback(t, cb, generation, listenerTypeURL, func() error { reverted = true; return nil })
				if !tt.noResponse {
					sendTypeGenerationResponse(t, cb, listenerTypeURL, generation, version)
				}
			}
			var detail *status.Status
			if tt.rejection != "" {
				detail = &status.Status{Message: tt.rejection}
			}
			// go-control-plane invokes callbacks before checking the nonce. An
			// unmatched request must not complete waits or consume rollback state.
			require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL(),
				VersionInfo: tt.version, ResponseNonce: tt.nonce, ErrorDetail: detail,
			}))
			require.Equal(t, 2, cb.PendingCompletionCount())
			for _, comp := range completions {
				requireCompletionPending(t, comp)
			}
			require.False(t, reverted)

			if tt.noResponse {
				sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-2")
			}
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-2")
			for _, wg := range waits {
				require.NoError(t, wg.Wait())
			}
			require.Zero(t, cb.PendingCompletionCount())
			require.False(t, reverted)
		})
	}
}

func TestFirstResponseNACKWithEmptyAcceptedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, "listener")
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-1")

	sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		ResponseNonce: "nonce-version-1",
		ErrorDetail:   &status.Status{Message: "rejected first response"},
	}))

	require.ErrorContains(t, wg.Wait(), "version version-1: rejected first response")
	require.Zero(t, cb.PendingCompletionCount())
}

func TestDetachedPolicyWaitCompletesWithoutDiscardingNACKRollback(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp, pending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1, "policy")
	registerTypeGenerationCompletion(t, cb, comp, pending, "version-1")

	otherWG := completion.NewWaitGroup(t.Context())
	t.Cleanup(otherWG.Cancel)
	otherPending := cb.NewTypeGenerationCompletionOwner("node-2", typeurl.NetworkPolicy, 2, SingleResourceScope("policy", Generation(2).Revision()), false)
	otherComp := otherWG.AddCompletion(otherPending)
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
	sendTypeGenerationResponse(t, cb, typeurl.NetworkPolicy, 1, "version-1")

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
	firstWG, first, firstPending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1, "policy")
	registerTypeGenerationCompletion(t, cb, first, firstPending, "version-1")
	detached := cb.TakePendingWaiters("node-1", typeurl.NetworkPolicy)

	// An unchanged policy can register a new wait for the same resource
	// generation after a listener has been re-added. A generation cutoff would
	// incorrectly include it in the earlier listener-removal completion.
	secondWG, second, secondPending := cb.newTestCompletion(t, typeurl.NetworkPolicy, 1, "policy")
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

	// Rollback registered after response delivery still needs to handle that
	// response's NACK when its generation and scope match.
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1")
	cb.AddTypeGenerationWithRollback(
		1, listenerTypeURL, "node-1",
		finalizingTestRollback{RevertFunc: func() error {
			reverted = true
			return nil
		}, finalize: func() { finalized = true }}, &ResourceScope{},
	)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL.URL(),
		ResponseNonce: "nonce-version-1",
		ErrorDetail:   &status.Status{Message: "rejected untracked first response"},
	}))
	require.True(t, reverted)
	require.False(t, finalized)
	require.Nil(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations)
}

func TestImmediateWatchResponseUsesCapturedGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wgA1, compA1, pendingA1 := cb.newTestCompletion(t, listenerTypeURL, 1, "listener")
	wgB, compB, pendingB := cb.newTestCompletion(t, listenerTypeURL, 2, "listener")
	wgA2, compA2, pendingA2 := cb.newTestCompletion(t, listenerTypeURL, 3, "listener")

	registerTypeGenerationCompletion(t, cb, compA1, pendingA1, "version-a")
	response := WithResponseCoverage(&cache.RawResponse{
		Request: &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()},
		Version: "version-a", Ctx: context.Background(),
	}, 1, newListenerSnapshot(t, "version-a"))
	registerTypeGenerationCompletion(t, cb, compB, pendingB, "version-b")
	cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-b", &listener.Listener{Name: "listener"}))
	// Register another same-TypeURL wait before publication supplies its version.
	// The delayed response must not borrow this newer generation.
	registerTypeGenerationCompletion(t, cb, compA2, pendingA2, "")

	cb.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{VersionInfo: "version-a", TypeUrl: listenerTypeURL.URL(), Nonce: "nonce-a"})
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")

	require.NoError(t, wgA1.Wait())
	requireCompletionPending(t, compB)
	requireCompletionPending(t, compA2)
	require.Equal(t, 2, cb.PendingCompletionCount())
	sendTypeGenerationResponse(t, cb, listenerTypeURL, 3, "version-c")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-c")
	require.NoError(t, wgB.Wait())
	require.NoError(t, wgA2.Wait())
	require.Zero(t, cb.PendingCompletionCount())
}

func TestIncompleteResponseMetadataCannotResolveUpdates(t *testing.T) {
	for _, tt := range []struct {
		name            string
		generation      Generation
		missingSnapshot bool
		rejection       string
	}{
		{name: "ack-without-generation"},
		{name: "nack-without-generation", rejection: "rejected listener"},
		{name: "ack-without-coverage", generation: 1, missingSnapshot: true},
		{name: "nack-without-coverage", generation: 1, missingSnapshot: true, rejection: "rejected listener"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			_, first, firstPending := cb.newTestCompletion(t, listenerTypeURL, 1, "listener")
			_, unversioned, unversionedPending := cb.newTestCompletion(t, listenerTypeURL, 3, "listener")
			registerTypeGenerationCompletion(t, cb, first, firstPending, "version-a")
			registerTypeGenerationCompletion(t, cb, unversioned, unversionedPending, "")
			reverted := false
			registerTypeGenerationRollback(t, cb, 1, listenerTypeURL, func() error { reverted = true; return nil })
			resource := &listener.Listener{Name: "listener"}
			snapshot := newListenerSnapshot(t, "version-a", resource)
			cb.SetPublishedSnapshot("node-1", snapshot)
			snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
			require.NoError(t, snapshotCache.SetSnapshot(t.Context(), "node-1", snapshot))
			request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()}
			response, err := snapshotCache.Fetch(t.Context(), request)
			require.NoError(t, err)
			var sourceSnapshot cache.ResourceSnapshot = snapshot
			if tt.missingSnapshot {
				sourceSnapshot = nil
			}
			// Neither a matching published version nor a versionless waiter can
			// supply the response's missing generation or resource coverage.
			response = WithResponseCoverage(response, tt.generation, sourceSnapshot)
			out, err := response.GetDiscoveryResponse()
			require.NoError(t, err)
			out.Nonce = "nonce-a"
			cb.OnStreamResponse(response.GetContext(), 1, request, out)
			request.VersionInfo, request.ResponseNonce = "version-a", out.Nonce
			if tt.rejection != "" {
				request.ErrorDetail = &status.Status{Message: tt.rejection}
			}
			require.NoError(t, cb.OnStreamRequest(1, request))
			requireCompletionPending(t, first)
			requireCompletionPending(t, unversioned)
			require.Equal(t, 2, cb.PendingCompletionCount())
			require.False(t, reverted)
			require.False(t, cb.HasResourceAcceptance("node-1", listenerTypeURL))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
		})
	}
}

func TestWithResponseCoveragePreservesPublicationContext(t *testing.T) {
	old := &listener.Listener{Name: "old"}
	current := &listener.Listener{Name: "current"}
	oldSnapshot := newListenerSnapshot(t, "version-a", old)
	currentSnapshot := newListenerSnapshot(t, "version-a", current)
	emptySnapshot := newListenerSnapshot(t, "version-a")
	for _, tt := range []struct {
		name       string
		ctx        context.Context
		snapshot   cache.ResourceSnapshot
		generation Generation
		accepted   *listener.Listener
	}{
		{name: "immediate", ctx: t.Context(), snapshot: currentSnapshot, generation: 2, accepted: current},
		{name: "published", ctx: WithSnapshotPublication(t.Context(), 1, oldSnapshot), snapshot: oldSnapshot, generation: 1, accepted: old},
		{name: "initial-empty", ctx: WithSnapshotPublication(t.Context(), 0, emptySnapshot), snapshot: emptySnapshot},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			_, first, firstPending := cb.newTestCompletion(t, listenerTypeURL, 1, old.Name)
			_, second, secondPending := cb.newTestCompletion(t, listenerTypeURL, 2, current.Name)
			registerTypeGenerationCompletion(t, cb, first, firstPending, "version-a")
			registerTypeGenerationCompletion(t, cb, second, secondPending, "version-a")
			snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
			require.NoError(t, snapshotCache.SetSnapshot(t.Context(), "node-1", tt.snapshot))
			request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()}
			response, err := snapshotCache.Fetch(tt.ctx, request)
			require.NoError(t, err)
			response = WithResponseCoverage(response, 2, currentSnapshot)
			out, err := response.GetDiscoveryResponse()
			require.NoError(t, err)
			out.Nonce = "nonce-a"
			cb.OnStreamResponse(response.GetContext(), 1, request, out)
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-a")
			require.Equal(t, 2-int(tt.generation), cb.PendingCompletionCount())
			for _, resource := range []*listener.Listener{old, current} {
				require.Equal(t, resource == tt.accepted, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Revision{}))
			}
		})
	}
}

func TestACKBeforeWaitRegistration(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version string
	}{
		{name: "published", version: "version-1"},
		{name: "unpublished"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			resource := &listener.Listener{Name: "listener"}
			cb.SetPublishedSnapshot("node-1", newListenerSnapshot(t, "version-1", resource))
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1", resource)
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, resource.Name, resource, true, Generation(1).Revision()))
			wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, resource.Name)
			// Envoy ACKs after the cache prepares the wait but before registration.
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			versionKnown := tt.version != ""
			registered, err := cb.AddPreparedTypeGenerationCompletion(comp, pending, tt.version, !versionKnown)
			require.NoError(t, err)
			require.Equal(t, !versionKnown, registered)
			if versionKnown {
				require.Zero(t, cb.PendingCompletionCount())
				comp.Complete(nil)
			} else {
				require.Equal(t, 1, cb.PendingCompletionCount())
				sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1", resource)
				// A wait registered without a known version follows the normal
				// ACK path even when the response repeats an accepted version.
				requireCompletionPending(t, comp)
				ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			}
			require.NoError(t, wg.Wait())
			require.Zero(t, cb.PendingCompletionCount())
		})
	}
}

func TestResponseGenerationBoundsCompletion(t *testing.T) {
	for _, resourceType := range completionTypeURLs {
		for _, tc := range []struct {
			name     string
			versions []string
			response Generation
		}{
			{name: "coalesced", versions: []string{"version-1", "version-2"}, response: 2},
			{name: "older-response", versions: []string{"version-1", "version-2"}, response: 1},
			{name: "coalesced-aba", versions: []string{"version-a", "version-b", "version-a"}, response: 3},
			{name: "older-repeated-version", versions: []string{"version-a", "version-b", "version-a"}, response: 1},
		} {
			t.Run(resourceType.name+"/"+tc.name, func(t *testing.T) {
				cb := newTestCompletionCallbacks()
				var waits []*completion.WaitGroup
				var completions []*completion.Completion
				for i, version := range tc.versions {
					wg, comp, pending := cb.newTestCompletion(t, resourceType.typeURL, Generation(i+1), "resource")
					waits, completions = append(waits, wg), append(completions, comp)
					registerTypeGenerationCompletion(t, cb, comp, pending, version)
				}
				// The generation identifies which mutations this response contains,
				// even when a later generation has the same version string.
				version := tc.versions[tc.response-1]
				if tc.name == "coalesced" {
					sendTypeGenerationResponse(t, cb, resourceType.typeURL, 1, tc.versions[0])
				}
				sendTypeGenerationResponse(t, cb, resourceType.typeURL, tc.response, version)
				ackTypeVersionResponse(t, cb, resourceType.typeURL, version)
				require.Equal(t, len(waits)-int(tc.response), cb.PendingCompletionCount())
				for i, wg := range waits {
					if Generation(i+1) <= tc.response {
						require.NoError(t, wg.Wait())
					} else {
						requireCompletionPending(t, completions[i])
					}
				}
				if int(tc.response) < len(waits) {
					latest := Generation(len(waits))
					sendTypeGenerationResponse(t, cb, resourceType.typeURL, latest, tc.versions[latest-1])
					ackTypeVersionResponse(t, cb, resourceType.typeURL, tc.versions[latest-1])
					for _, wg := range waits[tc.response:] {
						require.NoError(t, wg.Wait())
					}
					require.Zero(t, cb.PendingCompletionCount())
				}
			})
		}
	}
}
func TestNACKRevertsCoveredGenerations(t *testing.T) {
	for _, tc := range []struct {
		name        string
		accepted    Generation
		response    Generation
		latest      Generation
		unversioned bool
	}{
		{name: "coalesced", response: 3, latest: 3},
		{name: "stops-at-last-ack", accepted: 1, response: 3, latest: 3},
		{name: "unversioned-completion", response: 1, latest: 1, unversioned: true},
		{name: "newer-unsent-generation", response: 2, latest: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			var reverted []Generation
			var waits []*completion.WaitGroup
			var completions []*completion.Completion
			for generation := Generation(1); generation <= tc.latest; generation++ {
				wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, generation, "listener")
				waits, completions = append(waits, wg), append(completions, comp)
				version := fmt.Sprintf("version-%d", generation)
				if tc.unversioned {
					version = ""
				}
				registerTypeGenerationCompletion(t, cb, comp, pending, version)
				registerTypeGenerationRollback(t, cb, generation, listenerTypeURL, func() error {
					reverted = append(reverted, generation)
					return nil
				})
				if generation == tc.accepted {
					sendTypeGenerationResponse(t, cb, listenerTypeURL, generation, version)
					ackTypeVersionResponse(t, cb, listenerTypeURL, version)
					require.NoError(t, wg.Wait())
				}
				if generation == tc.response {
					// Later registrations must stay outside this response.
					sendTypeGenerationResponse(t, cb, listenerTypeURL, generation, fmt.Sprintf("version-%d", generation))
				}
			}
			require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
				Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL(),
				VersionInfo: fmt.Sprintf("version-%d", tc.accepted), ResponseNonce: fmt.Sprintf("nonce-version-%d", tc.response),
				ErrorDetail: &status.Status{Message: "rejected listener"},
			}))
			var expected []Generation
			for generation := tc.response; generation > tc.accepted; generation-- {
				expected = append(expected, generation)
				require.ErrorContains(t, waits[generation-1].Wait(), "rejected listener")
			}
			require.Equal(t, expected, reverted, "rollback order follows generations, regardless of completion version")
			require.Equal(t, int(tc.latest-tc.response), cb.PendingCompletionCount())
			for generation := tc.response + 1; generation <= tc.latest; generation++ {
				requireCompletionPending(t, completions[generation-1])
			}
			if tc.latest > tc.response {
				version := fmt.Sprintf("version-%d", tc.latest)
				sendTypeGenerationResponse(t, cb, listenerTypeURL, tc.latest, version)
				ackTypeVersionResponse(t, cb, listenerTypeURL, version)
				require.NoError(t, waits[tc.latest-1].Wait())
				require.Equal(t, expected, reverted)
			}
			require.Zero(t, cb.PendingCompletionCount())
		})
	}
}
func TestWaitCancellationRetainsResponseRollback(t *testing.T) {
	for _, tc := range []struct {
		name               string
		rollbackGeneration Generation
		rejection          string
	}{
		{name: "nack-newer-generation", rollbackGeneration: 2, rejection: "rejected after caller timeout"},
		{name: "ack-same-generation", rollbackGeneration: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1, SingleResourceScope("listener", Generation(1).Revision()), false)
			comp := wg.AddCompletion(owner)
			registerTypeGenerationCompletion(t, cb, comp, owner, "version-1")
			reverted, finalized := false, false
			cb.AddTypeGenerationWithRollback(tc.rollbackGeneration, listenerTypeURL, "node-1",
				finalizingTestRollback{
					RevertFunc: func() error { reverted = true; return nil },
					finalize:   func() { finalized = true },
				}, &ResourceScope{})
			version := fmt.Sprintf("version-%d", tc.rollbackGeneration)
			sendTypeGenerationResponse(t, cb, listenerTypeURL, tc.rollbackGeneration, version)

			cancel()
			require.ErrorIs(t, wg.Wait(), context.Canceled)
			require.Zero(t, cb.PendingCompletionCount())
			require.Len(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations, 1,
				"caller cancellation must retain response rollback state")
			require.False(t, finalized)
			if tc.rejection == "" {
				ackTypeVersionResponse(t, cb, listenerTypeURL, version)
			} else {
				require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL(), VersionInfo: "version-1",
					ResponseNonce: "nonce-" + version, ErrorDetail: &status.Status{Message: tc.rejection},
				}))
			}
			require.Equal(t, tc.rejection != "", reverted)
			require.Equal(t, tc.rejection == "", finalized)
			require.Nil(t, cb.typeURLState("node-1", listenerTypeURL).pendingGenerations)
		})
	}
}
