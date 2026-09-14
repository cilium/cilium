// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/pkg/completion"
)

const listenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

var completionTypeURLs = []struct {
	name    string
	typeURL string
}{
	{name: "network-policy", typeURL: NetworkPolicyTypeURL},
	{name: "listener", typeURL: listenerTypeURL},
}

func newTestCompletionCallbacks() *CompletionCallbacks {
	return NewCompletionCallbacks(slog.New(slog.DiscardHandler))
}

func newTestCompletion(t *testing.T) (*completion.WaitGroup, *completion.Completion) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	return wg, wg.AddCompletionWithCallback(nil, nil)
}

func registerTypeGenerationCompletion(t *testing.T, cb *CompletionCallbacks, comp *completion.Completion, typeURL string, generation uint64, version string) {
	t.Helper()
	registered, err := cb.AddTypeGenerationCompletion(comp, generation, version, typeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)
}

func sendTypeGenerationResponse(cb *CompletionCallbacks, typeURL string, generation uint64, version string) {
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), generation), 1,
		&discovery.DiscoveryRequest{
			Node:    &core.Node{Id: "node-1"},
			TypeUrl: typeURL,
		},
		&discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     typeURL,
		},
	)
}

func ackTypeVersionResponse(t *testing.T, cb *CompletionCallbacks, typeURL, version string) {
	t.Helper()
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     typeURL,
		VersionInfo: version,
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

func TestAddTypeGenerationCompletionCompletesAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.AddTypeGenerationCompletion(comp, 1, "version-1", NetworkPolicyTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.False(t, registered)

	require.Zero(t, cb.PendingCompletionCount())
	comp.Complete(nil)
	require.NoError(t, wg.Wait())
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

	registered, err := cb.AddTypeGenerationCompletion(comp, 2, "version-2", NetworkPolicyTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)

	require.Equal(t, 1, cb.PendingCompletionCount())
}

func TestOnStreamResponseCompletesPendingCompletionForAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	registered, err := cb.AddTypeGenerationCompletion(comp, 1, "", NetworkPolicyTypeURL, "node-1", true, nil)
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

	registered, err := cb.AddTypeGenerationCompletion(comp, 1, "version-1", listenerTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)

	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL},
	)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     listenerTypeURL,
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
	expectedGenerations := make([]uint64, 0, 3)

	for i, version := range []string{"version-1", "version-2", "version-3"} {
		_, comp := newTestCompletion(t)
		registered, err := cb.AddTypeGenerationCompletion(
			comp,
			uint64(i+1),
			version,
			listenerTypeURL,
			"node-1",
			true,
			func(expected uint64) (uint64, bool) {
				reverted = append(reverted, version)
				expectedGenerations = append(expectedGenerations, expected)
				return expected + 1, true
			},
		)
		require.NoError(t, err)
		require.True(t, registered)
	}

	// The response for version-3 coalesces all three pending updates. A NACK
	// rejects the entire response, so all of its updates must be reverted in
	// reverse order to restore the snapshot that preceded the response.
	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-3")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL,
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-3", "version-2", "version-1"}, reverted)
	require.Equal(t, []uint64{3, 4, 5}, expectedGenerations)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKRevertsUntrackedGeneration(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)
	expectedGenerations := make([]uint64, 0, 2)

	_, comp := newTestCompletion(t)
	registered, err := cb.AddTypeGenerationCompletion(
		comp, 1, "version-1", listenerTypeURL, "node-1", true,
		func(expected uint64) (uint64, bool) {
			reverted = append(reverted, "version-1")
			expectedGenerations = append(expectedGenerations, expected)
			return expected + 1, true
		},
	)
	require.NoError(t, err)
	require.True(t, registered)

	// Generation 2 has no completion of its own, but it can supersede gen 1 in
	// the snapshot response and must therefore participate in rollback.
	registered, completeUnsent := cb.AddTypeGeneration(
		2, "version-2", listenerTypeURL, "node-1", true,
		func(expected uint64) (uint64, bool) {
			reverted = append(reverted, "version-2")
			expectedGenerations = append(expectedGenerations, expected)
			return expected + 1, true
		},
	)
	require.True(t, registered)
	require.False(t, completeUnsent)

	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL,
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-2", "version-1"}, reverted)
	require.Equal(t, []uint64{2, 3}, expectedGenerations)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestStaleNACKDoesNotAffectNewerResponse(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg1, comp1 := newTestCompletion(t)
	wg2, comp2 := newTestCompletion(t)

	registerTypeGenerationCompletion(t, cb, comp1, listenerTypeURL, 1, "version-1")
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL, Nonce: "nonce-1"})

	registerTypeGenerationCompletion(t, cb, comp2, listenerTypeURL, 2, "version-2")
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 2), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-2", TypeUrl: listenerTypeURL, Nonce: "nonce-2"})

	// go-control-plane invokes callbacks before its stale-nonce check. Ignore
	// this request rather than applying it to the newer pending generation.
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL,
		VersionInfo:   "version-0",
		ResponseNonce: "nonce-1",
		ErrorDetail:   &status.Status{Message: "stale rejection"},
	}))
	require.Equal(t, 2, cb.PendingCompletionCount())
	requireCompletionPending(t, comp1)
	requireCompletionPending(t, comp2)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL,
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
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL, Nonce: "nonce-1"})
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL,
		ResponseNonce: "nonce-1",
		ErrorDetail:   &status.Status{Message: "rejected first response"},
	}))

	require.ErrorContains(t, wg.Wait(), "rejected first response")
	require.Zero(t, cb.PendingCompletionCount())
}

func TestWaitCancellationRemovesCompletionGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	ctx, cancel := context.WithCancel(t.Context())
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	owner := cb.NewTypeGenerationCompletionOwner("node-1", listenerTypeURL, 1)
	comp := wg.AddCompletionWithCallback(owner, nil)
	registered, err := cb.AddPreparedTypeGenerationCompletion(
		comp, owner, "version-1", true,
		func(expected uint64) (uint64, bool) { return expected + 1, true },
	)
	require.NoError(t, err)
	require.True(t, registered)
	registered, completeUnsent := cb.AddTypeGeneration(
		2, "version-2", listenerTypeURL, "node-1", true,
		func(expected uint64) (uint64, bool) { return expected + 1, true },
	)
	require.True(t, registered)
	require.False(t, completeUnsent)

	cancel()
	require.ErrorIs(t, wg.Wait(), context.Canceled)
	require.Zero(t, cb.PendingCompletionCount())

	// With the only waiter gone, later untracked generations have no callback
	// or rollback state to preserve.
	registered, completeUnsent = cb.AddTypeGeneration(3, "version-3", listenerTypeURL, "node-1", true, nil)
	require.False(t, registered)
	require.False(t, completeUnsent)
}

func TestStreamCloseClearsAcceptedGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	cb.OnStreamResponse(WithSnapshotGeneration(context.Background(), 1), 1,
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-1", TypeUrl: listenerTypeURL, Nonce: "nonce-1"})
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          &core.Node{Id: "node-1"},
		TypeUrl:       listenerTypeURL,
		VersionInfo:   "version-1",
		ResponseNonce: "nonce-1",
	}))
	cb.OnStreamClosed(1, &core.Node{Id: "node-1"})

	_, comp := newTestCompletion(t)
	registered, err := cb.AddTypeGenerationCompletion(
		comp, 2, "version-1", listenerTypeURL, "node-1", false, nil)
	require.NoError(t, err)
	require.True(t, registered, "a replacement Envoy must ACK its own response")
}

func TestFreshSubscriptionClearsAcceptedGenerationState(t *testing.T) {
	cb := newTestCompletionCallbacks()
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
	require.NoError(t, cb.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node:    &core.Node{Id: "node-1"},
		TypeUrl: listenerTypeURL,
	}))

	_, comp := newTestCompletion(t)
	registered, err := cb.AddTypeGenerationCompletion(
		comp, 2, "version-1", listenerTypeURL, "node-1", false, nil)
	require.NoError(t, err)
	require.True(t, registered)
}

func TestNACKRollbackStopsAtLastACKedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	_, ackedComp := newTestCompletion(t)
	registered, err := cb.AddTypeGenerationCompletion(
		ackedComp,
		1,
		"version-1",
		listenerTypeURL,
		"node-1",
		true,
		func(expected uint64) (uint64, bool) {
			reverted = append(reverted, "version-1")
			return expected + 1, true
		},
	)
	require.NoError(t, err)
	require.True(t, registered)
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")

	for i, version := range []string{"version-2", "version-3"} {
		_, comp := newTestCompletion(t)
		registered, err = cb.AddTypeGenerationCompletion(
			comp,
			uint64(i+2),
			version,
			listenerTypeURL,
			"node-1",
			true,
			func(expected uint64) (uint64, bool) {
				reverted = append(reverted, version)
				return expected + 1, true
			},
		)
		require.NoError(t, err)
		require.True(t, registered)
	}

	sendTypeGenerationResponse(cb, listenerTypeURL, 3, "version-3")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL,
		VersionInfo: "version-1",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	require.Equal(t, []string{"version-3", "version-2"}, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKRollsBackCompletionRegisteredWithoutVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	_, comp := newTestCompletion(t)
	reverted := false

	registered, err := cb.AddTypeGenerationCompletion(
		comp,
		1,
		"",
		listenerTypeURL,
		"node-1",
		true,
		func(expected uint64) (uint64, bool) {
			reverted = true
			return expected + 1, true
		},
	)
	require.NoError(t, err)
	require.True(t, registered)

	// The response callback runs before go-control-plane sends the response. It
	// attaches the completion to the response generation before Envoy can NACK it.
	sendTypeGenerationResponse(cb, listenerTypeURL, 1, "version-1")
	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL,
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
	}))

	require.True(t, reverted)
	require.Zero(t, cb.PendingCompletionCount())
}

func TestNACKDoesNotRollbackNewerUpdate(t *testing.T) {
	cb := newTestCompletionCallbacks()
	reverted := make([]string, 0, 2)

	for i, version := range []string{"version-1", "version-2"} {
		_, comp := newTestCompletion(t)
		registered, err := cb.AddTypeGenerationCompletion(
			comp,
			uint64(i+1),
			version,
			listenerTypeURL,
			"node-1",
			true,
			func(expected uint64) (uint64, bool) {
				reverted = append(reverted, version)
				return expected + 1, true
			},
		)
		require.NoError(t, err)
		require.True(t, registered)
	}

	// version-2 is now in flight. Register version-3 after the response was sent
	// but before Envoy NACKs it; version-3 was not part of that response.
	sendTypeGenerationResponse(cb, listenerTypeURL, 2, "version-2")
	wg3, comp3 := newTestCompletion(t)
	registered, err := cb.AddTypeGenerationCompletion(
		comp3,
		3,
		"version-3",
		listenerTypeURL,
		"node-1",
		true,
		func(expected uint64) (uint64, bool) {
			reverted = append(reverted, "version-3")
			return expected + 1, true
		},
	)
	require.NoError(t, err)
	require.True(t, registered)

	require.NoError(t, cb.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:        &core.Node{Id: "node-1"},
		TypeUrl:     listenerTypeURL,
		VersionInfo: "version-0",
		ErrorDetail: &status.Status{Message: "rejected listener"},
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
		&discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL},
		&discovery.DiscoveryResponse{VersionInfo: "version-a", TypeUrl: listenerTypeURL})
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
