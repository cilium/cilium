// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
)

const listenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

var orderedCompletionTypeURLs = []struct {
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

func registerTypeVersionCompletion(t *testing.T, cb *CompletionCallbacks, comp *completion.Completion, typeURL, version string) {
	t.Helper()
	registered, err := cb.AddTypeVersionCompletion(comp, version, typeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)
}

func sendTypeVersionResponse(cb *CompletionCallbacks, typeURL, version string) {
	cb.OnStreamResponse(context.Background(), 1,
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

func TestOrderedCompletionsUpdateUpToLastVersion(t *testing.T) {
	vo := newOrderedCompletions()
	compA1 := completion.NewCompletion(nil, nil, nil)
	compB := completion.NewCompletion(nil, nil, nil)
	compA2 := completion.NewCompletion(nil, nil, nil)
	compC := completion.NewCompletion(nil, nil, nil)

	vo.append("version-a", compA1)
	vo.append("version-b", compB)
	vo.append("version-a", compA2)
	vo.append("version-c", compC)

	updated := slices.Collect(vo.updateUpTo("version-a"))
	require.ElementsMatch(t, []*completion.Completion{compA1, compB, compA2}, updated)
	require.Len(t, *vo, 2)
	require.Equal(t, "version-a", (*vo)[0].version)
	require.Equal(t, 3, (*vo)[0].completions.Len())
	require.Equal(t, "version-c", (*vo)[1].version)
	require.True(t, (*vo)[1].completions.Has(compC))
}

func TestOrderedCompletionsCompleteUpToLastVersion(t *testing.T) {
	vo := newOrderedCompletions()
	compA1 := completion.NewCompletion(nil, nil, nil)
	compB := completion.NewCompletion(nil, nil, nil)
	compA2 := completion.NewCompletion(nil, nil, nil)
	compC := completion.NewCompletion(nil, nil, nil)

	vo.append("version-a", compA1)
	vo.append("version-b", compB)
	vo.append("version-a", compA2)
	vo.append("version-c", compC)

	completed := vo.completeUpTo("version-a")
	require.ElementsMatch(t, []*completion.Completion{compA1, compB, compA2}, completed)
	require.Len(t, *vo, 1)
	require.Equal(t, "version-c", (*vo)[0].version)
	require.True(t, (*vo)[0].completions.Has(compC))
}

func TestRemoveFromOrderedCompletionsCompactsMiddleEntry(t *testing.T) {
	cb := newTestCompletionCallbacks()
	vo := newOrderedCompletions()
	compA := completion.NewCompletion(nil, nil, nil)
	compB1 := completion.NewCompletion(nil, nil, nil)
	compB2 := completion.NewCompletion(nil, nil, nil)
	compC := completion.NewCompletion(nil, nil, nil)

	vo.append("version-a", compA)
	vo.append("version-b", compB1)
	vo.add("version-b", compB2)
	vo.append("version-c", compC)
	cb.completionsOrders[completionsOrderKey("node-1", listenerTypeURL)] = vo

	cb.RemoveTypeVersionCompletion(compB1)
	require.Len(t, *vo, 3)
	require.Equal(t, "version-b", (*vo)[1].version)
	require.Equal(t, 1, (*vo)[1].completions.Len())
	require.True(t, (*vo)[1].completions.Has(compB2))

	cb.RemoveTypeVersionCompletion(compB2)
	require.Len(t, *vo, 2)
	require.Equal(t, "version-a", (*vo)[0].version)
	require.Equal(t, "version-c", (*vo)[1].version)
}

func TestOrderedCompletionsRemoveCapacity(t *testing.T) {
	t.Run("ordinary capacity is retained", func(t *testing.T) {
		entries := make(orderedCompletions, 3, 16)
		entries[0].version = "version-a"
		entries[1].version = "version-b"
		entries[2].version = "version-c"

		entries.remove(1)
		require.Equal(t, 16, cap(entries))
		require.Equal(t, []string{"version-a", "version-c"}, []string{entries[0].version, entries[1].version})
	})

	t.Run("exactly the excess limit is retained", func(t *testing.T) {
		entries := make(orderedCompletions, 2, maxOrderedCompletionsExcessCapacity+1)
		entries.remove(0)
		require.Equal(t, maxOrderedCompletionsExcessCapacity+1, cap(entries))
		require.Equal(t, maxOrderedCompletionsExcessCapacity, cap(entries)-len(entries))
	})

	t.Run("capacity above the excess limit is released", func(t *testing.T) {
		entries := make(orderedCompletions, 2, maxOrderedCompletionsExcessCapacity+2)
		entries.remove(0)
		require.Equal(t, len(entries), cap(entries))
	})

	t.Run("large live slice shrinks only excessive capacity", func(t *testing.T) {
		entries := make(orderedCompletions, 200, 400)
		entries.remove(0)
		require.Len(t, entries, 199)
		require.Equal(t, 199, cap(entries))

		entries.remove(0)
		require.Len(t, entries, 198)
		require.Equal(t, 199, cap(entries))
	})
}

func TestAddTypeVersionCompletionCompletesAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.AddTypeVersionCompletion(comp, "version-1", NetworkPolicyTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.False(t, registered)

	require.Zero(t, cb.PendingCompletionCount())
	comp.Complete(nil)
	require.NoError(t, wg.Wait())
}

func TestAddTypeVersionCompletionKeepsPendingForNewVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	_, comp := newTestCompletion(t)

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	registered, err := cb.AddTypeVersionCompletion(comp, "version-2", NetworkPolicyTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)

	require.Equal(t, 1, cb.PendingCompletionCount())
}

func TestOnStreamResponseCompletesPendingCompletionForAlreadyAckedVersion(t *testing.T) {
	cb := newTestCompletionCallbacks()
	wg, comp := newTestCompletion(t)

	registered, err := cb.AddTypeVersionCompletion(comp, "", NetworkPolicyTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)
	require.Equal(t, 1, cb.PendingCompletionCount())

	req := &discovery.DiscoveryRequest{
		VersionInfo: "version-1",
		TypeUrl:     NetworkPolicyTypeURL,
		Node:        &core.Node{Id: "node-1"},
	}
	require.NoError(t, cb.OnStreamRequest(1, req))

	cb.OnStreamResponse(context.Background(), 1,
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

	registered, err := cb.AddTypeVersionCompletion(comp, "version-1", listenerTypeURL, "node-1", true, nil)
	require.NoError(t, err)
	require.True(t, registered)

	cb.OnStreamResponse(context.Background(), 1,
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
	for _, tt := range orderedCompletionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wg1, comp1 := newTestCompletion(t)
			wg2, comp2 := newTestCompletion(t)

			registerTypeVersionCompletion(t, cb, comp1, tt.typeURL, "version-1")
			registerTypeVersionCompletion(t, cb, comp2, tt.typeURL, "version-2")

			// The later response must move the earlier completion to version-2 rather
			// than leave it stranded in version-1's ordered-list entry.
			sendTypeVersionResponse(cb, tt.typeURL, "version-1")
			sendTypeVersionResponse(cb, tt.typeURL, "version-2")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-2")

			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wg1.Wait())
			require.NoError(t, wg2.Wait())
		})
	}
}

func TestOlderResponseDoesNotClaimNewerCompletion(t *testing.T) {
	for _, tt := range orderedCompletionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wg1, comp1 := newTestCompletion(t)
			wg2, comp2 := newTestCompletion(t)

			registerTypeVersionCompletion(t, cb, comp1, tt.typeURL, "version-1")
			registerTypeVersionCompletion(t, cb, comp2, tt.typeURL, "version-2")

			// An ACK for a response created before version-2 must not complete the
			// version-2 update, even though the response callback runs afterwards.
			sendTypeVersionResponse(cb, tt.typeURL, "version-1")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-1")
			require.Equal(t, 1, cb.PendingCompletionCount())
			require.NoError(t, wg1.Wait())
			requireCompletionPending(t, comp2)

			sendTypeVersionResponse(cb, tt.typeURL, "version-2")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-2")
			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wg2.Wait())
		})
	}
}

func TestResponseUsesLastMatchingVersion(t *testing.T) {
	for _, tt := range orderedCompletionTypeURLs {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			wgA1, compA1 := newTestCompletion(t)
			wgB, compB := newTestCompletion(t)
			wgA2, compA2 := newTestCompletion(t)

			registerTypeVersionCompletion(t, cb, compA1, tt.typeURL, "version-a")
			registerTypeVersionCompletion(t, cb, compB, tt.typeURL, "version-b")
			registerTypeVersionCompletion(t, cb, compA2, tt.typeURL, "version-a")

			// For A -> B -> A, the response for A represents the last A and therefore
			// covers both earlier entries as well as the final A entry.
			sendTypeVersionResponse(cb, tt.typeURL, "version-a")
			ackTypeVersionResponse(t, cb, tt.typeURL, "version-a")

			require.Zero(t, cb.PendingCompletionCount())
			require.NoError(t, wgA1.Wait())
			require.NoError(t, wgB.Wait())
			require.NoError(t, wgA2.Wait())
		})
	}
}
