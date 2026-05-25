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

	"github.com/cilium/cilium/pkg/completion"
)

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
