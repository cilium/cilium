// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"log/slog"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type streamLifecycleEvent struct {
	streamID int64
	nodeID   string
	mode     StreamMode
}

type testStreamLifecycleHandler struct {
	testNACKHandler
	started []streamLifecycleEvent
	closed  []streamLifecycleEvent
}

func (handler *testStreamLifecycleHandler) StreamStarted(streamID int64, nodeID string, mode StreamMode) {
	handler.started = append(handler.started, streamLifecycleEvent{streamID: streamID, nodeID: nodeID, mode: mode})
}

func (handler *testStreamLifecycleHandler) StreamClosed(streamID int64, nodeID string, mode StreamMode) {
	handler.closed = append(handler.closed, streamLifecycleEvent{streamID: streamID, nodeID: nodeID, mode: mode})
}

func TestStreamLifecycleHandler(t *testing.T) {
	for _, firstRequest := range []string{"subscription", "nack"} {
		t.Run(firstRequest, func(t *testing.T) {
			handler := &testStreamLifecycleHandler{}
			cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), handler)
			chained := ChainedCallbacks{cb}

			require.NoError(t, chained.OnStreamOpen(t.Context(), 7, ""))
			sotwRequest := &discovery.DiscoveryRequest{
				Node:    &core.Node{Id: "node-1"},
				TypeUrl: typeurl.NetworkPolicy.URL(),
			}
			if firstRequest == "nack" {
				// Even a stale NACK can be the first request identifying a node.
				// Its early-return path must still register the stream lifecycle.
				sotwRequest.ResponseNonce = "stale"
				sotwRequest.ErrorDetail = &status.Status{Message: "rejected policy"}
			}
			require.NoError(t, chained.OnStreamRequest(7, sotwRequest))
			require.Equal(t, []streamLifecycleEvent{{streamID: 7, nodeID: "node-1", mode: StreamModeSotW}}, handler.started)
			// A later request on the same stream must not increment the node's
			// stream count again.
			require.NoError(t, chained.OnStreamRequest(7, &discovery.DiscoveryRequest{TypeUrl: sotwRequest.TypeUrl}))
			require.Len(t, handler.started, 1)

			chained.OnStreamClosed(7, nil)
			require.Equal(t, []streamLifecycleEvent{{streamID: 7, nodeID: "node-1", mode: StreamModeSotW}}, handler.closed)
		})
	}
}

func TestStreamClosePreservesPendingWork(t *testing.T) {
	for _, tt := range []struct {
		name      string
		otherNode string
		reject    bool
	}{
		{name: "last-stream-ack"},
		{name: "last-stream-nack", reject: true},
		{name: "same-node-stream-ack", otherNode: "node-1"},
		{name: "same-node-stream-nack", otherNode: "node-1", reject: true},
		{name: "other-node-stream-ack", otherNode: "node-2"},
		{name: "other-node-stream-nack", otherNode: "node-2", reject: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cb := newTestCompletionCallbacks()
			if tt.otherNode != "" {
				require.NoError(t, cb.OnStreamRequest(2, &discovery.DiscoveryRequest{
					Node: &core.Node{Id: tt.otherNode}, TypeUrl: listenerTypeURL.URL(),
				}))
				t.Cleanup(func() { cb.OnStreamClosed(2, nil) })
			}
			accepted := &listener.Listener{Name: "listener-1", StatPrefix: "accepted"}
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 1, "version-1", accepted)
			ackTypeVersionResponse(t, cb, listenerTypeURL, "version-1")
			require.True(t, cb.ResourceAccepted("node-1", listenerTypeURL, accepted.Name, accepted, true, Revision{}))

			updated := &listener.Listener{Name: accepted.Name, StatPrefix: "pending"}
			wg, comp, pending := cb.newTestCompletion(t, listenerTypeURL, 2, updated.Name)
			registerTypeGenerationCompletion(t, cb, comp, pending, "version-2")
			reverted, finalized := false, false
			scope := SingleResourceScope(updated.Name, Generation(2).Revision())
			cb.AddTypeGenerationWithRollback(2, listenerTypeURL, "node-1", finalizingTestRollback{
				RevertFunc: func() error { reverted = true; return nil },
				finalize:   func() { finalized = true },
			}, &scope)
			snapshot := newListenerSnapshot(t, "version-2", updated)
			cb.SetPublishedSnapshot("node-1", snapshot)
			sendTypeGenerationResponse(t, cb, listenerTypeURL, 2, "version-2", updated)
			cb.OnStreamClosed(1, nil)
			require.Equal(t, tt.otherNode == "node-1",
				cb.ResourceAccepted("node-1", listenerTypeURL, accepted.Name, accepted, true, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, accepted.Name, nil, false, Revision{}))
			require.False(t, cb.ResourceAccepted("node-1", listenerTypeURL, updated.Name, updated, true, Revision{}))
			requireCompletionPending(t, comp)
			require.False(t, reverted)
			require.False(t, finalized)
			if tt.otherNode != "node-1" {
				_, noOp, pending := cb.newTestCompletion(t, listenerTypeURL, 1, accepted.Name)
				registered, err := cb.AddPreparedTypeGenerationCompletion(noOp, pending, "version-1", false)
				require.NoError(t, err)
				require.True(t, registered, "the old accepted version must not short-circuit a new wait")
				requireCompletionPending(t, noOp)
			}

			request := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: listenerTypeURL.URL()}
			require.NoError(t, cb.OnStreamRequest(3, request))
			t.Cleanup(func() { cb.OnStreamClosed(3, nil) })
			sendSnapshotResponse(t, cb, 3, request, 2, snapshot, "reconnected")
			requireCompletionPending(t, comp)
			request.VersionInfo, request.ResponseNonce = "version-2", "reconnected"
			if tt.reject {
				request.VersionInfo = ""
				request.ErrorDetail = &status.Status{Message: "rejected after reconnect"}
			}
			require.NoError(t, cb.OnStreamRequest(3, request))
			if tt.reject {
				require.ErrorContains(t, wg.Wait(), "rejected after reconnect")
			} else {
				require.NoError(t, wg.Wait())
			}
			require.Equal(t, tt.reject, reverted)
			require.Equal(t, !tt.reject, finalized)
		})
	}
}
