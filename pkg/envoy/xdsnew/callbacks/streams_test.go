// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"log/slog"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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
