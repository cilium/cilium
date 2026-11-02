// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"bytes"
	"fmt"
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

func TestDeltaStreamLifecycleHandler(t *testing.T) {
	for _, firstRequest := range []string{"subscription", "nack"} {
		t.Run(firstRequest, func(t *testing.T) {
			handler := &testStreamLifecycleHandler{}
			cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), handler)
			chained := ChainedCallbacks{cb}

			require.NoError(t, chained.OnDeltaStreamOpen(t.Context(), 7, ""))
			deltaRequest := &discovery.DeltaDiscoveryRequest{
				Node:    &core.Node{Id: "node-1"},
				TypeUrl: typeurl.NetworkPolicy.URL(),
			}
			if firstRequest == "nack" {
				// Even a stale NACK can be the first request identifying a node.
				deltaRequest.ResponseNonce = "stale"
				deltaRequest.ErrorDetail = &status.Status{Message: "rejected policy"}
			}
			require.NoError(t, chained.OnStreamDeltaRequest(7, deltaRequest))
			require.Equal(t, []streamLifecycleEvent{{
				streamID: 7, nodeID: "node-1", mode: StreamModeDelta,
			}}, handler.started)
			// SotW and Delta stream counters may reuse the same numeric ID without
			// colliding, and a repeated Delta request starts no second lifecycle.
			require.NoError(t, chained.OnStreamDeltaRequest(7, &discovery.DeltaDiscoveryRequest{
				TypeUrl: deltaRequest.TypeUrl,
			}))
			require.Len(t, handler.started, 1)

			chained.OnDeltaStreamClosed(7, nil)
			require.Equal(t, []streamLifecycleEvent{{
				streamID: 7, nodeID: "node-1", mode: StreamModeDelta,
			}}, handler.closed)
		})
	}
}

func TestDeltaStreamCloseDiscardsUndeliveredResponseMetadata(t *testing.T) {
	cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), &testStreamLifecycleHandler{})
	request := &discovery.DeltaDiscoveryRequest{
		Node:    &core.Node{Id: "node-1"},
		TypeUrl: typeurl.Listener.URL(),
	}
	require.NoError(t, cb.OnStreamDeltaRequest(7, request))

	require.Equal(t, int64(7), cb.StreamIDForDeltaRequest(request))
	cb.RegisterDeltaResponse(7, &discovery.DeltaDiscoveryResponse{
		TypeUrl: request.TypeUrl, SystemVersionInfo: "e1:g1",
	}, WithSnapshotGeneration(t.Context(), 1))
	cb.mutex.Lock()
	require.NotNil(t, cb.streams[streamKey{streamID: 7, mode: StreamModeDelta}].preparedDeltaResponse.response)
	cb.mutex.Unlock()

	cb.OnDeltaStreamClosed(7, nil)
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	require.Empty(t, cb.streams)
}

func TestDeltaStreamCloseBeforeResponseDeliveryDiscardsMetadata(t *testing.T) {
	cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), &testStreamLifecycleHandler{})
	request := &discovery.DeltaDiscoveryRequest{
		Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Listener.URL(),
	}
	require.NoError(t, cb.OnStreamDeltaRequest(7, request))

	streamID := cb.StreamIDForDeltaRequest(request)
	require.Equal(t, int64(7), streamID)
	cb.mutex.Lock()
	closedStream := cb.streams[streamKey{streamID: streamID, mode: StreamModeDelta}]
	cb.mutex.Unlock()

	// Closing can race with encoding a response for the original watch.
	// Late registration must neither retain metadata nor recreate the stream.
	cb.OnDeltaStreamClosed(streamID, nil)
	cb.RegisterDeltaResponse(streamID, &discovery.DeltaDiscoveryResponse{
		TypeUrl: request.TypeUrl, SystemVersionInfo: "e1:g1",
	}, WithSnapshotGeneration(t.Context(), 1))

	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	require.Empty(t, closedStream.preparedDeltaResponse)
	require.Empty(t, cb.streams)
}

func TestTakePendingResponsePreservesStreamOwnership(t *testing.T) {
	key := streamKey{streamID: 7, mode: StreamModeDelta}
	for _, owner := range []streamKey{
		key,
		{streamID: 8, mode: StreamModeDelta},
		{streamID: 7, mode: StreamModeSotW},
	} {
		t.Run(fmt.Sprintf("mode-%d/stream-%d", owner.mode, owner.streamID), func(t *testing.T) {
			pending := pendingResponse{
				pendingVersion: "e1:g2", pendingGeneration: 2, pendingNonce: "nonce-2",
				coverage: &responseCoverage{typeURL: typeurl.Listener, delta: true},
			}
			coverage := pending.coverage
			state := responseState{
				pendingResponse: pending, pendingStreamKey: owner,
				acceptedGeneration: 1, acceptedVersion: "e1:g1", rejectedVersion: "rejected",
			}
			expected := state
			if owner == key {
				expected.pendingResponse = pendingResponse{}
				expected.pendingStreamKey = streamKey{}
			}
			cb := newTestCompletionCallbacks()
			cb.mutex.Lock()
			taken := state.takePendingResponseLocked(key, &pending)
			cb.mutex.Unlock()
			require.Equal(t, "e1:g2", taken.pendingVersion)
			require.Equal(t, Generation(2), taken.pendingGeneration)
			require.Equal(t, "nonce-2", taken.pendingNonce)
			require.Same(t, coverage, taken.coverage)
			require.Empty(t, pending)
			require.Equal(t, expected, state)
		})
	}
}

type testNACKHandlerFunc func(string, func(RevertBatch) error) error

func (handler testNACKHandlerFunc) HandleNACK(nodeID string, process func(RevertBatch) error) error {
	return handler(nodeID, process)
}

func TestDeltaNACKRevalidatesAfterRequestInitialization(t *testing.T) {
	for _, transition := range []string{"closed", "newer-response"} {
		t.Run(transition, func(t *testing.T) {
			handler := &testStreamLifecycleHandler{}
			cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), handler)
			key := streamKey{streamID: 7, mode: StreamModeDelta}
			req := &discovery.DeltaDiscoveryRequest{
				Node: &core.Node{Id: "node-1"}, TypeUrl: typeurl.Listener.URL(),
				ResponseNonce: "old", ErrorDetail: &status.Status{Message: "rejected listener"},
			}
			cb.mutex.Lock()
			cb.ensureStreamState(key).responses[typeurl.Listener] = pendingResponse{pendingNonce: "old", pendingGeneration: 1}
			cb.mutex.Unlock()
			cb.nackHandler = testNACKHandlerFunc(func(nodeID string, process func(RevertBatch) error) error {
				require.Equal(t, "node-1", nodeID)
				require.Len(t, handler.started, 1, "register the lifecycle before acquiring the cache lock")
				cb.mutex.Lock()
				require.Same(t, req, cb.streams[key].deltaRequest)
				if transition == "newer-response" {
					cb.streams[key].responses[typeurl.Listener].pendingNonce = "new"
				}
				cb.mutex.Unlock()
				if transition == "closed" {
					cb.OnDeltaStreamClosed(key.streamID, nil)
				}
				return process(func([]Rollback) error {
					t.Fatal("a stale response must not be reverted")
					return nil
				})
			})
			require.NoError(t, cb.OnStreamDeltaRequest(key.streamID, req))
			cb.mutex.Lock()
			defer cb.mutex.Unlock()
			if transition == "closed" {
				require.NotContains(t, cb.streams, key)
			} else {
				require.Equal(t, "new", cb.streams[key].responses[typeurl.Listener].pendingNonce)
			}
		})
	}
}

func TestUnsupportedDeltaRequestInitializesStream(t *testing.T) {
	for _, nack := range []bool{false, true} {
		t.Run(fmt.Sprintf("nack-%t", nack), func(t *testing.T) {
			handler := &testStreamLifecycleHandler{}
			cb := NewCompletionCallbacks(slog.New(slog.DiscardHandler), handler)
			req := &discovery.DeltaDiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: "unsupported"}
			if nack {
				req.ResponseNonce = "stale"
				req.ErrorDetail = &status.Status{Message: "rejected"}
			}
			require.NoError(t, cb.OnStreamDeltaRequest(7, req))
			require.Equal(t, []streamLifecycleEvent{{streamID: 7, nodeID: "node-1", mode: StreamModeDelta}}, handler.started)
			cb.mutex.Lock()
			defer cb.mutex.Unlock()
			require.Empty(t, cb.streams[streamKey{streamID: 7, mode: StreamModeDelta}].deltaRequest)
		})
	}
}

func TestStreamCallbacksLogAtDebug(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		t.Run(level.String(), func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: level}))
			cb := ChainedCallbacks{LoggingCallbacks{Log: logger}, NewCompletionCallbacks(logger, testNACKHandler{})}
			typeURL := typeurl.Listener.URL()
			sotwReq := &discovery.DiscoveryRequest{Node: &core.Node{Id: "node-1"}, TypeUrl: typeURL}
			deltaReq := &discovery.DeltaDiscoveryRequest{Node: sotwReq.Node, TypeUrl: typeURL}
			require.NoError(t, cb.OnStreamOpen(t.Context(), 7, ""))
			require.NoError(t, cb.OnStreamRequest(7, sotwReq))
			cb.OnStreamResponse(t.Context(), 7, sotwReq, &discovery.DiscoveryResponse{TypeUrl: typeURL, VersionInfo: "v1"})
			cb.OnStreamClosed(7, nil)
			require.NoError(t, cb.OnDeltaStreamOpen(t.Context(), 7, ""))
			require.NoError(t, cb.OnStreamDeltaRequest(7, deltaReq))
			cb.OnStreamDeltaResponse(7, deltaReq, &discovery.DeltaDiscoveryResponse{TypeUrl: typeURL, SystemVersionInfo: "v1"})
			cb.OnDeltaStreamClosed(7, nil)
			if level == slog.LevelInfo {
				require.Empty(t, logs.String())
			} else {
				require.Equal(t, 8, bytes.Count(logs.Bytes(), []byte("\n")), "log each transport event once")
			}
		})
	}
}
