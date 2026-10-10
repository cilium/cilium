// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// StreamMode distinguishes go-control-plane's independently numbered SotW and
// Delta stream spaces.
type StreamMode uint8

const (
	StreamModeSotW StreamMode = iota
	StreamModeDelta
	StreamModeCount
)

// StreamLifecycleHandler maintains cache-side state for streams after their
// first request identifies a node and when they close.
type StreamLifecycleHandler interface {
	StreamStarted(streamID int64, nodeID string, mode StreamMode)
	StreamClosed(streamID int64, nodeID string, mode StreamMode)
}

type streamKey struct {
	streamID int64
	mode     StreamMode
}

type callbackStreamState struct {
	nodeID    string
	responses typeurl.Slots[pendingResponse]
}

// ensureStreamState returns stream state, creating it when needed.
// cb.mutex must be held.
func (cb *CompletionCallbacks) ensureStreamState(key streamKey) *callbackStreamState {
	stream := cb.streams[key]
	if stream == nil {
		stream = &callbackStreamState{}
		cb.streams[key] = stream
	}
	return stream
}

// streamForRequest remembers the request's node ID. Subsequent requests may
// omit Node. started reports the first association of this stream with a node.
// Caller must hold cb.mutex.
func (cb *CompletionCallbacks) streamForRequest(streamID int64, req *discovery.DiscoveryRequest) (*callbackStreamState, bool) {
	stream := cb.ensureStreamState(streamKey{streamID: streamID, mode: StreamModeSotW})
	started := stream.nodeID == "" && req.GetNode().GetId() != ""
	if nodeID := req.GetNode().GetId(); nodeID != "" {
		stream.nodeID = nodeID
	}
	return stream, started
}

// OnStreamOpen is called once an xDS stream is open with a stream ID and the type URL (or "" for ADS).
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	return nil
}

// OnStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
func (cb *CompletionCallbacks) OnStreamClosed(streamID int64, node *core.Node) {
	cb.mutex.Lock()
	var nodeID string
	if stream := cb.streams[streamKey{streamID: streamID, mode: StreamModeSotW}]; stream != nil {
		nodeID = stream.nodeID
	}
	if nodeID == "" && node != nil {
		nodeID = node.GetId()
	}
	delete(cb.streams, streamKey{streamID: streamID, mode: StreamModeSotW})
	if nodeState := cb.nodes[nodeID]; nodeState != nil {
		for typeURL := range typeurl.Count {
			state := &nodeState.typeURLs[typeURL].response
			if state.pendingStreamID == streamID {
				state.clearPending()
			}
		}
	}

	streamStillOpen := false
	for _, openStream := range cb.streams {
		if openStream.nodeID == nodeID {
			streamStillOpen = true
			break
		}
	}
	if nodeID != "" && !streamStillOpen {
		if nodeState := cb.nodes[nodeID]; nodeState != nil {
			for typeURL := range typeurl.Count {
				typeState := &nodeState.typeURLs[typeURL]
				typeState.response.clearPending()
				typeState.response.acceptedVersion = ""
				typeState.response.acceptedGeneration = 0
				typeState.acceptedResources = acceptedResourceGroup{}
			}
		}
	}
	cb.mutex.Unlock()
	if cb.streamLifecycle != nil && nodeID != "" {
		cb.streamLifecycle.StreamClosed(streamID, nodeID, StreamModeSotW)
	}

	cb.Log.Info("OnStreamClosed", logfields.XDSStreamID, streamID)
}

func (cb *CompletionCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	panic("unimplemented")
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb *CompletionCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	panic("unimplemented")
}
