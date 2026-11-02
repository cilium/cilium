// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
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

// streamKey includes the mode because go-control-plane allocates SotW and Delta
// stream IDs independently, while both servers share CompletionCallbacks.
type streamKey struct {
	streamID int64
	mode     StreamMode
}

type callbackStreamState struct {
	nodeID    string
	responses typeurl.Slots[pendingResponse]
	// deltaRequest associates the next cache watch with this stream. Request
	// handling and watch creation run consecutively on the stream goroutine.
	deltaRequest *discovery.DeltaDiscoveryRequest
	// Encoding transfers metadata only for the response this stream will
	// immediately report through OnStreamDeltaResponse.
	preparedDeltaResponse deltaResponseMetadata
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

// streamForDeltaRequest remembers the node before go-control-plane restores it
// on subsequent Delta requests. The validation callback normally fills Node,
// while this fallback keeps direct callback users correct.
func (cb *CompletionCallbacks) streamForDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) (*callbackStreamState, bool) {
	stream := cb.ensureStreamState(streamKey{streamID: streamID, mode: StreamModeDelta})
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
	cb.closeStream(streamID, node, StreamModeSotW)
}

func (cb *CompletionCallbacks) closeStream(streamID int64, node *core.Node, mode StreamMode) {
	key := streamKey{streamID: streamID, mode: mode}
	cb.mutex.Lock()
	var nodeID string
	stream := cb.streams[key]
	if stream != nil {
		nodeID = stream.nodeID
	}
	if nodeID == "" && node != nil {
		nodeID = node.GetId()
	}
	delete(cb.streams, key)
	if nodeState := cb.nodes[nodeID]; nodeState != nil {
		for typeURL := range typeurl.Count {
			state := &nodeState.typeURLs[typeURL].response
			if state.pendingStreamKey == key {
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
		cb.streamLifecycle.StreamClosed(streamID, nodeID, mode)
	}
}

func (cb *CompletionCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	return nil
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb *CompletionCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	cb.closeStream(streamID, node, StreamModeDelta)
}

// StreamIDForDeltaRequest associates a cache watch with its originating stream.
// The watch retains the ID because another request can arrive before delivery.
// go-control-plane handles each request and creates its watch consecutively.
func (cb *CompletionCallbacks) StreamIDForDeltaRequest(req *discovery.DeltaDiscoveryRequest) int64 {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	for key, stream := range cb.streams {
		if key.mode == StreamModeDelta && stream.deltaRequest == req {
			stream.deltaRequest = nil
			return key.streamID
		}
	}
	return 0
}
