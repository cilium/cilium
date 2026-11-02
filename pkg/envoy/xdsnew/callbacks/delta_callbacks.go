// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// Encoding and the Delta response callback run consecutively on one stream.
// A single slot transfers the exact encoded response's metadata without history.
type deltaResponseMetadata struct {
	response   *discovery.DeltaDiscoveryResponse
	generation Generation
	coverage   *responseCoverage
}

// RegisterDeltaResponse bridges the encoded response's metadata to
// OnStreamDeltaResponse, whose API has no context. Record it only while its
// originating stream is open; canceled responses which are never encoded
// need no registration.
func (cb *CompletionCallbacks) RegisterDeltaResponse(streamID int64, response *discovery.DeltaDiscoveryResponse, ctx context.Context) {
	prepared := deltaResponseMetadata{
		response:   response,
		generation: snapshotGenerationFromContext(ctx),
		coverage:   responseCoverageFromContext(ctx),
	}
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	if stream := cb.streams[streamKey{streamID: streamID, mode: StreamModeDelta}]; stream != nil {
		stream.preparedDeltaResponse = prepared
	}
}

// OnStreamDeltaRequest shares ACK/NACK handling with SotW. Delta requests do
// not echo a system version, so processing uses the nonce's recorded response.
func (cb *CompletionCallbacks) OnStreamDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	return cb.onStreamRequest(streamKey{streamID: streamID, mode: StreamModeDelta}, streamRequest{
		nodeID: req.GetNode().GetId(), typeURL: req.GetTypeUrl(),
		nonce: req.GetResponseNonce(), errorDetail: req.GetErrorDetail(), deltaRequest: req,
	})
}

// OnStreamDeltaResponse associates cache-side generation metadata with the
// nonce go-control-plane is about to send.
func (cb *CompletionCallbacks) OnStreamDeltaResponse(streamID int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	cb.onStreamResponse(streamKey{streamID: streamID, mode: StreamModeDelta}, req.GetNode().GetId(), resp.GetTypeUrl(), pendingResponse{
		pendingVersion: resp.GetSystemVersionInfo(), pendingNonce: resp.GetNonce(),
	}, resp)
}
