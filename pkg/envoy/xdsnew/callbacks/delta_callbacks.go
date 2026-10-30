// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"math"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// OnStreamDeltaRequest handles subscription requests and ACKs/NACKs for Delta
// ADS. The nonce identifies the exact response because Delta requests do not
// echo a system version.
func (cb *CompletionCallbacks) OnStreamDeltaRequest(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	if req.GetErrorDetail() != nil {
		return cb.handleDeltaNACK(streamID, req)
	}

	cb.mutex.Lock()
	stream, started := cb.streamForDeltaRequest(streamID, req)
	nodeID := stream.nodeID
	if started && cb.streamLifecycle != nil {
		defer cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeDelta)
	}
	typeURL := req.GetTypeUrl()
	typeIndex, supported := typeurl.FromURL(typeURL)
	if !supported {
		cb.mutex.Unlock()
		return nil
	}
	stream.deltaRequests[typeIndex] = req
	nodeState := cb.ensureNodeState(nodeID)
	typeState := nodeState.typeURLState(typeIndex)
	state := &typeState.response
	response := &stream.responses[typeIndex]
	if req.GetResponseNonce() == "" {
		state.acceptedVersion = ""
		state.acceptedGeneration = 0
		typeState.acceptedResources = acceptedResourceGroup{}
		cb.mutex.Unlock()
		return nil
	}
	if response.pendingNonce == "" || response.pendingNonce != req.GetResponseNonce() {
		cb.Log.Debug("Ignoring stale Delta xDS ACK/NACK",
			logfields.XDSTypeURL, typeURL,
			logfields.XDSNonce, req.GetResponseNonce(),
			logfields.NodeID, nodeID)
		cb.mutex.Unlock()
		return nil
	}

	acceptedGeneration := response.pendingGeneration
	acceptedVersion := response.pendingVersion
	coverage := response.coverage
	*response = pendingResponse{}
	key := streamKey{streamID: streamID, mode: StreamModeDelta}
	if state.pendingStream == key {
		state.clearPending()
	}
	if coverage != nil && acceptedGeneration != 0 {
		typeState.acceptedResources.acknowledge(coverage, acceptedGeneration)
	}
	if acceptedGeneration != 0 && acceptedGeneration >= state.acceptedGeneration && coverage.complete() {
		state.acceptedGeneration = acceptedGeneration
		state.acceptedVersion = acceptedVersion
		state.rejectedVersion = ""
		state.rejectedErr = nil
		if coverage == nil {
			typeState.acceptedResources = acceptedResourceGroup{}
			if published := nodeState.published; published != nil && published.GetVersion(typeURL) == acceptedVersion {
				typeState.acceptedResources = acceptedResourceGroup{
					generation: acceptedGeneration,
					resources:  published.GetResourcesAndTTL(typeURL),
				}
			}
		}
	}

	type completionResult struct {
		completion *completion.Completion
		generation Generation
	}
	var completed []completionResult
	var finalizers []Rollback
	debugEnabled := cb.Log.Enabled(context.Background(), slog.LevelDebug)
	for c, pending := range cb.pendingWaits {
		if pending.nodeID != nodeID || pending.typeURL != typeIndex || acceptedGeneration == 0 {
			continue
		}
		coveredGeneration := acceptedGeneration
		if pending.responseGeneration == acceptedGeneration {
			coveredGeneration = math.MaxUint64
		}
		if pending.scope.wholeType() && pending.generation > coveredGeneration {
			continue
		}
		if !pending.scope.acknowledge(coverage, coveredGeneration) {
			continue
		}
		completed = append(completed, completionResult{completion: c, generation: pending.generation})
		delete(cb.pendingWaits, c)
		if debugEnabled {
			cb.Log.Debug("Completed completion for Delta type URL and generation",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, acceptedVersion,
				logfields.XDSGeneration, pending.generation)
		}
	}
	for pending, generation := range typeState.pendingGenerations {
		if acceptedGeneration != 0 && generation <= acceptedGeneration && pending.scope != nil && pending.scope.acknowledge(coverage, acceptedGeneration) {
			finalizers = append(finalizers, pending.rollback)
			delete(typeState.pendingGenerations, pending)
		}
	}
	typeState.removeEmptyPendingGenerationSet()
	cb.mutex.Unlock()

	for _, rollback := range finalizers {
		rollback.Finalize()
	}
	for _, result := range completed {
		result.completion.Complete(nil)
	}
	return nil
}

func (cb *CompletionCallbacks) handleDeltaNACK(streamID int64, req *discovery.DeltaDiscoveryRequest) error {
	key := streamKey{streamID: streamID, mode: StreamModeDelta}
	typeIndex, supported := typeurl.FromURL(req.GetTypeUrl())
	cb.mutex.Lock()
	stream, started := cb.streamForDeltaRequest(streamID, req)
	if supported {
		stream.deltaRequests[typeIndex] = req
	}
	nodeID := stream.nodeID
	cb.mutex.Unlock()
	if started && cb.streamLifecycle != nil {
		cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeDelta)
	}
	if !supported {
		return nil
	}

	var recovery *nackRecovery
	err := cb.nackHandler.HandleNACK(nodeID, func(revert RevertBatch) error {
		cb.mutex.Lock()
		stream := cb.streams[key]
		if stream == nil || stream.nodeID != nodeID ||
			stream.responses[typeIndex].pendingNonce == "" ||
			stream.responses[typeIndex].pendingNonce != req.GetResponseNonce() {
			cb.mutex.Unlock()
			return nil
		}
		typeState := cb.ensureTypeURLState(nodeID, typeIndex)
		synthetic := &discovery.DiscoveryRequest{
			TypeUrl:       req.GetTypeUrl(),
			VersionInfo:   typeState.response.acceptedVersion,
			ResponseNonce: req.GetResponseNonce(),
			ErrorDetail:   req.GetErrorDetail(),
		}
		recovery = cb.handleNACKLocked(key, synthetic, stream, typeIndex, typeState)
		cb.mutex.Unlock()

		rollbacks := make([]Rollback, len(recovery.reverts))
		for i, selected := range recovery.reverts {
			rollbacks[i] = selected.pending.rollback
		}
		if err := revert(rollbacks); err != nil {
			cb.mutex.Lock()
			cb.finishNACKLocked(recovery)
			cb.mutex.Unlock()
			return fmt.Errorf("failed to revert NACKed %s for node %s: %w", req.GetTypeUrl(), nodeID, err)
		}
		return nil
	})
	if recovery != nil {
		recovery.complete()
	}
	return err
}

// OnStreamDeltaResponse associates cache-side generation metadata with the
// nonce go-control-plane is about to send.
func (cb *CompletionCallbacks) OnStreamDeltaResponse(streamID int64, req *discovery.DeltaDiscoveryRequest, resp *discovery.DeltaDiscoveryResponse) {
	version := resp.GetSystemVersionInfo()
	if version == "" {
		return
	}
	typeIndex, supported := typeurl.FromURL(resp.GetTypeUrl())
	if !supported {
		return
	}

	cb.mutex.Lock()
	stream, started := cb.streamForDeltaRequest(streamID, req)
	nodeID := stream.nodeID
	if stream.deltaRequests[typeIndex] == req {
		stream.deltaRequests[typeIndex] = nil
	}
	if started && cb.streamLifecycle != nil {
		defer cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeDelta)
	}
	prepared, found := cb.preparedDeltaResponses[req]
	if found {
		delete(cb.preparedDeltaResponses, req)
	} else {
		prepared.pendingVersion = version
	}
	prepared.pendingNonce = resp.GetNonce()
	stream.responses[typeIndex] = prepared

	typeState := cb.ensureTypeURLState(nodeID, typeIndex)
	responseGeneration := prepared.pendingGeneration
	coverage := prepared.coverage
	for _, pending := range cb.pendingWaits {
		if pending.nodeID == nodeID && pending.typeURL == typeIndex && pending.generation <= responseGeneration && pending.scope.intersects(coverage, responseGeneration) {
			pending.responseGeneration = responseGeneration
		}
	}
	for pending, generation := range typeState.pendingGenerations {
		if generation <= responseGeneration && pending.scope.intersects(coverage, responseGeneration) {
			pending.responseGeneration = responseGeneration
		}
	}

	state := &typeState.response
	if responseGeneration >= state.pendingGeneration && responseGeneration >= state.acceptedGeneration {
		state.pendingVersion = version
		state.pendingGeneration = responseGeneration
		state.pendingNonce = resp.GetNonce()
		state.coverage = coverage
		state.pendingStream = streamKey{streamID: streamID, mode: StreamModeDelta}
		if state.rejectedVersion == version {
			state.rejectedVersion = ""
			state.rejectedErr = nil
		}
	}
	cb.mutex.Unlock()
}
