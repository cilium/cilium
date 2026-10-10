// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// RevertBatch applies the selected inverses as one cache mutation. It is supplied
// by NACKHandler with the cache lock held, may be called at most once, and must
// not be retained by the caller.
type RevertBatch func([]Rollback) error

// NACKHandler serializes selection and recovery with cache mutations.
type NACKHandler interface {
	// HandleNACK acquires the cache lock before invoking process and keeps it
	// until process returns. process may acquire the callbacks lock to claim or
	// reconcile inverses, but must release it before calling RevertBatch.
	// Response delivery and application callbacks must run after unlocking.
	HandleNACK(nodeID string, process func(RevertBatch) error) error
}

type generationRevert struct {
	generation Generation
	pending    *pendingGeneration
}

// nackRecovery owns work detached under the callbacks lock. Only its request's
// goroutine changes it. No stream or shared response state is read while
// invoking cache recovery or application callbacks.
type nackRecovery struct {
	nodeID     string
	typeURL    typeurl.Index
	cause      error
	reverts    []generationRevert
	completed  []*completion.Completion
	finalizers []Rollback
}

// handleNACK enters the cache transaction before claiming any inverses. A cache
// caller therefore cannot attach a new wait between selection and compensation.
// The callbacks lock is never held while acquiring the cache lock.
func (cb *CompletionCallbacks) handleNACK(streamID int64, req *discovery.DiscoveryRequest) error {
	cb.mutex.Lock()
	stream, started := cb.streamForRequest(streamID, req)
	nodeID := stream.nodeID
	cb.mutex.Unlock()
	if started && cb.streamLifecycle != nil {
		cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeSotW)
	}
	typeURL, supported := typeurl.FromURL(req.GetTypeUrl())
	if !supported {
		return nil
	}

	var recovery *nackRecovery
	err := cb.nackHandler.HandleNACK(nodeID, func(revert RevertBatch) error {
		cb.mutex.Lock()
		// The stream may have closed or progressed while acquiring the cache
		// lock. Revalidate instead of acting on an earlier response identity.
		stream := cb.streams[streamKey{streamID: streamID, mode: StreamModeSotW}]
		if stream == nil || stream.nodeID != nodeID || (req.GetResponseNonce() != "" &&
			(stream.responses[typeURL].pendingNonce == "" || stream.responses[typeURL].pendingNonce != req.GetResponseNonce())) {
			cb.mutex.Unlock()
			return nil
		}
		recovery = cb.handleNACKLocked(streamID, req, stream, typeURL, cb.ensureTypeURLState(nodeID, typeURL))
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

// finishNACKLocked retains a failed batch after cache recovery. The caller holds
// cb.mutex throughout; this method never acquires or releases it and never
// invokes a rollback or application callback.
func (cb *CompletionCallbacks) finishNACKLocked(recovery *nackRecovery) {
	typeState := cb.ensureTypeURLState(recovery.nodeID, recovery.typeURL)
	if typeState.pendingGenerations == nil {
		typeState.pendingGenerations = make(map[Generation]*pendingGeneration, len(recovery.reverts))
	}
	for _, remaining := range recovery.reverts {
		// Another stream may have ACKed an already delivered response while
		// recovery ran without the callbacks lock. Preserve that progress without
		// discarding recovery for names that response did not acknowledge.
		if remaining.pending.scope.acknowledgeAcceptedRollback(typeState.acceptedResources, recovery.typeURL, remaining.generation) {
			recovery.finalizers = append(recovery.finalizers, remaining.pending.rollback)
			continue
		}
		remaining.pending.responseGeneration = 0
		if typeState.response.pendingGeneration >= remaining.generation {
			remaining.pending.responseGeneration = typeState.response.pendingGeneration
		}
		typeState.pendingGenerations[remaining.generation] = remaining.pending
	}
	typeState.removeEmptyPendingGenerationSet()
}

// complete runs without either cache or callbacks locks: both finalization and
// caller callbacks can reenter cache APIs. Waiters receive the original NACK,
// even when recovery failed and its returned error will close the stream.
func (recovery *nackRecovery) complete() {
	for _, rollback := range recovery.finalizers {
		rollback.Finalize()
	}
	for _, comp := range recovery.completed {
		comp.Complete(recovery.cause)
	}
}
