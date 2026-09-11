// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

type snapshotGenerationContextKey struct{}

// WithSnapshotGeneration associates an xDS response with the generation of
// the snapshot from which go-control-plane constructed it.
func WithSnapshotGeneration(ctx context.Context, generation uint64) context.Context {
	return context.WithValue(ctx, snapshotGenerationContextKey{}, generation)
}

func snapshotGenerationFromContext(ctx context.Context) uint64 {
	generation, _ := ctx.Value(snapshotGenerationContextKey{}).(uint64)
	return generation
}

func completionKey(nodeID, typeURL string) string {
	return nodeID + "\x00" + typeURL
}

// RevertFunc restores one resource update if expectedGeneration is still the
// current generation. On success it returns the generation published by the
// revert, which can be passed to the next older RevertFunc in a rollback chain.
type RevertFunc func(expectedGeneration uint64) (generation uint64, reverted bool)

// nodeIDForRequest returns the request node ID, falling back to the node ID
// remembered from the first request on the stream. cb.mutex must be held.
func (cb *CompletionCallbacks) nodeIDForRequest(streamID int64, req *discovery.DiscoveryRequest) string {
	if nodeID := req.GetNode().GetId(); nodeID != "" {
		cb.streamNodeIDs[streamID] = nodeID
		return nodeID
	}
	return cb.streamNodeIDs[streamID]
}

type CompletionCallbacks struct {
	Log *slog.Logger

	// mutex protects all fields below. go-control-plane invokes stream
	// callbacks outside the ADS server mutex, while cache updates register
	// completions from Cilium-owned paths.
	mutex lock.Mutex

	// pendingCompletions is the list of updates that are pending completion.
	pendingCompletions map[*completion.Completion]*pendingCompletion
	// responseStates tracks the latest xDS response/ACK state per (nodeID, typeURL).
	// Generations establish ordering; versions are retained only because Envoy
	// echoes the content version in ACK and NACK requests.
	responseStates map[string]responseState
	// streamNodeIDs remembers the node ID from the first request on each ADS
	// stream. Envoy is configured with SetNodeOnFirstMessageOnly, so subsequent
	// ACK/NACK requests can omit Node even though completions are keyed by node ID.
	streamNodeIDs map[int64]string
}

func NewCompletionCallbacks(logger *slog.Logger) *CompletionCallbacks {
	return &CompletionCallbacks{
		Log:                logger,
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
		responseStates:     make(map[string]responseState),
		streamNodeIDs:      make(map[int64]string),
	}
}

type responseState struct {
	// pendingVersion is the version in the most recent response for which we have
	// not yet observed an ACK or NACK.
	pendingVersion    string
	pendingGeneration uint64
	// acceptedVersion is the version Envoy most recently ACKed for this type.
	acceptedVersion string
	// rejectedVersion/rejectedErr remember the latest NACKed version so a
	// no-change update for that same cache state can fail immediately.
	rejectedVersion string
	rejectedErr     error
}

// pendingCompletion is an update that is pending completion.
type pendingCompletion struct {
	nodeID string
	// version is the version to be ACKed.
	version string
	// generation is the resource generation which registered this completion.
	generation uint64
	// responseGeneration is the snapshot response this completion has been
	// attached to. It may be older than generation when an unchanged update is
	// attached to a response already in flight.
	responseGeneration uint64

	// typeURL is the type URL of the resources to be ACKed.
	typeURL string

	// revertFunc is called when a NACK is received to undo the resource change.
	// It returns the newly published generation. The caller passes that value to
	// the next older revert so a coalesced rollback remains stale-update safe.
	revertFunc RevertFunc
}

func (cb *CompletionCallbacks) RemoveTypeGenerationCompletion(c *completion.Completion) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	delete(cb.pendingCompletions, c)
}

// CancelPendingCompletions completes all pending completions for the given type URL
// without an error, to unblock any waiters. This is used when the last proxy listener
// is removed, meaning Envoy will never ACK the pending updates. Completing with nil
// mirrors the behavior of the old xDS server, since there is nothing to do even if
// an error status was used instead.
func (cb *CompletionCallbacks) CancelPendingCompletions(typeURL string) {
	var completed []*completion.Completion

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.typeURL == typeURL {
			cb.Log.Debug("Cancelling pending completion",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, pc.version,
				"generation", pc.generation,
				logfields.NodeID, pc.nodeID)
			completed = append(completed, c)
			delete(cb.pendingCompletions, c)
		}
	}
	cb.mutex.Unlock()

	for _, c := range completed {
		c.Complete(nil)
	}
}

// PendingCompletionCount returns the number of pending completions. Intended for testing.
func (cb *CompletionCallbacks) PendingCompletionCount() int {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	return len(cb.pendingCompletions)
}

// addPendingCompletion records a completion that is waiting for an xDS ACK/NACK.
// cb.mutex must be held.
func (cb *CompletionCallbacks) addPendingCompletion(c *completion.Completion, generation uint64, version string, typeURL string, nodeID string, revertFunc RevertFunc) *pendingCompletion {
	cb.Log.Debug("Adding pending completion for type URL and generation",
		logfields.XDSTypeURL, typeURL,
		logfields.Version, version,
		"generation", generation,
		logfields.NodeID, nodeID)
	pc := &pendingCompletion{
		nodeID:     nodeID,
		version:    version,
		generation: generation,
		typeURL:    typeURL,
		revertFunc: revertFunc,
	}
	cb.pendingCompletions[c] = pc
	return pc
}

// CompleteCompletionsThroughGeneration completes pending updates superseded when
// the cache successfully lands on a version Envoy has already accepted. These
// updates were created no later than generation, but no response was sent for
// them and no future response can complete them.
func (cb *CompletionCallbacks) CompleteCompletionsThroughGeneration(nodeID, typeURL string, generation uint64, err error) {
	var completed []*completion.Completion

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.nodeID != nodeID || pc.typeURL != typeURL || pc.generation > generation {
			continue
		}
		completed = append(completed, c)
		delete(cb.pendingCompletions, c)
	}
	cb.mutex.Unlock()

	for _, c := range completed {
		c.Complete(err)
	}
}

// AddTypeGenerationCompletion registers a completion for a type/generation update.
// It returns (false, err) when no future xDS ACK is expected and the caller
// should complete the passed completion immediately after SetSnapshot succeeds.
func (cb *CompletionCallbacks) AddTypeGenerationCompletion(c *completion.Completion, generation uint64, version string, typeURL string, nodeID string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if _, ok := cb.pendingCompletions[c]; ok {
		cb.Log.Warn("Reusing existing completion",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, version,
			"generation", generation,
			logfields.NodeID, nodeID)
		return true, nil
	}

	key := completionKey(nodeID, typeURL)
	state := cb.responseStates[key]

	if version != "" && state.pendingVersion == version {
		// The response was already sent, but the ACK/NACK has not arrived yet.
		// Attach an unchanged update directly to that response generation so its
		// in-flight ACK can complete it.
		if state.pendingGeneration == 0 {
			// An immediately available CreateWatch response is built with a
			// background context. Its generation can still be recovered from an
			// update waiting for that same content version.
			state.pendingGeneration = generation
			cb.responseStates[key] = state
		}
		// The cache can move A -> B -> A while the first A response is in
		// flight. Since Envoy is already consuming the final desired contents,
		// attach every intervening generation to that response as well.
		for _, pending := range cb.pendingCompletions {
			if pending.nodeID == nodeID && pending.typeURL == typeURL &&
				pending.generation <= generation {
				pending.responseGeneration = state.pendingGeneration
			}
		}
		pc := cb.addPendingCompletion(c, generation, version, typeURL, nodeID, revertFunc)
		pc.responseGeneration = state.pendingGeneration
		return true, nil
	}

	if version != "" && state.pendingVersion == "" && state.acceptedVersion == version {
		// Envoy is already at the final desired version. This covers both the
		// simple no-change case and A->B->A coalescing where B was never sent.
		return false, nil
	}

	if version != "" && state.pendingVersion == "" && !versionChanged && state.rejectedVersion == version {
		return false, state.rejectedErr
	}

	cb.addPendingCompletion(c, generation, version, typeURL, nodeID, revertFunc)
	return true, nil
}

// OnFetchRequest implements server.Callbacks.
func (cb *CompletionCallbacks) OnFetchRequest(context.Context, *discovery.DiscoveryRequest) error {
	return nil
}

// OnFetchResponse implements server.Callbacks.
func (cb *CompletionCallbacks) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}

// OnStreamDeltaRequest implements server.Callbacks.
func (cb *CompletionCallbacks) OnStreamDeltaRequest(int64, *discovery.DeltaDiscoveryRequest) error {
	return nil
}

// OnStreamDeltaResponse implements server.Callbacks.
func (cb *CompletionCallbacks) OnStreamDeltaResponse(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse) {
}

var _ sotw.Callbacks = (*CompletionCallbacks)(nil)

// OnStreamOpen is called once an xDS stream is open with a stream ID and the type URL (or "" for ADS).
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamOpen(ctx context.Context, streamID int64, typ string) error {
	return nil
}

// OnStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
func (cb *CompletionCallbacks) OnStreamClosed(streamID int64, node *core.Node) {
	cb.mutex.Lock()
	delete(cb.streamNodeIDs, streamID)
	cb.mutex.Unlock()

	cb.Log.Info("OnStreamClosed", logfields.XDSStreamID, streamID)
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	cb.mutex.Lock()
	nodeID := cb.nodeIDForRequest(streamID, req)
	if req.VersionInfo == "" {
		// This means this is the first request on the stream, so we can ignore it for completion purposes since there is no version to ACK.
		cb.mutex.Unlock()
		return nil
	}
	typeURL := req.GetTypeUrl()
	key := completionKey(nodeID, typeURL)

	type completionResult struct {
		completion *completion.Completion
		generation uint64
		revertFunc RevertFunc
	}
	var completed []completionResult

	if req.GetErrorDetail() != nil {
		state := cb.responseStates[key]
		rejectedVersion := state.pendingVersion
		rejectedGeneration := state.pendingGeneration
		if rejectedVersion == "" {
			rejectedVersion = req.GetVersionInfo()
		}
		nackErr := fmt.Errorf("NACK from %s for %s version %s: %s",
			nodeID, typeURL, rejectedVersion, req.GetErrorDetail().GetMessage())
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.acceptedVersion = req.GetVersionInfo()
		state.rejectedVersion = rejectedVersion
		state.rejectedErr = nackErr
		cb.responseStates[key] = state

		// A NACK rejects the entire response. Roll back every snapshot update
		// coalesced into it, newest first, to restore the last ACKed state.
		for c, pc := range cb.pendingCompletions {
			if pc.nodeID != nodeID || pc.typeURL != typeURL ||
				rejectedGeneration == 0 || pc.responseGeneration != rejectedGeneration {
				continue
			}
			completed = append(completed, completionResult{
				completion: c,
				generation: pc.generation,
				revertFunc: pc.revertFunc,
			})
			delete(cb.pendingCompletions, c)
		}
		slices.SortFunc(completed, func(a, b completionResult) int {
			switch {
			case a.generation > b.generation:
				return -1
			case a.generation < b.generation:
				return 1
			default:
				return 0
			}
		})

		if len(completed) > 0 {
			cb.Log.Warn(
				"NACK received, reverting resource changes",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, rejectedVersion,
				"generation", rejectedGeneration,
				logfields.NodeID, nodeID,
				logfields.Error, req.GetErrorDetail().GetMessage(),
			)
		}
		cb.mutex.Unlock()
		var expectedGeneration uint64
		for _, result := range completed {
			if expectedGeneration == 0 {
				expectedGeneration = result.generation
			}
			if result.revertFunc == nil {
				continue
			}
			var reverted bool
			expectedGeneration, reverted = result.revertFunc(expectedGeneration)
			if !reverted {
				break
			}
		}
		for _, result := range completed {
			result.completion.Complete(nackErr)
		}
		return nil
	}

	// ACK received: complete every update attached to this response generation.
	// OnStreamResponse attaches all earlier coalesced generations to the same
	// response, so no separate version-order data structure is needed here.
	state := cb.responseStates[key]
	var acceptedGeneration uint64
	if state.pendingVersion == req.GetVersionInfo() {
		acceptedGeneration = state.pendingGeneration
		state.pendingVersion = ""
		state.pendingGeneration = 0
	}
	state.acceptedVersion = req.GetVersionInfo()
	state.rejectedVersion = ""
	state.rejectedErr = nil
	cb.responseStates[key] = state

	for c, pc := range cb.pendingCompletions {
		if pc.nodeID != nodeID || pc.typeURL != typeURL ||
			acceptedGeneration == 0 || pc.responseGeneration != acceptedGeneration {
			continue
		}
		completed = append(completed, completionResult{completion: c, generation: pc.generation})
		delete(cb.pendingCompletions, c)
		cb.Log.Debug("Completed completion for type URL and generation",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, req.GetVersionInfo(),
			"generation", pc.generation)
	}
	cb.mutex.Unlock()

	for _, result := range completed {
		result.completion.Complete(nil)
	}
	return nil
}

// OnStreamResponse is called immediately prior to sending a response on a stream.
func (cb *CompletionCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	version := resp.GetVersionInfo()
	typeURL := resp.GetTypeUrl()

	var completed []*completion.Completion

	cb.mutex.Lock()
	nodeID := cb.nodeIDForRequest(streamID, req)
	key := completionKey(nodeID, typeURL)

	if version == "" {
		cb.mutex.Unlock()
		return
	}

	// SetSnapshot propagates the exact generation through the response context.
	// CreateWatch uses a background context for an immediately available
	// snapshot, so fall back to the newest pending generation with the response's
	// content version in that case. The fallback does not establish ordering;
	// the selected numeric generation does.
	responseGeneration := snapshotGenerationFromContext(ctx)
	if responseGeneration == 0 {
		for _, pc := range cb.pendingCompletions {
			if pc.nodeID == nodeID && pc.typeURL == typeURL && pc.version == version &&
				pc.generation > responseGeneration {
				responseGeneration = pc.generation
			}
		}
	}
	if responseGeneration == 0 {
		for _, pc := range cb.pendingCompletions {
			if pc.nodeID == nodeID && pc.typeURL == typeURL && pc.version == "" &&
				pc.generation > responseGeneration {
				responseGeneration = pc.generation
			}
		}
	}

	// A response for generation G contains the finalized resource state after
	// every generation <= G. Attach that whole prefix to G. A later ACK/NACK can
	// now resolve it with an integer comparison instead of replaying hash order.
	for _, pc := range cb.pendingCompletions {
		if pc.nodeID == nodeID && pc.typeURL == typeURL && pc.generation <= responseGeneration {
			pc.responseGeneration = responseGeneration
		}
	}

	state := cb.responseStates[key]
	if state.pendingVersion == "" && state.acceptedVersion == version {
		state.rejectedVersion = ""
		state.rejectedErr = nil
		cb.responseStates[key] = state

		for c, pc := range cb.pendingCompletions {
			if responseGeneration != 0 && pc.typeURL == typeURL && pc.nodeID == nodeID &&
				pc.responseGeneration == responseGeneration {
				completed = append(completed, c)
				delete(cb.pendingCompletions, c)
			}
		}
		cb.mutex.Unlock()

		for _, c := range completed {
			c.Complete(nil)
		}
		return
	}

	state.pendingVersion = version
	state.pendingGeneration = responseGeneration
	if state.rejectedVersion == version {
		state.rejectedVersion = ""
		state.rejectedErr = nil
	}
	cb.responseStates[key] = state
	cb.mutex.Unlock()
}

func (cb *CompletionCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	panic("unimplemented")
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb *CompletionCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	panic("unimplemented")
}
