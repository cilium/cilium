// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
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
	// pendingGenerations records resource-changing snapshot generations while a
	// completion for the same node and type is outstanding. Unlike the old
	// version ordering, the generation is both the identity and the order.
	pendingGenerations map[string]map[uint64]*pendingGeneration
	// publishedSnapshots lets an immediately available CreateWatch response,
	// whose context is not inherited from SetSnapshot, recover the generation of
	// the current snapshot without inserting version-only ordering markers.
	publishedSnapshots map[string]publishedSnapshot
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
		pendingGenerations: make(map[string]map[uint64]*pendingGeneration),
		publishedSnapshots: make(map[string]publishedSnapshot),
		responseStates:     make(map[string]responseState),
		streamNodeIDs:      make(map[int64]string),
	}
}

type publishedSnapshot struct {
	generation uint64
	snapshot   cache.ResourceSnapshot
}

type responseState struct {
	// pendingVersion is the version in the most recent response for which we have
	// not yet observed an ACK or NACK.
	pendingVersion    string
	pendingGeneration uint64
	// go-control-plane invokes this callback before rejecting a stale nonce.
	// Match requests to the exact response and stream here as well so an old
	// ACK/NACK cannot resolve a newer generation.
	pendingNonce    string
	pendingStreamID int64
	// acceptedVersion is the version Envoy most recently ACKed for this type.
	acceptedVersion string
	// rejectedVersion/rejectedErr remember the latest NACKed version so a
	// no-change update for that same cache state can fail immediately.
	rejectedVersion string
	rejectedErr     error
}

// pendingCompletion is an update that is pending completion.
type pendingCompletion struct {
	callbacks *CompletionCallbacks
	key       string
	nodeID    string
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
	// revertFunc restores the tracked update on NACK. Updates without a
	// completion are represented separately in pendingGenerations.
	revertFunc RevertFunc
}

func (pc *pendingCompletion) ID() string {
	return fmt.Sprintf("nodeID:%s,typeURL:%s,generation:%d", pc.nodeID, pc.typeURL, pc.generation)
}

func (pc *pendingCompletion) CleanupAfterWait(c *completion.Completion) {
	pc.callbacks.RemoveTypeGenerationCompletion(c)
}

// pendingGeneration is a resource-changing snapshot generation which may be
// folded into a later response. It is separate from pendingCompletion because
// not every update has a WaitGroup, but every coalesced update must be reverted
// if the response containing it is NACKed.
type pendingGeneration struct {
	generation         uint64
	responseGeneration uint64
	revertFunc         RevertFunc
}

// hasPendingCompletion reports whether an ACK/NACK waiter exists for key.
// cb.mutex must be held.
func (cb *CompletionCallbacks) hasPendingCompletion(key string) bool {
	for _, pc := range cb.pendingCompletions {
		if pc.key == key {
			return true
		}
	}
	return false
}

// prunePendingGenerations removes rollback/order state once no waiter can
// consume it. cb.mutex must be held.
func (cb *CompletionCallbacks) prunePendingGenerations(key string) {
	if !cb.hasPendingCompletion(key) {
		delete(cb.pendingGenerations, key)
	}
}

func (cb *CompletionCallbacks) RemoveTypeGenerationCompletion(c *completion.Completion) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	pc, ok := cb.pendingCompletions[c]
	if !ok {
		return
	}
	delete(cb.pendingCompletions, c)
	cb.prunePendingGenerations(pc.key)
}

// NewTypeGenerationCompletionOwner returns an owner which drops callback state
// if its WaitGroup ends before Envoy ACKs or NACKs the generation.
func (cb *CompletionCallbacks) NewTypeGenerationCompletionOwner(nodeID, typeURL string, generation uint64) completion.Owner {
	return &pendingCompletion{
		callbacks:  cb,
		key:        completionKey(nodeID, typeURL),
		nodeID:     nodeID,
		typeURL:    typeURL,
		generation: generation,
	}
}

// CancelPendingCompletions completes all pending completions for the given type URL
// without an error, to unblock any waiters. This is used when the last proxy listener
// is removed, meaning Envoy will never ACK the pending updates. Completing with nil
// mirrors the behavior of the old xDS server, since there is nothing to do even if
// an error status was used instead.
func (cb *CompletionCallbacks) CancelPendingCompletions(typeURL string) {
	var completed []*completion.Completion

	cb.mutex.Lock()
	keys := make(map[string]struct{})
	for c, pc := range cb.pendingCompletions {
		if pc.typeURL == typeURL {
			cb.Log.Debug("Cancelling pending completion",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, pc.version,
				"generation", pc.generation,
				logfields.NodeID, pc.nodeID)
			completed = append(completed, c)
			delete(cb.pendingCompletions, c)
			keys[pc.key] = struct{}{}
		}
	}
	for key := range keys {
		cb.prunePendingGenerations(key)
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
func (cb *CompletionCallbacks) addPendingCompletion(c *completion.Completion, pending *pendingCompletion, key string, generation uint64, version string, typeURL string, nodeID string, revertFunc RevertFunc) *pendingCompletion {
	if cb.Log.Enabled(context.Background(), slog.LevelDebug) {
		cb.Log.Debug("Adding pending completion for type URL and generation",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, version,
			"generation", generation,
			logfields.NodeID, nodeID)
	}
	if pending == nil {
		pending = &pendingCompletion{callbacks: cb}
	}
	pending.key = key
	pending.nodeID = nodeID
	pending.version = version
	pending.generation = generation
	pending.typeURL = typeURL
	pending.revertFunc = revertFunc
	cb.pendingCompletions[c] = pending
	return pending
}

// CompleteCompletionsThroughGeneration completes pending updates superseded when
// the cache successfully lands on a version Envoy has already accepted. These
// updates were created no later than generation, but no response was sent for
// them and no future response can complete them.
func (cb *CompletionCallbacks) CompleteCompletionsThroughGeneration(nodeID, typeURL string, generation uint64, err error) {
	var completed []*completion.Completion
	key := completionKey(nodeID, typeURL)

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.key != key || pc.generation > generation {
			continue
		}
		completed = append(completed, c)
		delete(cb.pendingCompletions, c)
	}
	for pendingGeneration := range cb.pendingGenerations[key] {
		if pendingGeneration <= generation {
			delete(cb.pendingGenerations[key], pendingGeneration)
		}
	}
	cb.prunePendingGenerations(key)
	cb.mutex.Unlock()

	for _, c := range completed {
		c.Complete(err)
	}
}

// SetPublishedSnapshot records the authoritative snapshot generation for a
// node. Cache.UpdateResources stages this before SetSnapshot so a concurrent
// CreateWatch can recover the generation, and restores the previous value if
// publication fails.
func (cb *CompletionCallbacks) SetPublishedSnapshot(nodeID string, generation uint64, snapshot cache.ResourceSnapshot) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if snapshot == nil {
		delete(cb.publishedSnapshots, nodeID)
		return
	}
	cb.publishedSnapshots[nodeID] = publishedSnapshot{
		generation: generation,
		snapshot:   snapshot,
	}
}

// AddTypeGeneration records a resource-changing generation while an older or
// current completion is pending. It returns completeUnsent when the new
// generation returns to an already accepted version and therefore cannot
// produce a response of its own.
func (cb *CompletionCallbacks) AddTypeGeneration(generation uint64, version, typeURL, nodeID string, versionChanged bool, revertFunc RevertFunc) (registered, completeUnsent bool) {
	if !versionChanged {
		return false, false
	}

	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	return cb.addTypeGeneration(generation, version, typeURL, nodeID, revertFunc)
}

// FinalizeTypeGeneration supplies the content version which was deliberately
// left unknown while resource updates were staged. It also resolves the cases
// where no new response can be produced because Envoy is already processing or
// has already accepted the finalized contents.
//
// The caller must only complete generations when complete is true after the
// finalized snapshot has been installed successfully.
func (cb *CompletionCallbacks) FinalizeTypeGeneration(nodeID, typeURL string, generation uint64, version string, versionChanged bool) (complete bool, err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	key := completionKey(nodeID, typeURL)
	for _, pending := range cb.pendingCompletions {
		if pending.key == key && pending.generation <= generation {
			pending.version = version
		}
	}

	state := cb.responseStates[key]
	if version != "" && state.pendingVersion == version {
		for _, pending := range cb.pendingCompletions {
			if pending.key == key && pending.generation <= generation {
				pending.responseGeneration = state.pendingGeneration
			}
		}
		for _, pending := range cb.pendingGenerations[key] {
			if pending.generation <= generation {
				pending.responseGeneration = state.pendingGeneration
			}
		}
		return false, nil
	}

	if version != "" && state.pendingVersion == "" && state.acceptedVersion == version {
		return true, nil
	}
	if version != "" && state.pendingVersion == "" && !versionChanged && state.rejectedVersion == version {
		return true, state.rejectedErr
	}
	return false, nil
}

// addTypeGeneration implements AddTypeGeneration with cb.mutex held.
func (cb *CompletionCallbacks) addTypeGeneration(generation uint64, version, typeURL, nodeID string, revertFunc RevertFunc) (registered, completeUnsent bool) {
	key := completionKey(nodeID, typeURL)
	if !cb.hasPendingCompletion(key) {
		return false, false
	}
	// A tracked update already carries its own revert function. Avoid recording
	// the same generation twice when staged rollback history is registered at
	// finalization. AwaitCurrentVersion completions have no revert function, so
	// retain a non-nil staged revert alongside those completions.
	for _, pending := range cb.pendingCompletions {
		if pending.key == key && pending.generation == generation &&
			(revertFunc == nil || pending.revertFunc != nil) {
			return false, false
		}
	}

	state := cb.responseStates[key]
	if version != "" && state.pendingVersion == "" && state.acceptedVersion == version {
		return false, true
	}

	generations := cb.pendingGenerations[key]
	if generations == nil {
		generations = make(map[uint64]*pendingGeneration)
		cb.pendingGenerations[key] = generations
	}
	pending := generations[generation]
	if pending == nil {
		pending = &pendingGeneration{generation: generation}
		generations[generation] = pending
	}
	if revertFunc != nil {
		pending.revertFunc = revertFunc
	}

	if version != "" && state.pendingVersion == version {
		if state.pendingGeneration == 0 {
			state.pendingGeneration = generation
			cb.responseStates[key] = state
		}
		for _, pc := range cb.pendingCompletions {
			if pc.nodeID == nodeID && pc.typeURL == typeURL && pc.generation <= generation {
				pc.responseGeneration = state.pendingGeneration
			}
		}
		for _, pg := range generations {
			if pg.generation <= generation {
				pg.responseGeneration = state.pendingGeneration
			}
		}
	}

	if cb.Log.Enabled(context.Background(), slog.LevelDebug) {
		cb.Log.Debug("Added pending snapshot generation",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, version,
			"generation", generation,
			logfields.NodeID, nodeID)
	}
	return true, false
}

// RemoveTypeGeneration removes a generation which was staged for a snapshot
// that was not published.
func (cb *CompletionCallbacks) RemoveTypeGeneration(nodeID, typeURL string, generation uint64) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	key := completionKey(nodeID, typeURL)
	delete(cb.pendingGenerations[key], generation)
	cb.prunePendingGenerations(key)
}

// AddTypeGenerationCompletion registers a completion for a type/generation update.
// It returns (false, err) when no future xDS ACK is expected and the caller
// should complete the passed completion immediately after SetSnapshot succeeds.
func (cb *CompletionCallbacks) AddTypeGenerationCompletion(c *completion.Completion, generation uint64, version string, typeURL string, nodeID string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
	return cb.addTypeGenerationCompletion(c, nil, generation, version, typeURL, nodeID, versionChanged, revertFunc)
}

// AddPreparedTypeGenerationCompletion registers a completion using the object
// already allocated as its completion.Owner, avoiding a second hot-path
// allocation for callback bookkeeping.
func (cb *CompletionCallbacks) AddPreparedTypeGenerationCompletion(c *completion.Completion, owner completion.Owner, version string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
	pending, ok := owner.(*pendingCompletion)
	if !ok || pending.callbacks != cb {
		return false, fmt.Errorf("invalid type generation completion owner")
	}
	return cb.addTypeGenerationCompletion(c, pending, pending.generation, version, pending.typeURL, pending.nodeID, versionChanged, revertFunc)
}

func (cb *CompletionCallbacks) addTypeGenerationCompletion(c *completion.Completion, pending *pendingCompletion, generation uint64, version string, typeURL string, nodeID string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
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
	if pending != nil {
		key = pending.key
	}
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
		pc := cb.addPendingCompletion(c, pending, key, generation, version, typeURL, nodeID, revertFunc)
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

	cb.addPendingCompletion(c, pending, key, generation, version, typeURL, nodeID, revertFunc)
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
	nodeID := cb.streamNodeIDs[streamID]
	if nodeID == "" && node != nil {
		nodeID = node.GetId()
	}
	delete(cb.streamNodeIDs, streamID)

	streamStillOpen := false
	for _, openNodeID := range cb.streamNodeIDs {
		if openNodeID == nodeID {
			streamStillOpen = true
			break
		}
	}
	if nodeID != "" && !streamStillOpen {
		prefix := nodeID + "\x00"
		for key, state := range cb.responseStates {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			state.pendingVersion = ""
			state.pendingGeneration = 0
			state.pendingNonce = ""
			state.pendingStreamID = 0
			state.acceptedVersion = ""
			cb.responseStates[key] = state
		}
	}
	cb.mutex.Unlock()

	cb.Log.Info("OnStreamClosed", logfields.XDSStreamID, streamID)
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	cb.mutex.Lock()
	nodeID := cb.nodeIDForRequest(streamID, req)
	typeURL := req.GetTypeUrl()
	key := completionKey(nodeID, typeURL)
	if req.GetVersionInfo() == "" && req.GetResponseNonce() == "" && req.GetErrorDetail() == nil {
		// This is a fresh subscription, not an ACK or NACK. Any accepted
		// version belongs to an earlier Envoy process.
		state := cb.responseStates[key]
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.pendingNonce = ""
		state.pendingStreamID = 0
		state.acceptedVersion = ""
		cb.responseStates[key] = state
		cb.mutex.Unlock()
		return nil
	}

	state := cb.responseStates[key]
	if req.GetResponseNonce() != "" &&
		(state.pendingNonce == "" || state.pendingStreamID != streamID || state.pendingNonce != req.GetResponseNonce()) {
		cb.Log.Debug("Ignoring stale xDS ACK/NACK",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, req.GetVersionInfo(),
			logfields.NodeID, nodeID)
		cb.mutex.Unlock()
		return nil
	}

	type completionResult struct {
		completion *completion.Completion
		generation uint64
	}
	var completed []completionResult

	if req.GetErrorDetail() != nil {
		type generationRevert struct {
			generation uint64
			revertFunc RevertFunc
		}
		var generationReverts []generationRevert
		rejectedVersion := state.pendingVersion
		rejectedGeneration := state.pendingGeneration
		if rejectedVersion == "" {
			rejectedVersion = req.GetVersionInfo()
		}
		nackErr := fmt.Errorf("NACK from %s for %s version %s: %s",
			nodeID, typeURL, rejectedVersion, req.GetErrorDetail().GetMessage())
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.pendingNonce = ""
		state.pendingStreamID = 0
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
			})
			generationReverts = append(generationReverts, generationRevert{
				generation: pc.generation,
				revertFunc: pc.revertFunc,
			})
			delete(cb.pendingCompletions, c)
		}

		for generation, pending := range cb.pendingGenerations[key] {
			if rejectedGeneration == 0 || pending.responseGeneration != rejectedGeneration {
				continue
			}
			generationReverts = append(generationReverts, generationRevert{
				generation: pending.generation,
				revertFunc: pending.revertFunc,
			})
			delete(cb.pendingGenerations[key], generation)
		}
		slices.SortFunc(generationReverts, func(a, b generationRevert) int {
			switch {
			case a.generation > b.generation:
				return -1
			case a.generation < b.generation:
				return 1
			default:
				return 0
			}
		})

		cb.prunePendingGenerations(key)

		if len(completed) > 0 || len(generationReverts) > 0 {
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
		expectedGeneration := rejectedGeneration
		for _, pending := range generationReverts {
			if pending.revertFunc == nil {
				continue
			}
			var reverted bool
			expectedGeneration, reverted = pending.revertFunc(expectedGeneration)
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
	var acceptedGeneration uint64
	if state.pendingVersion == req.GetVersionInfo() {
		acceptedGeneration = state.pendingGeneration
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.pendingNonce = ""
		state.pendingStreamID = 0
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
	for generation, pending := range cb.pendingGenerations[key] {
		if acceptedGeneration != 0 && pending.responseGeneration == acceptedGeneration {
			delete(cb.pendingGenerations[key], generation)
		}
	}
	cb.prunePendingGenerations(key)
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
	// snapshot, so recover the generation from the authoritative snapshot state
	// staged by Cache.UpdateResources. The content version check prevents a
	// delayed response from being attributed to a newer snapshot.
	responseGeneration := snapshotGenerationFromContext(ctx)
	if responseGeneration == 0 {
		if published, ok := cb.publishedSnapshots[nodeID]; ok &&
			published.snapshot != nil && published.snapshot.GetVersion(typeURL) == version {
			responseGeneration = published.generation
		}
	}
	// Keep a narrow fallback for callback unit tests and response paths that do
	// not originate in Cache.UpdateResources.
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
	for _, pending := range cb.pendingGenerations[key] {
		if pending.generation <= responseGeneration {
			pending.responseGeneration = responseGeneration
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
		for generation, pending := range cb.pendingGenerations[key] {
			if responseGeneration != 0 && pending.responseGeneration == responseGeneration {
				delete(cb.pendingGenerations[key], generation)
			}
		}
		cb.prunePendingGenerations(key)
		cb.mutex.Unlock()

		for _, c := range completed {
			c.Complete(nil)
		}
		return
	}

	state.pendingVersion = version
	state.pendingGeneration = responseGeneration
	state.pendingNonce = resp.GetNonce()
	state.pendingStreamID = streamID
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
