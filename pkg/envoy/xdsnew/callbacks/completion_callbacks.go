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
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = typeurl.NetworkPolicyURL
	NetworkPolicyHostsTypeURL = typeurl.NetworkPolicyHostsURL
)

type snapshotGenerationContextKey struct{}

type streamResetContextKey struct{}

// WithSnapshotGeneration associates an xDS response with the generation of
// the snapshot from which go-control-plane constructed it.
func WithSnapshotGeneration(ctx context.Context, generation uint64) context.Context {
	return context.WithValue(ctx, snapshotGenerationContextKey{}, generation)
}

func snapshotGenerationFromContext(ctx context.Context) uint64 {
	generation, _ := ctx.Value(snapshotGenerationContextKey{}).(uint64)
	return generation
}

// WithStreamReset marks a response as belonging to the transport-only empty
// snapshot used to resynchronize one ADS stream. Such responses must not
// accept, reject, or otherwise modify desired cache generations.
func WithStreamReset(ctx context.Context, streamID int64) context.Context {
	return context.WithValue(ctx, streamResetContextKey{}, streamID)
}

// RevertFunc restores the resources in one update which have not been
// superseded by newer resource generations. It returns the current node
// generation, which can be passed to the next older RevertFunc in a rollback
// chain, and whether it restored at least one resource.
type RevertFunc func(expectedGeneration uint64) (generation uint64, reverted bool)

// FinalizeFunc releases rollback state after the corresponding update can no
// longer be reverted.
type FinalizeFunc func()

// Rollback is the lifecycle of rollback state for one resource update.
// Exactly one of Revert or Finalize is called after the rollback is registered.
type Rollback interface {
	Revert(expectedGeneration uint64) (generation uint64, reverted bool)
	Finalize()
}

type funcRollback struct {
	revert   RevertFunc
	finalize FinalizeFunc
}

func (rollback *funcRollback) Revert(expectedGeneration uint64) (uint64, bool) {
	if rollback.revert == nil {
		rollback.Finalize()
		return expectedGeneration, false
	}
	return rollback.revert(expectedGeneration)
}

func (rollback *funcRollback) Finalize() {
	if rollback.finalize != nil {
		rollback.finalize()
	}
}

func newRollback(revert RevertFunc, finalize FinalizeFunc) Rollback {
	if revert == nil && finalize == nil {
		return nil
	}
	return &funcRollback{revert: revert, finalize: finalize}
}

// nodeIDForRequest returns the request node ID, falling back to the node ID
// remembered from the first request on the stream. cb.mutex must be held.
func (cb *CompletionCallbacks) nodeIDForRequest(streamID int64, req *discovery.DiscoveryRequest) string {
	stream := cb.ensureStreamState(streamID)
	stream.request = req
	if nodeID := req.GetNode().GetId(); nodeID != "" {
		stream.nodeID = nodeID
		return nodeID
	}
	return stream.nodeID
}

type CompletionCallbacks struct {
	Log *slog.Logger

	// mutex protects all fields below. go-control-plane invokes stream
	// callbacks outside the ADS server mutex, while cache updates register
	// completions from Cilium-owned paths.
	mutex lock.Mutex

	// pendingCompletions is the list of updates that are pending completion.
	pendingCompletions map[*completion.Completion]*pendingCompletion
	// nodes groups response and rollback bookkeeping first by node ID and then
	// by TypeURL. Keeping related state together avoids parallel maps with the
	// same composite keys.
	nodes map[string]*callbackNodeState
	// streams remember the node ID and latest request for each ADS stream.
	// Envoy is configured with SetNodeOnFirstMessageOnly, so subsequent ACK/NACK
	// requests can omit Node. The latest request also lets Cache.CreateWatch
	// recover the stream ID, which go-control-plane does not otherwise expose to
	// its cache interface.
	streams map[int64]*callbackStreamState
	// streamClosed is invoked without mutex held so the cache can discard the
	// synthetic snapshot of a stream which closes during a soft reset.
	streamClosed func(streamID int64)
}

func NewCompletionCallbacks(logger *slog.Logger) *CompletionCallbacks {
	return &CompletionCallbacks{
		Log:                logger,
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
		nodes:              make(map[string]*callbackNodeState),
		streams:            make(map[int64]*callbackStreamState),
	}
}

// StreamResetPhase is the cache-visible phase of a stream-local soft reset.
// The zero value is the ordinary live-cache path.
type StreamResetPhase uint8

const (
	StreamResetInactive StreamResetPhase = iota
	StreamResetRequested
	StreamResetting
	StreamResetComplete
	streamResetFailed
)

type callbackStreamState struct {
	nodeID  string
	request *discovery.DiscoveryRequest

	softResetEligible    bool
	listenerSynchronized bool
	resetAttempted       bool
	resetPhase           StreamResetPhase
	resetResponseNonce   string
}

func (cb *CompletionCallbacks) ensureStreamState(streamID int64) *callbackStreamState {
	state := cb.streams[streamID]
	if state == nil {
		state = &callbackStreamState{}
		cb.streams[streamID] = state
	}
	return state
}

// SetStreamClosedCallback installs the cache-side cleanup invoked after an ADS
// stream closes. It is configured once while constructing the cache.
func (cb *CompletionCallbacks) SetStreamClosedCallback(callback func(streamID int64)) {
	cb.mutex.Lock()
	cb.streamClosed = callback
	cb.mutex.Unlock()
}

// StreamResetStateForRequest maps the request passed to CreateWatch back to its
// ADS stream and reports whether that stream is entering or leaving a reset.
// go-control-plane numbers real streams from one, so stream ID zero means the
// request was not associated with a stream callback.
func (cb *CompletionCallbacks) StreamResetStateForRequest(req *discovery.DiscoveryRequest) (int64, StreamResetPhase) {
	if req == nil {
		return 0, StreamResetInactive
	}
	typeURL, supported := typeurl.FromURL(req.GetTypeUrl())
	if !supported || typeURL != typeurl.Listener {
		return 0, StreamResetInactive
	}

	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	for streamID, state := range cb.streams {
		if state.request == req {
			if state.resetPhase == StreamResetRequested ||
				state.resetPhase == StreamResetting ||
				state.resetPhase == StreamResetComplete {
				return streamID, state.resetPhase
			}
			return streamID, StreamResetInactive
		}
	}
	return 0, StreamResetInactive
}

// BeginStreamReset starts the empty snapshot barrier for the LDS response
// whose initial synchronization was NACKed. All resource types on which
// draining listeners may depend remain on the live cache.
func (cb *CompletionCallbacks) BeginStreamReset(streamID int64) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	stream := cb.streams[streamID]
	if stream == nil || stream.resetPhase != StreamResetRequested {
		return false
	}
	if nodeState := cb.nodeState(stream.nodeID); nodeState != nil {
		typeState := &nodeState.typeURLs[typeurl.Listener]
		// The empty snapshot is deliberately not an accepted desired snapshot.
		// Prevent updates racing the reset from treating the old Listener state
		// as already accepted.
		typeState.response.acceptedVersion = ""
		typeState.acceptedSnapshot = nil
	}
	stream.resetPhase = StreamResetting
	return true
}

// FinishStreamReset returns the stream to the authoritative cache after every
// reset response has been ACKed. The one-attempt guard remains set for the
// lifetime of the stream.
func (cb *CompletionCallbacks) FinishStreamReset(streamID int64) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	stream := cb.streams[streamID]
	if stream == nil || stream.resetPhase != StreamResetComplete {
		return false
	}
	stream.resetPhase = StreamResetInactive
	stream.resetResponseNonce = ""
	return true
}

// AbortStreamReset prevents a failed setup from being retried on the same
// stream. Stream closure releases all remaining state.
func (cb *CompletionCallbacks) AbortStreamReset(streamID int64) {
	cb.mutex.Lock()
	if stream := cb.streams[streamID]; stream != nil {
		stream.resetPhase = streamResetFailed
	}
	cb.mutex.Unlock()
}

type callbackNodeState struct {
	// published lets an immediately available CreateWatch response, whose
	// context is not inherited from SetSnapshot, recover the generation of the
	// current snapshot without inserting version-only ordering markers.
	published publishedSnapshot
	typeURLs  typeurl.Slots[typeURLState]
}

type typeURLState struct {
	// pendingGenerations records resource-changing snapshot generations until
	// the response carrying them is ACKed, NACKed, or otherwise proven not to
	// need a response. Their lifetime is deliberately independent from caller
	// completions: a caller may stop waiting before Envoy consumes the response,
	// and updates without a WaitGroup must still be reverted on NACK.
	pendingGenerations map[uint64]*pendingGeneration
	// acceptedSnapshot retains the immutable snapshot last ACKed for this
	// node/type. This permits resource-level no-op checks while another resource
	// of the same type is pending.
	acceptedSnapshot cache.ResourceSnapshot
	// response tracks the latest xDS response/ACK state for this node/type.
	// Generations establish ordering; versions are retained only because Envoy
	// echoes the content version in ACK and NACK requests.
	response responseState
}

// nodeState returns existing callback state for nodeID. cb.mutex must be held.
func (cb *CompletionCallbacks) nodeState(nodeID string) *callbackNodeState {
	return cb.nodes[nodeID]
}

// ensureNodeState returns callback state for nodeID, creating it when needed.
// cb.mutex must be held.
func (cb *CompletionCallbacks) ensureNodeState(nodeID string) *callbackNodeState {
	state := cb.nodes[nodeID]
	if state == nil {
		state = &callbackNodeState{}
		cb.nodes[nodeID] = state
	}
	return state
}

func (state *callbackNodeState) typeURLState(index typeurl.Index) *typeURLState {
	if state == nil {
		return nil
	}
	return &state.typeURLs[index]
}

// typeURLState returns existing callback state for nodeID and index.
// cb.mutex must be held.
func (cb *CompletionCallbacks) typeURLState(nodeID string, index typeurl.Index) *typeURLState {
	return cb.nodeState(nodeID).typeURLState(index)
}

// ensureTypeURLState returns callback state for nodeID and index, creating the
// node level when needed. cb.mutex must be held.
func (cb *CompletionCallbacks) ensureTypeURLState(nodeID string, index typeurl.Index) *typeURLState {
	return cb.ensureNodeState(nodeID).typeURLState(index)
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
	typeURL typeurl.Index
	// rollback restores the tracked update on NACK. Updates without a
	// completion are represented separately in pendingGenerations.
	rollback Rollback
}

func (pc *pendingCompletion) ID() string {
	return fmt.Sprintf("nodeID:%s,typeURL:%s,generation:%d", pc.nodeID, pc.typeURL.URL(), pc.generation)
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
	rollback           Rollback
}

// hasPendingCompletion reports whether an ACK/NACK waiter exists for the
// node/type pair.
// cb.mutex must be held.
func (cb *CompletionCallbacks) hasPendingCompletion(nodeID string, typeURL typeurl.Index) bool {
	for _, pc := range cb.pendingCompletions {
		if pc.nodeID == nodeID && pc.typeURL == typeURL {
			return true
		}
	}
	return false
}

// removeEmptyPendingGenerationSet releases only the empty per-type container.
// Individual generations are response-owned and must not be pruned merely
// because their caller stopped waiting for an ACK or NACK.
func (state *typeURLState) removeEmptyPendingGenerationSet() {
	if state == nil {
		return
	}
	if len(state.pendingGenerations) == 0 {
		state.pendingGenerations = nil
	}
}

// RemoveTypeGenerationCompletion stops notifying one caller. Published
// generation rollback state remains live until its xDS response terminates.
func (cb *CompletionCallbacks) RemoveTypeGenerationCompletion(c *completion.Completion) {
	cb.mutex.Lock()
	pc, ok := cb.pendingCompletions[c]
	if !ok {
		cb.mutex.Unlock()
		return
	}
	delete(cb.pendingCompletions, c)
	var finalize FinalizeFunc
	if pc.rollback != nil {
		finalize = pc.rollback.Finalize
	}
	cb.mutex.Unlock()
	if finalize != nil {
		finalize()
	}
}

// NewTypeGenerationCompletionOwner returns an owner which drops callback state
// if its WaitGroup ends before Envoy ACKs or NACKs the generation.
func (cb *CompletionCallbacks) NewTypeGenerationCompletionOwner(nodeID string, typeURL typeurl.Index, generation uint64) completion.Owner {
	return &pendingCompletion{
		callbacks:  cb,
		nodeID:     nodeID,
		typeURL:    typeURL,
		generation: generation,
	}
}

// CancelPendingCompletions completes all pending completions for the given type
// URL without an error, to unblock any waiters. This is used when the last proxy
// listener is removed, meaning Cilium must not wait for a policy ACK. It does not
// discard response-owned rollback state: an already-sent response may still be
// NACKed, or its state may be carried by a response after Envoy reconnects.
// Completing with nil mirrors the behavior of the old xDS server.
func (cb *CompletionCallbacks) CancelPendingCompletions(typeURL typeurl.Index) {
	var completed []*completion.Completion
	var finalizers []FinalizeFunc

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.typeURL == typeURL {
			cb.Log.Debug("Cancelling pending completion",
				logfields.XDSTypeURL, typeURL.URL(),
				logfields.Version, pc.version,
				logfields.XDSGeneration, pc.generation,
				logfields.NodeID, pc.nodeID)
			completed = append(completed, c)
			delete(cb.pendingCompletions, c)
			if pc.rollback != nil {
				finalizers = append(finalizers, pc.rollback.Finalize)
			}
		}
	}
	cb.mutex.Unlock()

	for _, finalize := range finalizers {
		finalize()
	}
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
func (cb *CompletionCallbacks) addPendingCompletion(c *completion.Completion, pending *pendingCompletion, generation uint64, version string, typeURL typeurl.Index, nodeID string, rollback Rollback) *pendingCompletion {
	if cb.Log.Enabled(context.Background(), slog.LevelDebug) {
		cb.Log.Debug("Adding pending completion for type URL and generation",
			logfields.XDSTypeURL, typeURL.URL(),
			logfields.Version, version,
			logfields.XDSGeneration, generation,
			logfields.NodeID, nodeID)
	}
	if pending == nil {
		pending = &pendingCompletion{callbacks: cb}
	}
	pending.nodeID = nodeID
	pending.version = version
	pending.generation = generation
	pending.typeURL = typeURL
	pending.rollback = rollback
	cb.pendingCompletions[c] = pending
	return pending
}

// CompleteWaitersThroughGeneration completes callers through generation
// without accepting or discarding response-owned rollback state. It is used
// when Cilium does not need to wait for an ACK even though an already-sent
// response may still be NACKed.
func (cb *CompletionCallbacks) CompleteWaitersThroughGeneration(nodeID string, typeURL typeurl.Index, generation uint64, err error) {
	cb.completeThroughGeneration(nodeID, typeURL, generation, err, false)
}

// CompleteCompletionsThroughGeneration completes pending updates superseded
// when the cache successfully lands on a version Envoy has already accepted.
// These updates were created no later than generation, but no response was sent
// for them and no future response can complete them. Response-owned rollback
// state through generation is finalized as accepted.
func (cb *CompletionCallbacks) CompleteCompletionsThroughGeneration(nodeID string, typeURL typeurl.Index, generation uint64, err error) {
	cb.completeThroughGeneration(nodeID, typeURL, generation, err, true)
}

func (cb *CompletionCallbacks) completeThroughGeneration(nodeID string, typeURL typeurl.Index, generation uint64, err error, finalizeGenerations bool) {
	var completed []*completion.Completion
	var finalizers []FinalizeFunc

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.nodeID != nodeID || pc.typeURL != typeURL || pc.generation > generation {
			continue
		}
		completed = append(completed, c)
		delete(cb.pendingCompletions, c)
		if pc.rollback != nil {
			finalizers = append(finalizers, pc.rollback.Finalize)
		}
	}
	if finalizeGenerations {
		state := cb.typeURLState(nodeID, typeURL)
		if state != nil {
			for pendingGeneration, pending := range state.pendingGenerations {
				if pendingGeneration <= generation {
					if pending.rollback != nil {
						finalizers = append(finalizers, pending.rollback.Finalize)
					}
					delete(state.pendingGenerations, pendingGeneration)
				}
			}
			state.removeEmptyPendingGenerationSet()
		}
	}
	cb.mutex.Unlock()

	for _, finalize := range finalizers {
		finalize()
	}
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
		state := cb.nodeState(nodeID)
		if state == nil {
			return
		}
		state.published = publishedSnapshot{}
		for typeURL := range typeurl.Count {
			state.typeURLs[typeURL].acceptedSnapshot = nil
		}
		return
	}
	cb.ensureNodeState(nodeID).published = publishedSnapshot{
		generation: generation,
		snapshot:   snapshot,
	}
}

// ResourceAccepted reports whether one desired resource has the same contents
// in the snapshot most recently ACKed for nodeID and typeURL. The retained
// snapshots are immutable, so callers can pass their canonical cache pointer
// and make the common already-ACKed case a pointer comparison.
func (cb *CompletionCallbacks) ResourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, desired proto.Message, desiredExists bool) bool {
	return cb.resourceAccepted(nodeID, typeURL, resourceName, nil, false, desired, desiredExists, false)
}

// ChangedResourceAccepted reports whether a changed resource has the same
// contents in the most recently ACKed snapshot. previous is the cache value
// which the caller already established differs semantically from desired. If
// the accepted snapshot still owns that exact previous pointer, desired cannot
// be accepted and the expensive protobuf comparison is unnecessary.
func (cb *CompletionCallbacks) ChangedResourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, previous proto.Message, previousExists bool, desired proto.Message, desiredExists bool) bool {
	return cb.resourceAccepted(nodeID, typeURL, resourceName, previous, previousExists, desired, desiredExists, true)
}

func (cb *CompletionCallbacks) resourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, previous proto.Message, previousExists bool, desired proto.Message, desiredExists, desiredChanged bool) bool {
	cb.mutex.Lock()
	typeState := cb.typeURLState(nodeID, typeURL)
	var acceptedSnapshot cache.ResourceSnapshot
	if typeState != nil {
		acceptedSnapshot = typeState.acceptedSnapshot
	}
	cb.mutex.Unlock()
	if acceptedSnapshot == nil {
		return false
	}
	accepted, acceptedExists := acceptedSnapshot.GetResourcesAndTTL(typeURL.URL())[resourceName]
	if acceptedExists != desiredExists {
		return false
	}
	if desiredChanged && acceptedExists == previousExists &&
		(!previousExists || accepted.Resource == previous) {
		return false
	}
	return !desiredExists || accepted.Resource == desired || proto.Equal(accepted.Resource, desired)
}

// AddTypeGeneration records a resource-changing generation until the response
// carrying it reaches a protocol terminal state. It returns completeUnsent
// when the new generation returns to an already accepted version and therefore
// cannot produce a response of its own.
func (cb *CompletionCallbacks) AddTypeGeneration(generation uint64, version string, typeURL typeurl.Index, nodeID string, versionChanged bool, revertFunc RevertFunc) (registered, completeUnsent bool) {
	return cb.AddTypeGenerationWithRollback(generation, version, typeURL, nodeID, versionChanged, newRollback(revertFunc, nil))
}

// AddTypeGenerationWithRollback records a rollback lifecycle without splitting
// its terminal operations into separately allocated method values.
func (cb *CompletionCallbacks) AddTypeGenerationWithRollback(generation uint64, version string, typeURL typeurl.Index, nodeID string, versionChanged bool, rollback Rollback) (registered, completeUnsent bool) {
	if !versionChanged {
		return false, false
	}

	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	return cb.addTypeGeneration(generation, version, typeURL, nodeID, rollback)
}

// CoalesceUnsentTypeGeneration advances response-owned rollback state which
// has not yet been attached to a response. The same callbacks continue to own
// the coalesced state, now representing every update through newGeneration.
// It returns false if the generation is missing or has already been attached
// to a response and therefore can no longer be changed.
func (cb *CompletionCallbacks) CoalesceUnsentTypeGeneration(nodeID string, typeURL typeurl.Index, oldGeneration, newGeneration uint64) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	typeState := cb.typeURLState(nodeID, typeURL)
	if typeState == nil {
		return false
	}
	generations := typeState.pendingGenerations
	pending := generations[oldGeneration]
	if pending == nil || pending.responseGeneration != 0 {
		return false
	}
	if oldGeneration == newGeneration {
		return true
	}
	if generations[newGeneration] != nil {
		return false
	}
	delete(generations, oldGeneration)
	pending.generation = newGeneration
	generations[newGeneration] = pending
	return true
}

// FinalizeTypeGeneration supplies the content version which was deliberately
// left unknown while resource updates were staged. It also resolves the cases
// where no new response can be produced because Envoy is already processing or
// has already accepted the finalized contents.
//
// The caller must only complete generations when complete is true after the
// finalized snapshot has been installed successfully.
func (cb *CompletionCallbacks) FinalizeTypeGeneration(nodeID string, typeURL typeurl.Index, generation uint64, version string, versionChanged bool) (complete bool, err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	for _, pending := range cb.pendingCompletions {
		if pending.nodeID == nodeID && pending.typeURL == typeURL && pending.generation <= generation {
			pending.version = version
		}
	}

	typeState := cb.typeURLState(nodeID, typeURL)
	var state responseState
	if typeState != nil {
		state = typeState.response
	}
	if version != "" && state.pendingVersion == version {
		for _, pending := range cb.pendingCompletions {
			if pending.nodeID == nodeID && pending.typeURL == typeURL && pending.generation <= generation {
				pending.responseGeneration = state.pendingGeneration
			}
		}
		if typeState != nil {
			for _, pending := range typeState.pendingGenerations {
				if pending.generation <= generation {
					pending.responseGeneration = state.pendingGeneration
				}
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
func (cb *CompletionCallbacks) addTypeGeneration(generation uint64, version string, typeURL typeurl.Index, nodeID string, rollback Rollback) (registered, completeUnsent bool) {
	// Function-less generations are useful only as ordering state for an
	// outstanding completion. A cache-owned response rollback survives without
	// a waiter until its response is ACKed, NACKed, or proven unnecessary.
	if rollback == nil && !cb.hasPendingCompletion(nodeID, typeURL) {
		return false, false
	}
	// A tracked update may already carry its own rollback. Avoid recording
	// the same generation twice when staged rollback history is registered at
	// finalization. AwaitCurrentVersion completions have no rollback, so retain
	// a non-nil staged rollback alongside those completions.
	for _, pending := range cb.pendingCompletions {
		if pending.nodeID == nodeID && pending.typeURL == typeURL && pending.generation == generation &&
			(rollback == nil || pending.rollback != nil) {
			return false, false
		}
	}

	typeState := cb.typeURLState(nodeID, typeURL)
	if typeState != nil && version != "" &&
		typeState.response.pendingVersion == "" && typeState.response.acceptedVersion == version {
		return false, true
	}
	if typeState == nil {
		typeState = cb.ensureTypeURLState(nodeID, typeURL)
	}
	state := &typeState.response

	generations := typeState.pendingGenerations
	if generations == nil {
		generations = make(map[uint64]*pendingGeneration)
		typeState.pendingGenerations = generations
	}
	pending := generations[generation]
	if pending == nil {
		pending = &pendingGeneration{generation: generation}
		generations[generation] = pending
	}
	if rollback != nil {
		pending.rollback = rollback
	}

	if version != "" && state.pendingVersion == version {
		if state.pendingGeneration == 0 {
			state.pendingGeneration = generation
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
			logfields.XDSTypeURL, typeURL.URL(),
			logfields.Version, version,
			logfields.XDSGeneration, generation,
			logfields.NodeID, nodeID)
	}
	return true, false
}

// AddTypeGenerationCompletion registers a completion for a type/generation update.
// It returns (false, err) when no future xDS ACK is expected and the caller
// should complete the passed completion immediately after SetSnapshot succeeds.
func (cb *CompletionCallbacks) AddTypeGenerationCompletion(c *completion.Completion, generation uint64, version string, typeURL typeurl.Index, nodeID string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
	return cb.addTypeGenerationCompletion(c, nil, generation, version, typeURL, nodeID, versionChanged, newRollback(revertFunc, nil))
}

// AddPreparedTypeGenerationCompletion registers a completion using the object
// already allocated as its completion.Owner, avoiding a second hot-path
// allocation for callback bookkeeping.
func (cb *CompletionCallbacks) AddPreparedTypeGenerationCompletion(c *completion.Completion, owner completion.Owner, version string, versionChanged bool, revertFunc RevertFunc) (bool, error) {
	pending, ok := owner.(*pendingCompletion)
	if !ok || pending.callbacks != cb {
		return false, fmt.Errorf("invalid type generation completion owner")
	}
	return cb.addTypeGenerationCompletion(c, pending, pending.generation, version, pending.typeURL, pending.nodeID, versionChanged, newRollback(revertFunc, nil))
}

func (cb *CompletionCallbacks) addTypeGenerationCompletion(c *completion.Completion, pending *pendingCompletion, generation uint64, version string, typeURL typeurl.Index, nodeID string, versionChanged bool, rollback Rollback) (bool, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if _, ok := cb.pendingCompletions[c]; ok {
		cb.Log.Warn("Reusing existing completion",
			logfields.XDSTypeURL, typeURL.URL(),
			logfields.Version, version,
			logfields.XDSGeneration, generation,
			logfields.NodeID, nodeID)
		return true, nil
	}

	typeState := cb.ensureTypeURLState(nodeID, typeURL)
	state := &typeState.response

	if version != "" && state.pendingVersion == version {
		// The response was already sent, but the ACK/NACK has not arrived yet.
		// Attach an unchanged update directly to that response generation so its
		// in-flight ACK can complete it.
		if state.pendingGeneration == 0 {
			// An immediately available CreateWatch response is built with a
			// background context. Its generation can still be recovered from an
			// update waiting for that same content version.
			state.pendingGeneration = generation
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
		pc := cb.addPendingCompletion(c, pending, generation, version, typeURL, nodeID, rollback)
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

	cb.addPendingCompletion(c, pending, generation, version, typeURL, nodeID, rollback)
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
	cb.mutex.Lock()
	cb.ensureStreamState(streamID).softResetEligible = typ == ""
	cb.mutex.Unlock()
	return nil
}

// OnStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
func (cb *CompletionCallbacks) OnStreamClosed(streamID int64, node *core.Node) {
	cb.mutex.Lock()
	stream := cb.streams[streamID]
	var nodeID string
	if stream != nil {
		nodeID = stream.nodeID
	}
	if nodeID == "" && node != nil {
		nodeID = node.GetId()
	}
	delete(cb.streams, streamID)

	streamStillOpen := false
	for _, openStream := range cb.streams {
		if openStream.nodeID == nodeID {
			streamStillOpen = true
			break
		}
	}
	if nodeID != "" && !streamStillOpen {
		if nodeState := cb.nodeState(nodeID); nodeState != nil {
			for typeURL := range typeurl.Count {
				typeState := &nodeState.typeURLs[typeURL]
				typeState.response.pendingVersion = ""
				typeState.response.pendingGeneration = 0
				typeState.response.pendingNonce = ""
				typeState.response.pendingStreamID = 0
				typeState.response.acceptedVersion = ""
				typeState.acceptedSnapshot = nil
			}
		}
	}
	streamClosed := cb.streamClosed
	cb.mutex.Unlock()
	if streamClosed != nil {
		streamClosed(streamID)
	}

	cb.Log.Info("OnStreamClosed", logfields.XDSStreamID, streamID)
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	cb.mutex.Lock()
	nodeID := cb.nodeIDForRequest(streamID, req)
	typeURL := req.GetTypeUrl()
	typeIndex, supported := typeurl.FromURL(typeURL)
	if !supported {
		cb.mutex.Unlock()
		return nil
	}
	nodeState := cb.ensureNodeState(nodeID)
	typeState := nodeState.typeURLState(typeIndex)
	state := &typeState.response
	stream := cb.streams[streamID]
	if stream != nil && stream.resetPhase == StreamResetting && typeIndex == typeurl.Listener &&
		req.GetResponseNonce() != "" {
		if stream.resetResponseNonce != "" && stream.resetResponseNonce == req.GetResponseNonce() {
			if req.GetErrorDetail() != nil {
				stream.resetPhase = streamResetFailed
				cb.mutex.Unlock()
				return fmt.Errorf("NACK from %s for empty %s stream reset: %s",
					nodeID, typeURL, req.GetErrorDetail().GetMessage())
			}
			stream.resetResponseNonce = ""
			// The empty response is a transport barrier, not an accepted
			// desired snapshot. Clear the ordinary response state so the next
			// live-cache response establishes acceptance from scratch.
			*state = responseState{}
			typeState.acceptedSnapshot = nil
			stream.resetPhase = StreamResetComplete
			cb.mutex.Unlock()
			return nil
		}
	}
	if req.GetVersionInfo() == "" && req.GetResponseNonce() == "" && req.GetErrorDetail() == nil {
		// This is a fresh subscription, not an ACK or NACK. Any accepted
		// version belongs to an earlier Envoy process.
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.pendingNonce = ""
		state.pendingStreamID = 0
		state.acceptedVersion = ""
		typeState.acceptedSnapshot = nil
		cb.mutex.Unlock()
		return nil
	}

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
		if stream != nil && stream.softResetEligible &&
			typeIndex == typeurl.Listener &&
			!stream.listenerSynchronized &&
			(!stream.resetAttempted ||
				stream.resetPhase == StreamResetRequested || stream.resetPhase == StreamResetting) {
			if !stream.resetAttempted {
				stream.resetAttempted = true
				stream.resetPhase = StreamResetRequested
			}
			rejectedVersion := state.pendingVersion
			if rejectedVersion == "" {
				rejectedVersion = req.GetVersionInfo()
			}
			// Preserve every attached completion and rollback. The current
			// desired state will be offered again after Envoy ACKs the empty
			// stream view, at which point a real ACK or NACK owns them.
			state.pendingVersion = ""
			state.pendingGeneration = 0
			state.pendingNonce = ""
			state.pendingStreamID = 0
			state.acceptedVersion = ""
			state.rejectedVersion = ""
			state.rejectedErr = nil
			typeState.acceptedSnapshot = nil
			cb.Log.Warn("Initial xDS NACK requested a stream soft reset",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, rejectedVersion,
				logfields.NodeID, nodeID,
				logfields.Error, req.GetErrorDetail().GetMessage())
			cb.mutex.Unlock()
			return nil
		}

		type generationRevert struct {
			generation uint64
			rollback   Rollback
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

		// A NACK rejects the entire response. Visit every snapshot update
		// coalesced into it, newest first. Each revert restores only resources
		// which have not been superseded since this response was sent.
		for c, pc := range cb.pendingCompletions {
			if pc.nodeID != nodeID || pc.typeURL != typeIndex ||
				rejectedGeneration == 0 || pc.responseGeneration != rejectedGeneration {
				continue
			}
			completed = append(completed, completionResult{
				completion: c,
				generation: pc.generation,
			})
			generationReverts = append(generationReverts, generationRevert{
				generation: pc.generation,
				rollback:   pc.rollback,
			})
			delete(cb.pendingCompletions, c)
		}

		for generation, pending := range typeState.pendingGenerations {
			if rejectedGeneration == 0 || pending.responseGeneration != rejectedGeneration {
				continue
			}
			generationReverts = append(generationReverts, generationRevert{
				generation: pending.generation,
				rollback:   pending.rollback,
			})
			delete(typeState.pendingGenerations, generation)
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

		typeState.removeEmptyPendingGenerationSet()

		if len(completed) > 0 || len(generationReverts) > 0 {
			cb.Log.Warn(
				"NACK received, reverting resource changes",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, rejectedVersion,
				logfields.XDSGeneration, rejectedGeneration,
				logfields.NodeID, nodeID,
				logfields.Error, req.GetErrorDetail().GetMessage(),
			)
		}
		cb.mutex.Unlock()
		expectedGeneration := rejectedGeneration
		for _, pending := range generationReverts {
			if pending.rollback == nil {
				continue
			}
			// Reverts are fenced per resource. A newer update may supersede every
			// resource in one generation while an older coalesced generation still
			// owns other resources which must be restored.
			expectedGeneration, _ = pending.rollback.Revert(expectedGeneration)
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
	acceptedStreamResponse := state.pendingNonce != "" &&
		state.pendingStreamID == streamID && state.pendingNonce == req.GetResponseNonce()
	if state.pendingVersion == req.GetVersionInfo() {
		acceptedGeneration = state.pendingGeneration
		state.pendingVersion = ""
		state.pendingGeneration = 0
		state.pendingNonce = ""
		state.pendingStreamID = 0
	} else if state.pendingVersion == "" && req.GetResponseNonce() == "" {
		// A version-only request can establish that Envoy already holds the
		// currently published snapshot without OnStreamResponse having run in
		// this process. Treat the matching published generation as accepted so
		// its response-owned rollback does not get folded into a later response.
		if published := nodeState.published; published.snapshot != nil &&
			published.snapshot.GetVersion(typeURL) == req.GetVersionInfo() {
			acceptedGeneration = published.generation
			for _, pc := range cb.pendingCompletions {
				if pc.nodeID == nodeID && pc.typeURL == typeIndex && pc.generation <= acceptedGeneration {
					pc.responseGeneration = acceptedGeneration
				}
			}
			for _, pending := range typeState.pendingGenerations {
				if pending.generation <= acceptedGeneration {
					pending.responseGeneration = acceptedGeneration
				}
			}
		}
	}
	state.acceptedVersion = req.GetVersionInfo()
	if stream != nil && typeIndex == typeurl.Listener &&
		(acceptedStreamResponse || acceptedGeneration != 0) {
		stream.listenerSynchronized = true
	}
	state.rejectedVersion = ""
	state.rejectedErr = nil
	if published := nodeState.published; acceptedGeneration != 0 &&
		published.snapshot != nil && published.snapshot.GetVersion(typeURL) == req.GetVersionInfo() {
		// Another resource type may have published a newer snapshot while this
		// response was in flight. Reuse it when this type's content version is
		// unchanged; its immutable resources are equivalent to those just ACKed.
		typeState.acceptedSnapshot = published.snapshot
	}

	var finalizers []FinalizeFunc
	for c, pc := range cb.pendingCompletions {
		if pc.nodeID != nodeID || pc.typeURL != typeIndex ||
			acceptedGeneration == 0 || pc.responseGeneration != acceptedGeneration {
			continue
		}
		completed = append(completed, completionResult{completion: c, generation: pc.generation})
		delete(cb.pendingCompletions, c)
		if pc.rollback != nil {
			finalizers = append(finalizers, pc.rollback.Finalize)
		}
		cb.Log.Debug("Completed completion for type URL and generation",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, req.GetVersionInfo(),
			logfields.XDSGeneration, pc.generation)
	}
	for generation, pending := range typeState.pendingGenerations {
		if acceptedGeneration != 0 && pending.responseGeneration == acceptedGeneration {
			if pending.rollback != nil {
				finalizers = append(finalizers, pending.rollback.Finalize)
			}
			delete(typeState.pendingGenerations, generation)
		}
	}
	typeState.removeEmptyPendingGenerationSet()
	cb.mutex.Unlock()

	for _, finalize := range finalizers {
		finalize()
	}
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
	var finalizers []FinalizeFunc

	cb.mutex.Lock()
	nodeID := cb.nodeIDForRequest(streamID, req)

	if version == "" {
		cb.mutex.Unlock()
		return
	}
	typeIndex, supported := typeurl.FromURL(typeURL)
	if !supported {
		cb.mutex.Unlock()
		return
	}
	if resetStreamID, reset := ctx.Value(streamResetContextKey{}).(int64); reset {
		stream := cb.streams[streamID]
		if resetStreamID == streamID && stream != nil && stream.resetPhase == StreamResetting &&
			typeIndex == typeurl.Listener {
			stream.resetResponseNonce = resp.GetNonce()
		}
		cb.mutex.Unlock()
		return
	}
	nodeState := cb.ensureNodeState(nodeID)
	typeState := nodeState.typeURLState(typeIndex)

	// SetSnapshot propagates the exact generation through the response context.
	// CreateWatch uses a background context for an immediately available
	// snapshot, so recover the generation from the authoritative snapshot state
	// staged by Cache.ApplyResources. The content version check prevents a
	// delayed response from being attributed to a newer snapshot.
	responseGeneration := snapshotGenerationFromContext(ctx)
	if responseGeneration == 0 {
		if published := nodeState.published; published.snapshot != nil &&
			published.snapshot.GetVersion(typeURL) == version {
			responseGeneration = published.generation
		}
	}
	// Keep a narrow fallback for callback unit tests and response paths that do
	// not originate in Cache.ApplyResources.
	if responseGeneration == 0 {
		for _, pc := range cb.pendingCompletions {
			if pc.nodeID == nodeID && pc.typeURL == typeIndex && pc.version == version &&
				pc.generation > responseGeneration {
				responseGeneration = pc.generation
			}
		}
	}
	if responseGeneration == 0 {
		for _, pc := range cb.pendingCompletions {
			if pc.nodeID == nodeID && pc.typeURL == typeIndex && pc.version == "" &&
				pc.generation > responseGeneration {
				responseGeneration = pc.generation
			}
		}
	}

	// A response for generation G contains the finalized resource state after
	// every generation <= G. Attach that whole prefix to G. A later ACK/NACK can
	// now resolve it with an integer comparison instead of replaying hash order.
	for _, pc := range cb.pendingCompletions {
		if pc.nodeID == nodeID && pc.typeURL == typeIndex && pc.generation <= responseGeneration {
			pc.responseGeneration = responseGeneration
		}
	}
	for _, pending := range typeState.pendingGenerations {
		if pending.generation <= responseGeneration {
			pending.responseGeneration = responseGeneration
		}
	}

	state := &typeState.response
	if state.pendingVersion == "" && state.acceptedVersion == version {
		state.rejectedVersion = ""
		state.rejectedErr = nil

		for c, pc := range cb.pendingCompletions {
			if responseGeneration != 0 && pc.typeURL == typeIndex && pc.nodeID == nodeID &&
				pc.responseGeneration == responseGeneration {
				completed = append(completed, c)
				delete(cb.pendingCompletions, c)
				if pc.rollback != nil {
					finalizers = append(finalizers, pc.rollback.Finalize)
				}
			}
		}
		for generation, pending := range typeState.pendingGenerations {
			if responseGeneration != 0 && pending.responseGeneration == responseGeneration {
				if pending.rollback != nil {
					finalizers = append(finalizers, pending.rollback.Finalize)
				}
				delete(typeState.pendingGenerations, generation)
			}
		}
		typeState.removeEmptyPendingGenerationSet()
		cb.mutex.Unlock()

		for _, finalize := range finalizers {
			finalize()
		}
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
	cb.mutex.Unlock()
}

func (cb *CompletionCallbacks) OnDeltaStreamOpen(ctx context.Context, streamID int64, typeURL string) error {
	panic("unimplemented")
}

// OnDeltaStreamClosed invokes DeltaStreamClosedFunc.
func (cb *CompletionCallbacks) OnDeltaStreamClosed(streamID int64, node *core.Node) {
	panic("unimplemented")
}
