// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	sotw "github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/revert"
)

type snapshotGenerationContextKey struct{}

func snapshotGenerationFromContext(ctx context.Context) Generation {
	switch published := ctx.Value(snapshotGenerationContextKey{}).(type) {
	case Generation:
		return published
	case *snapshotPublication:
		return published.generation
	default:
		return 0
	}
}

type generationResponse struct {
	cache.Response
	ctx context.Context
}

func (response *generationResponse) GetContext() context.Context {
	return response.ctx
}

// Rollback is the lifecycle of rollback state for one resource update.
type Rollback = revert.Revertible

type CompletionCallbacks struct {
	Log         *slog.Logger
	nackHandler NACKHandler

	// mutex protects all fields below. go-control-plane invokes stream
	// callbacks outside the ADS server mutex, while cache updates register
	// completions from Cilium-owned paths.
	mutex lock.Mutex

	// pendingWaits indexes caller waits by their WaitGroup completion.
	// Values hold xDS requirements and also implement completion.Owner.
	pendingWaits map[*completion.Completion]*resourceWait
	// nodes groups response and rollback bookkeeping first by node ID and then
	// by TypeURL. Keeping related state together avoids parallel maps with the
	// same composite keys.
	nodes map[string]*callbackNodeState
	// streams remember the node ID and pending responses for each ADS stream.
	// Envoy may omit Node on subsequent ACK/NACK requests. Named EDS
	// subscriptions can use several streams for the same node/resource type.
	streams map[streamKey]*callbackStreamState
	// streamLifecycle is immutable and called without the callbacks mutex held.
	streamLifecycle StreamLifecycleHandler
}

func NewCompletionCallbacks(logger *slog.Logger, nackHandler NACKHandler) *CompletionCallbacks {
	// Cache owners implement both interfaces. Owners which need only NACK
	// processing can omit stream lifecycle bookkeeping.
	streamLifecycle, _ := nackHandler.(StreamLifecycleHandler)
	return &CompletionCallbacks{
		Log:             logger,
		nackHandler:     nackHandler,
		pendingWaits:    make(map[*completion.Completion]*resourceWait),
		nodes:           make(map[string]*callbackNodeState),
		streams:         make(map[streamKey]*callbackStreamState),
		streamLifecycle: streamLifecycle,
	}
}

type callbackNodeState struct {
	typeURLs typeurl.Slots[typeURLState]
}

type typeURLState struct {
	// pendingGenerations records resource-changing snapshot generations until
	// the response carrying them is ACKed, NACKed, or otherwise proven not to
	// need a response. Their lifetime is deliberately independent from caller
	// completions: a caller may stop waiting before Envoy consumes the response,
	// and revertible updates without a WaitGroup must still be reverted on NACK.
	// Key by inverse identity: named responses can split one API generation
	// into independently resolved rollback lifetimes.
	pendingGenerations map[*pendingGeneration]Generation
	// acceptedResources retains this type's immutable ACKed resource group and
	// sparse overrides from subset ACKs.
	acceptedResources acceptedResourceGroup
	// response tracks the latest xDS response/ACK state for this node/type.
	response responseState
}

type acceptedResourceGroup struct {
	// generation is the ACKed response boundary, not any resource's revision.
	// Zero means acceptance is unknown. An ACKed empty group may
	// have a nil resource map, so the map alone cannot represent this distinction.
	generation Generation
	resources  map[string]cache_types.ResourceWithTTL
	// partial overrides individual names accepted by subset responses. The
	// common full-group case shares the snapshot map and needs no overlay.
	partial map[string]acceptedResource
	// A named full-positive response proves omission only for those names.
	requested []string
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
	return cb.nodes[nodeID].typeURLState(index)
}

// ensureTypeURLState returns callback state for nodeID and index, creating the
// node level when needed. cb.mutex must be held.
func (cb *CompletionCallbacks) ensureTypeURLState(nodeID string, index typeurl.Index) *typeURLState {
	return cb.ensureNodeState(nodeID).typeURLState(index)
}

// responseState tracks the latest xDS response/ACK state for a specific node/type.
type responseState struct {
	pendingVersion    string
	pendingGeneration Generation
	pendingStreamID   int64
	// acceptedGeneration prevents a delayed ACK on another stream from
	// replacing a newer accepted baseline with an older one.
	acceptedGeneration Generation
	// acceptedVersion belongs to the greatest generation ACKed for this type.
	acceptedVersion string
	// rejectedVersion/rejectedErr remember the latest NACKed version so a
	// no-change upsert for that same cache state can fail immediately.
	rejectedVersion string
	rejectedErr     error
	// Greatest NACKed response boundary. Retain it across ACKs and later NACKs
	// so forgetting a removed name cannot revive older absence evidence. A
	// covering ACK satisfies the fence per name, without retaining rejected names.
	rejectedGeneration Generation
}

// pendingResponse identifies one outstanding response and the resource names
// it communicates. Generations establish ordering; versions are retained because
// Envoy echoes them in ACK and NACK requests.
type pendingResponse struct {
	// pendingVersion is the version in the most recent response for which we have
	// not yet observed an ACK or NACK.
	pendingVersion    string
	pendingGeneration Generation
	// OnStreamRequest runs before go-control-plane rejects a stale nonce.
	// Match the exact response and stream so an old ACK/NACK cannot resolve a
	// newer generation.
	pendingNonce string
	coverage     *responseCoverage
}

func (state *responseState) clearPending() {
	state.pendingVersion = ""
	state.pendingGeneration = 0
	state.pendingStreamID = 0
}

// resourceWait tracks one caller's wait for Envoy to accept resource state.
type resourceWait struct {
	callbacks *CompletionCallbacks
	nodeID    string
	// typeURL is the type URL of the resources to be ACKed.
	typeURL typeurl.Index
	// removalOnly waits survive NACKs until a response ACKs their removal
	// requirements, or the caller's context ends. They own no cache rollback.
	removalOnly bool
	// generation is the snapshot boundary needed by this completion. Its scope
	// records the required revisions of individual resource names.
	generation Generation
	scope      ResourceScope
}

func (pc *resourceWait) ID() string {
	return fmt.Sprintf("nodeID:%s,typeURL:%s,generation:%d", pc.nodeID, pc.typeURL.URL(), pc.generation)
}

func (pc *resourceWait) CleanupAfterWait(c *completion.Completion) {
	pc.callbacks.RemoveTypeGenerationCompletion(c)
}

// pendingGeneration retains response-owned rollback which may be folded into a
// later response. Its boundary is stored in pendingGenerations. It outlives caller
// waits, including updates without a WaitGroup, so a NACK can still revert the
// communicated names whose originating API transactions remain current.
type pendingGeneration struct {
	// Always non-nil: generations without a response inverse are tracked only
	// by caller completions, not by this response-owned container.
	rollback Rollback
	// nil means the cache has not collected a response for this inverse yet.
	// Capture its scope at delivery, rather than rebuilding an immutable name
	// map after every coalesced mutation. A non-nil zero scope covers the type.
	scope *ResourceScope
}

// removeEmptyPendingGenerationSet releases only the empty per-type container.
// Individual generations are response-owned and must not be pruned merely
// because their caller stopped waiting for an ACK or NACK.
func (state *typeURLState) removeEmptyPendingGenerationSet() {
	if len(state.pendingGenerations) == 0 {
		state.pendingGenerations = nil
	}
}

// RemoveTypeGenerationCompletion stops notifying one caller. Published
// generation rollback state remains live until its xDS response terminates.
func (cb *CompletionCallbacks) RemoveTypeGenerationCompletion(c *completion.Completion) {
	cb.mutex.Lock()
	delete(cb.pendingWaits, c)
	cb.mutex.Unlock()
}

// NewTypeGenerationCompletionOwner returns an owner which drops callback state
// if its WaitGroup ends before Envoy ACKs or NACKs the generation.
// scope must contain at least one resource name and its required revision.
func (cb *CompletionCallbacks) NewTypeGenerationCompletionOwner(nodeID string, typeURL typeurl.Index, generation Generation, scope ResourceScope, removalOnly bool) *resourceWait {
	return &resourceWait{
		callbacks:   cb,
		nodeID:      nodeID,
		typeURL:     typeURL,
		generation:  generation,
		scope:       scope,
		removalOnly: removalOnly,
	}
}

// DetachedWaiters holds caller waits removed from callback bookkeeping.
// Complete must be called after releasing the cache and callbacks locks:
// completion can wake callers that immediately access the cache.
// Response-owned generation rollback state is deliberately not included.
type DetachedWaiters struct {
	completions []*completion.Completion
}

func (detached DetachedWaiters) Complete(err error) {
	for _, comp := range detached.completions {
		comp.Complete(err)
	}
}

// TakePendingWaiters detaches the current caller waits for one node and
// resource type. It is safe to call while holding the cache mutation lock: a
// subsequent policy update cannot register a new wait until the lock is
// released. Completing the returned batch is a separate, unlocked operation.
func (cb *CompletionCallbacks) TakePendingWaiters(nodeID string, typeURL typeurl.Index) DetachedWaiters {
	var detached DetachedWaiters
	cb.mutex.Lock()
	for comp, pending := range cb.pendingWaits {
		if pending.nodeID != nodeID || pending.typeURL != typeURL {
			continue
		}
		detached.completions = append(detached.completions, comp)
		delete(cb.pendingWaits, comp)
	}
	cb.mutex.Unlock()
	return detached
}

// PendingCompletionCount returns the number of pending completions. Intended for testing.
func (cb *CompletionCallbacks) PendingCompletionCount() int {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	return len(cb.pendingWaits)
}

// addPendingCompletion records a completion that is waiting for an xDS ACK/NACK.
// cb.mutex must be held.
func (cb *CompletionCallbacks) addPendingCompletion(c *completion.Completion, pending *resourceWait, version string) {
	if cb.Log.Enabled(context.Background(), slog.LevelDebug) {
		cb.Log.Debug("Adding pending completion for type URL and generation",
			logfields.XDSTypeURL, pending.typeURL.URL(),
			logfields.Version, version,
			logfields.XDSGeneration, pending.generation,
			logfields.NodeID, pending.nodeID)
	}
	cb.pendingWaits[c] = pending
}

// SetPublishedSnapshot prunes obsolete sparse acceptance evidence after the
// cache confirms SetSnapshot installed the snapshot, before delivering buffered
// responses. It does not infer acceptance from publication or echoed versions.
func (cb *CompletionCallbacks) SetPublishedSnapshot(nodeID string, snapshot cache.ResourceSnapshot) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	nodeState := cb.nodes[nodeID]
	if nodeState == nil {
		// No acceptance evidence exists before callback state is created.
		return
	}
	// Subset subscribers may never ACK a full group. Their sparse acceptance
	// overrides must not become a history of names no longer in desired state.
	// The immutable baseline still has a bounded lifetime (one group per type).
	for index := range typeurl.Count {
		accepted := &nodeState.typeURLs[index].acceptedResources
		if len(accepted.partial) == 0 {
			continue
		}
		desired := snapshot.GetResourcesAndTTL(index.URL())
		for name := range accepted.partial {
			if _, exists := desired[name]; !exists {
				delete(accepted.partial, name)
			}
		}
		if len(accepted.partial) == 0 {
			accepted.partial = nil
		}
	}
}

// ResourceAccepted reports whether the latest ACK evidence for this resource
// matches its desired contents. An ACK for another name proves nothing here.
// minimumRevision requires ACK evidence covering at least that value revision;
// zero permits matching accepted contents regardless of their revision.
// Resource pointers are immutable, so the common already-ACKed case needs only
// a pointer comparison. Sparse acceptance bookkeeping is read under cb.mutex.
func (cb *CompletionCallbacks) ResourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, desired proto.Message, desiredExists bool, minimumRevision Revision) bool {
	return cb.resourceAccepted(nodeID, typeURL, resourceName, nil, false, desired, desiredExists, false, minimumRevision)
}

// HasResourceAcceptance reports whether this type has any resource-level ACK
// evidence. A false result lets bulk updates skip per-name acceptance checks;
// a true result does not prove acceptance of any particular name or contents.
func (cb *CompletionCallbacks) HasResourceAcceptance(nodeID string, typeURL typeurl.Index) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	state := cb.typeURLState(nodeID, typeURL)
	return state != nil && (state.acceptedResources.generation != 0 || len(state.acceptedResources.partial) != 0)
}

// RemovalWaitRevision fences an absent name without retaining a desired entry.
// Previously accepted absence stays usable unless a later sent
// value makes it uncertain. After a NACK, conservatively require absence evidence
// at least as new as that rejection, including for names omitted by later NACKs.
// Otherwise a never-present name retains revision zero. This is used only for
// removal waits; it retains neither protobufs nor per-name deletion history.
func (cb *CompletionCallbacks) RemovalWaitRevision(nodeID string, typeURL typeurl.Index, name string, revision Revision) Revision {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	typeState := cb.typeURLState(nodeID, typeURL)
	if typeState == nil {
		return revision
	}
	_, exists, acceptedGeneration := typeState.acceptedResources.resource(name, typeURL)
	if exists && acceptedGeneration > revision.revision {
		revision = acceptedGeneration.Revision()
	}
	state := &typeState.response
	if state.rejectedGeneration > revision.revision && state.rejectedGeneration > acceptedGeneration {
		revision = state.rejectedGeneration.Revision()
	}
	for _, stream := range cb.streams {
		response := stream.responses[typeURL]
		if stream.nodeID == nodeID && response.pendingGeneration > acceptedGeneration &&
			response.coverage != nil && response.coverage.resources[name].Resource != nil && response.coverage.contains(name) {
			if response.pendingGeneration > revision.revision {
				revision = response.pendingGeneration.Revision()
			}
		}
	}
	for _, pending := range cb.pendingWaits {
		if pending.nodeID != nodeID || pending.typeURL != typeURL || !pending.removalOnly {
			continue
		}
		required := pending.scope.more[name]
		if pending.scope.name == name {
			required = pending.scope.revision
		}
		if required.revision > revision.revision {
			revision = required
		}
	}
	return revision
}

// ChangedResourceAccepted reports whether a changed resource has the same
// contents in the most recently ACKed resource group. previous is the cache value
// which the caller already established differs semantically from desired. If
// the accepted group still owns that exact previous pointer, desired cannot
// be accepted and the expensive protobuf comparison is unnecessary.
// minimumRevision has the same revision-fence meaning as ResourceAccepted.
func (cb *CompletionCallbacks) ChangedResourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, previous proto.Message, previousExists bool, desired proto.Message, desiredExists bool, minimumRevision Revision) bool {
	return cb.resourceAccepted(nodeID, typeURL, resourceName, previous, previousExists, desired, desiredExists, true, minimumRevision)
}

func (cb *CompletionCallbacks) resourceAccepted(nodeID string, typeURL typeurl.Index, resourceName string, previous proto.Message, previousExists bool, desired proto.Message, desiredExists, desiredChanged bool, minimumRevision Revision) bool {
	cb.mutex.Lock()
	typeState := cb.typeURLState(nodeID, typeURL)
	var acceptedResources acceptedResourceGroup
	if typeState != nil {
		acceptedResources = typeState.acceptedResources
	}
	accepted, acceptedExists, acceptedGeneration := acceptedResources.resource(resourceName, typeURL)
	cb.mutex.Unlock()
	if acceptedGeneration == 0 || minimumRevision.revision > acceptedGeneration {
		return false
	}
	if acceptedExists != desiredExists {
		return false
	}
	if desiredChanged && acceptedExists == previousExists &&
		(!previousExists || accepted.Resource == previous) {
		return false
	}
	return !desiredExists || accepted.Resource == desired || xds.ResourceEqual(accepted.Resource, desired)
}

// AddTypeGenerationWithRollback records a non-nil response-owned rollback,
// independently of caller waits. A nil scope remains unclaimed until the cache
// collects a response; an explicit zero scope tracks the whole resource type.
func (cb *CompletionCallbacks) AddTypeGenerationWithRollback(generation Generation, typeURL typeurl.Index, nodeID string, rollback Rollback, scope *ResourceScope) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	typeState := cb.ensureTypeURLState(nodeID, typeURL)
	generations := typeState.pendingGenerations
	if generations == nil {
		generations = make(map[*pendingGeneration]Generation)
		typeState.pendingGenerations = generations
	}
	generations[&pendingGeneration{rollback: rollback, scope: scope}] = generation

	if cb.Log.Enabled(context.Background(), slog.LevelDebug) {
		cb.Log.Debug("Added pending snapshot generation",
			logfields.XDSTypeURL, typeURL.URL(),
			logfields.XDSGeneration, generation,
			logfields.NodeID, nodeID)
	}
}

// CoalesceUnsentTypeGeneration updates a registered, unclaimed rollback's
// generation and response requirements. A nil scope leaves it unclaimed.
// The caller holds the cache lock and owns the node/type's sole unclaimed
// rollback, registered at oldGeneration. Response claiming clears that cache
// reference under the same lock, so this entry remains unclaimed during the update.
func (cb *CompletionCallbacks) CoalesceUnsentTypeGeneration(nodeID string, typeURL typeurl.Index, oldGeneration, newGeneration Generation, scope *ResourceScope) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	generations := cb.typeURLState(nodeID, typeURL).pendingGenerations
	for pending, boundary := range generations {
		if boundary == oldGeneration && pending.scope == nil {
			pending.scope = scope
			if oldGeneration != newGeneration {
				generations[pending] = newGeneration
			}
			return
		}
	}
}

// PartitionUnsentTypeGeneration freezes the covered part of an unsent inverse
// before delivery, while leaving the other part available for coalescing.
// Names from the same API generation can have independent response lifetimes.
func (cb *CompletionCallbacks) PartitionUnsentTypeGeneration(nodeID string, typeURL typeurl.Index, oldGeneration, remainingGeneration Generation, remaining Rollback, remainingScope *ResourceScope, sentGeneration Generation, sent Rollback, sentScope *ResourceScope) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	typeState := cb.ensureTypeURLState(nodeID, typeURL)
	for pending, boundary := range typeState.pendingGenerations {
		if boundary == oldGeneration && pending.scope == nil {
			delete(typeState.pendingGenerations, pending)
			break
		}
	}
	typeState.pendingGenerations[&pendingGeneration{rollback: remaining, scope: remainingScope}] = remainingGeneration
	typeState.pendingGenerations[&pendingGeneration{rollback: sent, scope: sentScope}] = sentGeneration
}

// DiscardUnsentTypeGeneration removes a generation whose coalesced resource
// changes returned to their original values before any response was produced.
// The caller owns and finalizes its rollback after this method succeeds.
func (cb *CompletionCallbacks) DiscardUnsentTypeGeneration(nodeID string, typeURL typeurl.Index, generation Generation) bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	typeState := cb.typeURLState(nodeID, typeURL)
	if typeState == nil {
		return false
	}
	for pending, boundary := range typeState.pendingGenerations {
		if boundary == generation && pending.scope == nil {
			delete(typeState.pendingGenerations, pending)
			typeState.removeEmptyPendingGenerationSet()
			return true
		}
	}
	return false
}

// AddPreparedTypeGenerationCompletion registers a completion using the object
// already allocated as its completion.Owner, avoiding a second hot-path
// allocation for callback bookkeeping. pending must have been created by this
// callback handler and supplied as the owner when c was added to its WaitGroup.
func (cb *CompletionCallbacks) AddPreparedTypeGenerationCompletion(c *completion.Completion, pending *resourceWait, version string, versionChanged bool) (bool, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	nodeID, typeURL, generation := pending.nodeID, pending.typeURL, pending.generation

	if _, ok := cb.pendingWaits[c]; ok {
		cb.Log.Warn("Reusing existing completion",
			logfields.XDSTypeURL, typeURL.URL(),
			logfields.Version, version,
			logfields.XDSGeneration, generation,
			logfields.NodeID, nodeID)
		return true, nil
	}

	typeState := cb.ensureTypeURLState(nodeID, typeURL)
	state := &typeState.response

	if version != "" && state.pendingVersion == "" && state.acceptedVersion == version {
		// An ACK can arrive after the cache checks resource acceptance but before
		// it registers this no-op wait. Resolve it here: the unchanged published
		// version may not produce another response.
		return false, nil
	}

	if version != "" && state.pendingVersion == "" && !versionChanged && state.rejectedVersion == version && !pending.removalOnly {
		return false, state.rejectedErr
	}

	cb.addPendingCompletion(c, pending, version)
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

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	if req.GetErrorDetail() != nil {
		return cb.handleNACK(streamID, req)
	}
	cb.mutex.Lock()
	stream, started := cb.streamForRequest(streamID, req)
	nodeID := stream.nodeID
	if started && cb.streamLifecycle != nil {
		defer cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeSotW)
	}
	typeURL := req.GetTypeUrl()
	typeIndex, supported := typeurl.FromURL(typeURL)
	if !supported {
		cb.mutex.Unlock()
		return nil
	}
	typeState := cb.ensureTypeURLState(nodeID, typeIndex)
	state := &typeState.response
	response := &stream.responses[typeIndex]
	if req.GetVersionInfo() == "" && req.GetResponseNonce() == "" {
		// This is a subscription request, not an ACK or NACK. Preserve any
		// in-flight identity until its actual ACK/NACK arrives. Acceptance is
		// conservatively unknown for the new subscription.
		state.acceptedVersion = ""
		state.acceptedGeneration = 0
		typeState.acceptedResources = acceptedResourceGroup{}
		cb.mutex.Unlock()
		return nil
	}

	// go-control-plane checks nonces after invoking callbacks. Require the
	// outstanding response's nonce before resolving waits or recording acceptance.
	if response.pendingNonce == "" || response.pendingNonce != req.GetResponseNonce() {
		cb.Log.Debug("Ignoring stale xDS ACK/NACK",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, req.GetVersionInfo(),
			logfields.NodeID, nodeID)
		cb.mutex.Unlock()
		return nil
	}

	type completionResult struct {
		completion *completion.Completion
		generation Generation
	}
	var completed []completionResult

	coverage := response.coverage
	// ACK received: resolve the prefix actually covered by this stream's response.
	// Other streams can have newer responses in flight. Each ACK proves only the
	// resource names and revisions communicated by its own response.
	var acceptedGeneration Generation
	if response.pendingVersion == req.GetVersionInfo() {
		acceptedGeneration = response.pendingGeneration
		*response = pendingResponse{}
		if state.pendingStreamID == streamID {
			state.clearPending()
		}
	}
	// An echoed version without a matching response proves nothing about the
	// resources Envoy received. Even a wildcard request on a new stream can
	// carry a version learned from an earlier named subscription.
	if acceptedGeneration != 0 {
		typeState.acceptedResources.acknowledge(coverage, acceptedGeneration)
	}
	if acceptedGeneration != 0 && acceptedGeneration >= state.acceptedGeneration && coverage.complete() &&
		typeHasDeletionSemantics(typeIndex) {
		state.acceptedGeneration = acceptedGeneration
		state.acceptedVersion = req.GetVersionInfo()
		state.rejectedVersion = ""
		state.rejectedErr = nil
	}

	var finalizers []Rollback
	debugEnabled := cb.Log.Enabled(context.Background(), slog.LevelDebug)
	for c, pc := range cb.pendingWaits {
		if pc.nodeID != nodeID || pc.typeURL != typeIndex ||
			acceptedGeneration == 0 {
			continue
		}
		if pc.removalOnly {
			if !pc.scope.acknowledgeRemovals(coverage, acceptedGeneration, pc.generation) {
				continue
			}
		} else {
			if !pc.scope.acknowledge(coverage, acceptedGeneration) {
				continue
			}
		}
		completed = append(completed, completionResult{completion: c, generation: pc.generation})
		delete(cb.pendingWaits, c)
		if debugEnabled {
			cb.Log.Debug("Completed completion for type URL and generation",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, req.GetVersionInfo(),
				logfields.XDSGeneration, pc.generation)
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

// handleNACKLocked processes a NACK after node/type and nonce validation.
// The caller holds cb.mutex and req.ErrorDetail must be non-nil. It records the
// rejection and transfers rollback and waiter ownership to the returned work.
// It never changes lock ownership or calls the cache.
func (cb *CompletionCallbacks) handleNACKLocked(streamID int64, req *discovery.DiscoveryRequest, stream *callbackStreamState, typeIndex typeurl.Index, typeState *typeURLState) *nackRecovery {
	nodeID := stream.nodeID
	typeURL := req.GetTypeUrl()
	state := &typeState.response
	response := &stream.responses[typeIndex]
	coverage := response.coverage
	var completed []*completion.Completion
	var generationReverts []generationRevert
	// Nonce validation guarantees a recorded response with a nonempty version.
	// The request reports the last accepted version, which may be empty.
	rejectedVersion := response.pendingVersion
	rejectedGeneration := response.pendingGeneration
	nackErr := fmt.Errorf("NACK from %s for %s version %s: %s",
		nodeID, typeURL, rejectedVersion, req.GetErrorDetail().GetMessage())
	*response = pendingResponse{}
	state.rejectedGeneration = max(state.rejectedGeneration, rejectedGeneration)
	if state.pendingStreamID == streamID {
		state.clearPending()
	}
	if rejectedGeneration != 0 && rejectedGeneration >= state.acceptedGeneration && coverage.complete() &&
		typeHasDeletionSemantics(typeIndex) {
		state.acceptedVersion = req.GetVersionInfo()
		state.rejectedVersion = rejectedVersion
		state.rejectedErr = nackErr
	}

	// A NACK rejects the entire response. Select every update coalesced into it
	// and pass its inverses newest first to the cache, which composes one final
	// correction while preserving superseding API transactions.
	for pending, generation := range typeState.pendingGenerations {
		if rejectedGeneration == 0 || generation > rejectedGeneration || !pending.scope.intersects(coverage, rejectedGeneration) {
			continue
		}
		generationReverts = append(generationReverts, generationRevert{
			generation: generation, pending: pending,
		})
		delete(typeState.pendingGenerations, pending)
	}
	for c, pc := range cb.pendingWaits {
		if pc.nodeID != nodeID || pc.typeURL != typeIndex || rejectedGeneration == 0 {
			continue
		}
		if !pc.scope.intersects(coverage, rejectedGeneration) {
			continue
		}
		if pc.removalOnly {
			// This wait covers only removals of the rejected type, even if its
			// API transaction upserted other types. Await a later ACK.
			continue
		}
		completed = append(completed, c)
		delete(cb.pendingWaits, c)
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
			"NACK received",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, rejectedVersion,
			logfields.XDSGeneration, rejectedGeneration,
			logfields.NodeID, nodeID,
			logfields.Error, req.GetErrorDetail().GetMessage(),
		)
	}
	return &nackRecovery{
		nodeID: nodeID, typeURL: typeIndex, cause: nackErr,
		reverts: generationReverts, completed: completed,
	}
}

// OnStreamResponse is called immediately prior to sending a response on a stream.
func (cb *CompletionCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	version := resp.GetVersionInfo()
	typeURL := resp.GetTypeUrl()

	cb.mutex.Lock()
	stream, started := cb.streamForRequest(streamID, req)
	nodeID := stream.nodeID
	if started && cb.streamLifecycle != nil {
		defer cb.streamLifecycle.StreamStarted(streamID, nodeID, StreamModeSotW)
	}

	if version == "" {
		cb.mutex.Unlock()
		return
	}
	typeIndex, supported := typeurl.FromURL(typeURL)
	if !supported {
		cb.mutex.Unlock()
		return
	}
	coverage := responseCoverageFromContext(ctx)
	if coverage == nil {
		// Only the cache's exact response metadata proves what Envoy received.
		// An uninstrumented response must not acquire waits or rollback state.
		cb.mutex.Unlock()
		return
	}
	typeState := cb.ensureTypeURLState(nodeID, typeIndex)

	// SetSnapshot responses inherit the publication context; the cache captures
	// the generation of immediate CreateWatch responses before releasing its
	// lock. Never infer it from current publications or waiters: delivery may
	// be delayed past newer updates, even when contents match an earlier state.
	responseGeneration := snapshotGenerationFromContext(ctx)
	stream.responses[typeIndex] = pendingResponse{
		pendingVersion: version, pendingGeneration: responseGeneration, pendingNonce: resp.GetNonce(),
		coverage: coverage,
	}

	state := &typeState.response
	// A delayed response on another stream must not replace the newer response
	// or accepted version used by no-op completion registration. Its exact
	// identity remains available in the stream-local slot above.
	if responseGeneration >= state.pendingGeneration && responseGeneration >= state.acceptedGeneration {
		state.pendingVersion = version
		state.pendingGeneration = responseGeneration
		state.pendingStreamID = streamID
		if state.rejectedVersion == version {
			state.rejectedVersion = ""
			state.rejectedErr = nil
		}
	}
	cb.mutex.Unlock()
}
