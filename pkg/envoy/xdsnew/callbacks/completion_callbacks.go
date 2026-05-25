// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"container/list"
	"context"
	"fmt"
	"log/slog"

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
	NetworkPolicyHostsTypeUrl = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

// versionEntry holds all pending completions associated with a single version.
type versionEntry struct {
	version     string
	completions map[*completion.Completion]struct{}
}

// orderedCompletions maintains insertion order of versions with O(1) lookup by version string.
// When a version is ACKed, all versions up to and including it are completed.
type orderedCompletions struct {
	list     *list.List
	elements map[string]*list.Element
}

func newOrderedCompletions() *orderedCompletions {
	return &orderedCompletions{
		list:     list.New(),
		elements: make(map[string]*list.Element),
	}
}

// add adds a completion to the given version entry. If the version doesn't exist
// yet, a new entry is appended to the end of the list (newest).
func (vo *orderedCompletions) add(version string, c *completion.Completion) {
	if elem, ok := vo.elements[version]; ok {
		entry := elem.Value.(*versionEntry)
		entry.completions[c] = struct{}{}
		return
	}
	entry := &versionEntry{
		version:     version,
		completions: map[*completion.Completion]struct{}{c: {}},
	}
	elem := vo.list.PushBack(entry)
	vo.elements[version] = elem
}

// completeUpTo returns all completions for the given version and all versions
// that were inserted before it, removing them from the list.
func (vo *orderedCompletions) completeUpTo(version string) []*completion.Completion {
	elem, ok := vo.elements[version]
	if !ok {
		return nil
	}
	var completed []*completion.Completion
	for e := vo.list.Front(); e != nil; {
		entry := e.Value.(*versionEntry)
		next := e.Next()
		for c := range entry.completions {
			completed = append(completed, c)
		}
		delete(vo.elements, entry.version)
		vo.list.Remove(e)
		if e == elem {
			break
		}
		e = next
	}
	return completed
}

func completionsOrderKey(nodeID, typeURL string) string {
	return nodeID + "\x00" + typeURL
}

type CompletionCallbacks struct {
	Log *slog.Logger

	// mutex protects all fields below. go-control-plane invokes stream
	// callbacks outside the ADS server mutex, while cache updates register
	// completions from Cilium-owned paths.
	mutex lock.Mutex

	// pendingCompletions is the list of updates that are pending completion.
	pendingCompletions map[*completion.Completion]*pendingCompletion
	// completionsOrders tracks the order in which versions were sent per (nodeID, typeURL).
	// When an ACK is received for a version, all completions for that version and
	// all earlier versions are completed.
	// A separate mutex is not needed here: completionsOrders is always updated
	// together with pendingCompletions and responseStates under mutex above, so
	// a single lock keeps response state, pending completions, and version order
	// consistent.
	completionsOrders map[string]*orderedCompletions
	// responseStates tracks the latest xDS response/ACK state per (nodeID, typeURL).
	// This is intentionally current-state only: resource versions are content
	// hashes, so the same version can legitimately reappear after coalescing or
	// reverting updates.
	responseStates map[string]responseState
}

func NewCompletionCallbacks(logger *slog.Logger) *CompletionCallbacks {
	return &CompletionCallbacks{
		Log:                logger,
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
		completionsOrders:  make(map[string]*orderedCompletions),
		responseStates:     make(map[string]responseState),
	}
}

type responseState struct {
	// pendingVersion is the version in the most recent response for which we have
	// not yet observed an ACK or NACK.
	pendingVersion string
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

	// typeURL is the type URL of the resources to be ACKed.
	typeURL string

	// revertFunc is called when a NACK is received to undo the resource change.
	revertFunc func()

	// inCompletionsOrder is true if this completion has been added to an orderedCompletions.
	inCompletionsOrder bool
}

func (cb *CompletionCallbacks) RemoveTypeVersionCompletion(c *completion.Completion) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	delete(cb.pendingCompletions, c)
	cb.removeFromOrderedCompletions(c)
}

// removeFromOrderedCompletions removes a completion from whatever orderedCompletions entry it belongs to.
// cb.mutex must be held.
func (cb *CompletionCallbacks) removeFromOrderedCompletions(c *completion.Completion) {
	for key, vo := range cb.completionsOrders {
		for _, elem := range vo.elements {
			entry := elem.Value.(*versionEntry)
			if _, ok := entry.completions[c]; ok {
				delete(entry.completions, c)
				if len(entry.completions) == 0 {
					vo.list.Remove(elem)
					delete(vo.elements, entry.version)
				}
				if vo.list.Len() == 0 {
					delete(cb.completionsOrders, key)
				}
				return
			}
		}
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
	for c, pc := range cb.pendingCompletions {
		if pc.typeURL == typeURL {
			cb.Log.Debug("Cancelling pending completion",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, pc.version,
				logfields.NodeID, pc.nodeID)
			completed = append(completed, c)
			delete(cb.pendingCompletions, c)
			cb.removeFromOrderedCompletions(c)
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
func (cb *CompletionCallbacks) addPendingCompletion(c *completion.Completion, version string, typeURL string, nodeID string, revertFunc func()) *pendingCompletion {
	cb.Log.Debug("Adding pending completion for type URL and version",
		logfields.XDSTypeURL, typeURL,
		logfields.Version, version,
		logfields.NodeID, nodeID)
	pc := &pendingCompletion{
		nodeID:     nodeID,
		version:    version,
		typeURL:    typeURL,
		revertFunc: revertFunc,
	}
	cb.pendingCompletions[c] = pc
	return pc
}

// addToCompletionsOrder attaches a pending completion to an xDS response
// version. cb.mutex must be held.
func (cb *CompletionCallbacks) addToCompletionsOrder(c *completion.Completion, pc *pendingCompletion, version string) {
	key := completionsOrderKey(pc.nodeID, pc.typeURL)
	vo, ok := cb.completionsOrders[key]
	if !ok {
		vo = newOrderedCompletions()
		cb.completionsOrders[key] = vo
	}
	vo.add(version, c)
	pc.inCompletionsOrder = true
	cb.Log.Debug("Added completion to version order",
		logfields.XDSTypeURL, pc.typeURL,
		logfields.Version, version,
		logfields.NodeID, pc.nodeID)
}

// CompleteUnsentPendingCompletions completes pending updates that were never
// attached to any xDS response. Call this after the cache has successfully
// landed on a version Envoy has already accepted; at that point there is no
// future response that could complete the superseded updates.
func (cb *CompletionCallbacks) CompleteUnsentPendingCompletions(nodeID, typeURL string, err error) {
	var completed []*completion.Completion

	cb.mutex.Lock()
	for c, pc := range cb.pendingCompletions {
		if pc.nodeID != nodeID || pc.typeURL != typeURL || pc.inCompletionsOrder {
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

// AddTypeVersionCompletion registers a completion for a type/version update.
// It returns (false, err) when no future xDS ACK is expected and the caller
// should complete the passed completion immediately after SetSnapshot succeeds.
func (cb *CompletionCallbacks) AddTypeVersionCompletion(c *completion.Completion, version string, typeURL string, nodeID string, versionChanged bool, revertFunc func()) (bool, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	if _, ok := cb.pendingCompletions[c]; ok {
		cb.Log.Warn("Reusing existing completion",
			logfields.XDSTypeURL, typeURL,
			logfields.Version, version,
			logfields.NodeID, nodeID)
		return true, nil
	}

	key := completionsOrderKey(nodeID, typeURL)
	state := cb.responseStates[key]

	if version != "" && state.pendingVersion == version {
		// The response was already sent, but the ACK/NACK has not arrived yet.
		// Add the completion directly to that response's order so the in-flight
		// ACK can complete it.
		pc := cb.addPendingCompletion(c, version, typeURL, nodeID, revertFunc)
		cb.addToCompletionsOrder(c, pc, version)
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

	cb.addPendingCompletion(c, version, typeURL, nodeID, revertFunc)
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
	cb.Log.Info("OnStreamClosed", logfields.XDSStreamID, streamID)
}

// OnStreamRequest is called once a request is received on a stream.
// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
func (cb *CompletionCallbacks) OnStreamRequest(streamID int64, req *discovery.DiscoveryRequest) error {
	if req.VersionInfo == "" {
		// This means this is the first request on the stream, so we can ignore it for completion purposes since there is no version to ACK.
		return nil
	}
	nodeID := req.GetNode().GetId()
	typeURL := req.GetTypeUrl()
	key := completionsOrderKey(nodeID, typeURL)

	var completed []*completion.Completion
	var completeErr error
	var revertFunc func()

	cb.mutex.Lock()
	if req.GetErrorDetail() != nil {
		state := cb.responseStates[key]
		rejectedVersion := state.pendingVersion
		if rejectedVersion == "" {
			rejectedVersion = req.GetVersionInfo()
		}
		nackErr := fmt.Errorf("NACK from %s for %s version %s: %s",
			nodeID, typeURL, rejectedVersion, req.GetErrorDetail().GetMessage())
		state.pendingVersion = ""
		state.acceptedVersion = req.GetVersionInfo()
		state.rejectedVersion = rejectedVersion
		state.rejectedErr = nackErr
		cb.responseStates[key] = state

		// NACK received: find a matching pending completion for the revert function.
		for c, pc := range cb.pendingCompletions {
			if pc.typeURL != typeURL || pc.nodeID != nodeID {
				continue
			}
			cb.Log.Warn(
				"NACK received, reverting resource change",
				logfields.XDSTypeURL, pc.typeURL,
				logfields.Version, pc.version,
				logfields.NodeID, pc.nodeID,
				logfields.Error, req.GetErrorDetail().GetMessage(),
			)
			revertFunc = pc.revertFunc
			// Complete this completion and all earlier ones in the version order,
			// since the revert rolls back all changes up to this point.
			if vo, ok := cb.completionsOrders[key]; ok {
				completed = vo.completeUpTo(pc.version)
				for _, ec := range completed {
					delete(cb.pendingCompletions, ec)
				}
				if vo.list.Len() == 0 {
					delete(cb.completionsOrders, key)
				}
			} else {
				// Completion wasn't in a version order yet; complete it directly.
				completed = append(completed, c)
				delete(cb.pendingCompletions, c)
			}
			completeErr = nackErr
			break
		}
		cb.mutex.Unlock()
		if revertFunc != nil {
			revertFunc()
		}
		for _, c := range completed {
			c.Complete(completeErr)
		}
		return nil
	}

	// ACK received: complete this version and all earlier versions in the version order.
	state := cb.responseStates[key]
	state.acceptedVersion = req.GetVersionInfo()
	state.rejectedVersion = ""
	state.rejectedErr = nil
	if state.pendingVersion == req.GetVersionInfo() {
		state.pendingVersion = ""
	}
	cb.responseStates[key] = state

	if vo, ok := cb.completionsOrders[key]; ok {
		completed = vo.completeUpTo(req.GetVersionInfo())
		for _, c := range completed {
			delete(cb.pendingCompletions, c)
			cb.Log.Debug("Completed completion for type URL and version",
				logfields.XDSTypeURL, typeURL,
				logfields.Version, req.GetVersionInfo())
		}
		if vo.list.Len() == 0 {
			delete(cb.completionsOrders, key)
		}
	}
	cb.mutex.Unlock()

	for _, c := range completed {
		c.Complete(nil)
	}
	return nil
}

// OnStreamResponse is called immediately prior to sending a response on a stream.
func (cb *CompletionCallbacks) OnStreamResponse(ctx context.Context, streamID int64, req *discovery.DiscoveryRequest, resp *discovery.DiscoveryResponse) {
	version := resp.GetVersionInfo()
	typeURL := resp.GetTypeUrl()
	nodeID := req.GetNode().GetId()

	var completed []*completion.Completion

	cb.mutex.Lock()

	if typeURL == NetworkPolicyTypeURL || typeURL == NetworkPolicyHostsTypeUrl {
		// Check if any completion has been registered for this type URL and node ID, and if so, update resource version.
		for _, pc := range cb.pendingCompletions {
			if pc.typeURL == typeURL && pc.nodeID == nodeID {
				cb.Log.Debug("Updating version completion for type URL and version",
					logfields.XDSTypeURL, pc.typeURL,
					logfields.Version, version,
					logfields.NodeID, nodeID)
				pc.version = version
			}
		}
	}

	if version == "" {
		cb.mutex.Unlock()
		return
	}

	key := completionsOrderKey(nodeID, typeURL)
	state := cb.responseStates[key]
	if state.pendingVersion == "" && state.acceptedVersion == version {
		state.rejectedVersion = ""
		state.rejectedErr = nil
		cb.responseStates[key] = state

		if vo, ok := cb.completionsOrders[key]; ok {
			completed = vo.completeUpTo(version)
			for _, c := range completed {
				delete(cb.pendingCompletions, c)
			}
			if vo.list.Len() == 0 {
				delete(cb.completionsOrders, key)
			}
		}
		for c, pc := range cb.pendingCompletions {
			if pc.typeURL == typeURL && pc.nodeID == nodeID && !pc.inCompletionsOrder {
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
	if state.rejectedVersion == version {
		state.rejectedVersion = ""
		state.rejectedErr = nil
	}
	cb.responseStates[key] = state

	// Add matching pending completions to the version order.
	for c, pc := range cb.pendingCompletions {
		if pc.typeURL == typeURL && pc.nodeID == nodeID && !pc.inCompletionsOrder {
			cb.addToCompletionsOrder(c, pc, version)
		}
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
