// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ProxyError wraps the error and the detail received from the proxy in to a new type
// that implements the error interface.
type ProxyError struct {
	Err    error
	Detail string
}

func (pe *ProxyError) Error() string {
	return pe.Err.Error() + ": " + pe.Detail
}

var ErrNackReceived = errors.New("NACK received")

// ResourceVersionAckObserver defines the HandleResourceVersionAck method
// which is called whenever a node acknowledges having applied a version of
// the resources of a given type.
type ResourceVersionAckObserver interface {
	// HandleResourceVersionAck notifies that the node with the given NodeIP
	// has acknowledged having applied the resources.
	// Calls to this function must not block.
	HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, nodeIP string, resourceNames []string, typeURL string, detail string)

	// MarkRestorePending informs the observer about a pending state restoration.
	MarkRestorePending()

	// MarkRestoreCompleted clears the 'restore' state so that updates are acked normally.
	MarkRestoreCompleted()

	// WaitForFirstAck() blocks until the given node has acked the first ACK.
	WaitForFirstAck(ctx context.Context, node string, typeURL string)
}

// AckingResourceMutatorRevertFunc is a function which reverts the effects of
// an update on a AckingResourceMutator.
type AckingResourceMutatorRevertFunc func()

type AckingResourceMutatorRevertFuncList []AckingResourceMutatorRevertFunc

func (rl AckingResourceMutatorRevertFuncList) Revert() {
	// Revert the listed funcions in reverse order
	for i := len(rl) - 1; i >= 0; i-- {
		rl[i]()
	}
}

// AckingResourceMutator is a variant of ResourceMutator which calls back a
// Completion when a resource update is ACKed by a set of Envoy nodes.
type AckingResourceMutator interface {
	// Upsert inserts or updates a resource from this set by name and increases
	// the set's version number atomically if the resource is actually inserted
	// or updated.
	// The completion is called back when the new upserted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc

	// DeleteNode frees resources held for the named node
	DeleteNode(nodeID string)

	// Delete deletes a resource from this set by name and increases the cache's
	// version number atomically if the resource is actually deleted.
	// The completion is called back when the new deleted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Delete(typeURL string, resourceName string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc

	// CancelCompletions completes all pending completions on the given TypeURL.
	// Called only when it is known that the TypeURL client has stopped processing updates.
	// Completions are completed without an error, as the resource updater can not react in
	// any way to the resource client going away.
	CancelCompletions(typeURL string)
}

// AckingResourceMutatorWrapper is an AckingResourceMutator which wraps a
// ResourceMutator to notifies callers when resource updates are ACKed by
// nodes.
// AckingResourceMutatorWrapper also implements ResourceVersionAckObserver in
// order to be notified of ACKs from nodes.
type AckingResourceMutatorWrapper struct {
	// mutator is the wrapped resource mutator.
	mutator ResourceMutator

	// locker locks all accesses to the remaining fields.
	locker lock.Mutex

	// Last version stored by 'mutator'
	version uint64

	// ackedVersions is the last version acked by a node for this cache.
	// The key is the IPv4 address of the Envoy instance in string format.
	// e.g. "127.0.0.1" for the host proxy.
	ackedVersions map[string]uint64

	// ackedNodes has a channel for each node for which someone is waiting for the first ACK to
	// be received. The channel is closed after the first ACK has been received, and set to
	// 'nil' to avoid closing the channel more than once.
	ackedNodes map[string]chan struct{}

	// pendingCompletions is the list of updates that are pending completion.
	pendingCompletions map[*completion.Completion]*pendingCompletion

	// restoring controls waiting for acks. When 'true' updates do not wait for acks from the xDS client,
	// as xDS caches are pre-populated before passing any resources to xDS clients.
	restoring bool
}

// pendingCompletion is an update that is pending completion.
type pendingCompletion struct {
	// version is the version to be ACKed.
	version uint64

	// typeURL is the type URL of the resources to be ACKed.
	typeURL string

	// remainingNodesResources maps each pending node ID to pending resource
	// name.
	remainingNodesResources map[string]map[string]struct{}
}

// NewAckingResourceMutatorWrapper creates a new AckingResourceMutatorWrapper
// to wrap the given ResourceMutator.
func NewAckingResourceMutatorWrapper(mutator ResourceMutator) *AckingResourceMutatorWrapper {
	return &AckingResourceMutatorWrapper{
		mutator:            mutator,
		ackedVersions:      make(map[string]uint64),
		ackedNodes:         make(map[string]chan struct{}),
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
	}
}

func (m *AckingResourceMutatorWrapper) MarkRestorePending() {
	m.locker.Lock()
	defer m.locker.Unlock()

	m.restoring = true
}

// MarkRestoreCompleted clears the 'restore' state so that updates are acked normally.
func (m *AckingResourceMutatorWrapper) MarkRestoreCompleted() {
	m.locker.Lock()
	defer m.locker.Unlock()

	m.restoring = false
}

func (m *AckingResourceMutatorWrapper) WaitForFirstAck(ctx context.Context, node string, typeURL string) {
	// No wait if there are no resources of the given type
	if !m.mutator.HasAny(typeURL) {
		return
	}

	m.locker.Lock()
	ch, exists := m.ackedNodes[node]
	// This can happen before the first request from the node is received, so we must initialize
	// a channel here if one does not exist for the node.
	if !exists {
		ch = make(chan struct{})
		m.ackedNodes[node] = ch
	}
	m.locker.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.XDSClientNode: node,
		logfields.XDSTypeURL:    typeURL,
	})

	// ch can be 'nil' to avoid closing the channel more than once. If so, the first ACK has
	// already been received.
	if ch == nil {
		logger.Info("WaitForFirstAck: first ACK has already been received, no need to wait")
		return
	}

	logger.Info("WaitForFirstAck: Waiting until first ACK has been received")
	// wait after m.locker has been released!
	select {
	case <-ctx.Done():
		logger.Info("WaitForFirstAck: canceling wait for the first ACK due to expired context")
	case <-ch:
		// ACK was received
		logger.Info("WaitForFirstAck: resuming after receiving the first ACK")
	}
}

// addCurrentVersionCompletion adds a completion to wait for any ACK for the
// version and type URL for the given nodes, ignoring the ACKed resource names.
// Nodes that have already acked the version are skipped. No completion is added if all nodes have
// already acked the given version.
// Returns true if the caller should wait for an ACK.
func (m *AckingResourceMutatorWrapper) addCurrentVersionCompletion(typeURL string, nodeIPs []string, wg *completion.WaitGroup, callback func(error)) bool {
	remainingNodesResources := make(map[string]map[string]struct{}, len(nodeIPs))
	for _, nodeIP := range nodeIPs {
		if acked, exists := m.ackedVersions[nodeIP]; exists && acked >= m.version {
			log.WithFields(logrus.Fields{
				logfields.XDSCachedVersion: m.version,
				logfields.XDSAckedVersion:  acked,
				logfields.XDSClientNode:    nodeIP,
			}).Debug("Skipping node that has already ACKed version")
			continue
		}
		remainingNodesResources[nodeIP] = nil
	}
	if len(remainingNodesResources) == 0 {
		return false
	}

	comp := &pendingCompletion{
		version:                 m.version,
		typeURL:                 typeURL,
		remainingNodesResources: remainingNodesResources,
	}
	c := wg.AddCompletionWithCallback(callback)
	m.pendingCompletions[c] = comp
	return true
}

func (m *AckingResourceMutatorWrapper) maybeAddCurrentVersionCompletion(wait bool, typeURL string, nodeIPs []string, wg *completion.WaitGroup, callback func(error)) {
	if wait {
		wait = m.addCurrentVersionCompletion(typeURL, nodeIPs, wg, callback)
	}

	// Call callback immediately if there was nothing to wait for
	if !wait && callback != nil {
		callback(nil)
	}
}

// DeleteNode frees resources held for the named nodes
func (m *AckingResourceMutatorWrapper) DeleteNode(nodeID string) {
	m.locker.Lock()
	defer m.locker.Unlock()

	delete(m.ackedVersions, nodeID)
	if ch, exists := m.ackedNodes[nodeID]; exists && ch != nil {
		close(ch)
	}
	delete(m.ackedNodes, nodeID)
}

// CancelCompletions is called after it is known the xDS client has been terminated, so that waiting
// for any N/ACKs is futile. Full resource sync will happen when the xDS client start again (if it
// does). Completions are terminated without an error, as there is nothing do, even it an error
// status was used instead. This mirrors the behavior when it is known the xDS client has not yet
// been started, when we do not even try to wait for any N/ACKs.
func (m *AckingResourceMutatorWrapper) CancelCompletions(typeURL string) {
	m.locker.Lock()
	defer m.locker.Unlock()

	for comp, pending := range m.pendingCompletions {
		if comp.Err() != nil {
			// Completion was canceled or timed out.
			// Remove from pending list.
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:         typeURL,
				logfields.PendingCompletions: pending,
			}).Debug("completion context was canceled")
			delete(m.pendingCompletions, comp)
			continue
		}

		if pending.typeURL == typeURL {
			clear(pending.remainingNodesResources)
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:  typeURL,
				logfields.WaitVersion: pending.version,
			}).Debug("completing cancel")
			comp.Complete(nil)
			delete(m.pendingCompletions, comp)
			continue
		}
	}
}

func (m *AckingResourceMutatorWrapper) Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	wait := wg != nil

	if m.restoring {
		// Do not wait for acks when restoring state
		log.WithFields(logrus.Fields{
			logfields.XDSTypeURL:      typeURL,
			logfields.XDSResourceName: resourceName,
		}).Debug("Upsert: Restoring, skipping wait for ACK")

		wait = false
	}

	var updated bool
	var revert ResourceMutatorRevertFunc
	m.version, updated, revert = m.mutator.Upsert(typeURL, resourceName, resource)

	if !updated {
		// Add a completion object for the current version so that the caller may wait for
		// the N/ACK
		m.maybeAddCurrentVersionCompletion(wait, typeURL, nodeIDs, wg, callback)
		return func() {}
	}

	if wait {
		// Create a new completion
		c := wg.AddCompletionWithCallback(callback)

		comp := &pendingCompletion{
			version:                 m.version,
			typeURL:                 typeURL,
			remainingNodesResources: make(map[string]map[string]struct{}, len(nodeIDs)),
		}
		for _, nodeID := range nodeIDs {
			comp.remainingNodesResources[nodeID] = make(map[string]struct{}, 1)
			comp.remainingNodesResources[nodeID][resourceName] = struct{}{}
		}
		m.pendingCompletions[c] = comp
	} else if callback != nil {
		callback(nil)
	}

	// Returned revert function locks again, so it can NOT be called from 'callback' directly,
	// as 'callback' is called with the lock already held.
	if revert != nil {
		return func() {
			m.locker.Lock()
			defer m.locker.Unlock()
			m.version, _ = revert()
		}
	}
	return func() {}
}

func (m *AckingResourceMutatorWrapper) Delete(typeURL string, resourceName string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	wait := wg != nil

	if m.restoring {
		// Do not wait for acks when restoring state
		log.WithFields(logrus.Fields{
			logfields.XDSTypeURL:      typeURL,
			logfields.XDSResourceName: resourceName,
		}).Debug("Delete: Restoring, skipping wait for ACK")

		wait = false
	}

	// Always delete the resource, even if the completion's context was
	// canceled before we even started, since we have no way to signal whether
	// the resource is actually deleted.

	// There is no explicit ACK for resource deletion in the xDS protocol.
	// As a best effort, just wait for any ACK for the version and type URL,
	// and ignore the ACKed resource names.

	var updated bool
	var revert ResourceMutatorRevertFunc
	m.version, updated, revert = m.mutator.Delete(typeURL, resourceName)

	// remove any possible pending completions for the deleted resourceName
	for comp, pending := range m.pendingCompletions {
		if comp.Err() != nil {
			// Completion was canceled or timed out.
			// Remove from pending list.
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:      typeURL,
				logfields.XDSResourceName: resourceName,
			}).Debugf("completion context was canceled: %v", pending)
			delete(m.pendingCompletions, comp)
			continue
		}
		if pending.typeURL == typeURL {
			for _, resourceNames := range pending.remainingNodesResources {
				// resourceNames map is left in place even if empty, so that
				// it can be found by HandleResourceVersionAck to complete
				// the pending completion when an N/ACK is received
				delete(resourceNames, resourceName)
			}
		}
	}

	// Add a completion object for the current version so that the caller may wait for the N/ACK
	m.maybeAddCurrentVersionCompletion(wait, typeURL, nodeIDs, wg, callback)

	if updated && revert != nil {
		return func() {
			m.locker.Lock()
			defer m.locker.Unlock()
			m.version, _ = revert()
		}
	}
	return func() {}
}

// 'ackVersion' is the last version that was acked. 'nackVersion', if greater than 'ackVersion', is the last version that was NACKed.
func (m *AckingResourceMutatorWrapper) HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, nodeIP string, resourceNames []string, typeURL string, detail string) {
	ackLog := log.WithFields(logrus.Fields{
		logfields.XDSAckedVersion: ackVersion,
		logfields.XDSNonce:        nackVersion,
		logfields.XDSClientNode:   nodeIP,
		logfields.XDSTypeURL:      typeURL,
	})

	m.locker.Lock()
	defer m.locker.Unlock()

	// Update the last seen ACKed version if it advances the previously ACKed version.
	// Version 0 is special as it indicates that we have received the first xDS
	// resource request from Envoy. Prior to that we do not have a map entry for the
	// node at all.
	if previouslyAckedVersion, exists := m.ackedVersions[nodeIP]; !exists || previouslyAckedVersion < ackVersion {
		m.ackedVersions[nodeIP] = ackVersion

		// Signal reception of an ACK (exluding the version 0, or any NACKs).
		if previouslyAckedVersion < ackVersion {
			ch, exists := m.ackedNodes[nodeIP]
			if !exists || ch != nil {
				log.WithFields(logrus.Fields{
					logfields.XDSClientNode:   nodeIP,
					logfields.XDSTypeURL:      typeURL,
					logfields.XDSAckedVersion: ackVersion,
				}).Info("HandleResourceVersionAck: first ACK received")
			}
			// nil the channel (if any) to mark the reception of the ACK
			m.ackedNodes[nodeIP] = nil
			if exists && ch != nil {
				// Wake up any waiters
				close(ch)
			}
		}
	}

	remainingCompletions := make(map[*completion.Completion]*pendingCompletion, len(m.pendingCompletions))

	for comp, pending := range m.pendingCompletions {
		if comp.Err() != nil {
			// Completion was canceled or timed out.
			// Remove from pending list.
			ackLog.Debugf("completion context was canceled: %v", pending)
			continue
		}

		if pending.typeURL == typeURL {
			if pending.version <= nackVersion {
				// Get the set of resource names we are still waiting for the node
				// to ACK.
				remainingResourceNames, found := pending.remainingNodesResources[nodeIP]
				if found {
					for _, name := range resourceNames {
						delete(remainingResourceNames, name)
					}
					if len(remainingResourceNames) == 0 {
						delete(pending.remainingNodesResources, nodeIP)
					}
					if len(pending.remainingNodesResources) == 0 {
						// completedComparision. Notify and remove from pending list.
						if pending.version <= ackVersion {
							ackLog.Debugf("completing ACK: %v", pending)
							comp.Complete(nil)
						} else {
							ackLog.Warningf("completing NACK: %v", pending)
							comp.Complete(&ProxyError{Err: ErrNackReceived, Detail: detail})
						}
						continue
					}
				}
			}
		}

		// Completion didn't match or is still waiting for some ACKs. Keep it
		// in the pending list.
		remainingCompletions[comp] = pending
	}

	m.pendingCompletions = remainingCompletions
}
