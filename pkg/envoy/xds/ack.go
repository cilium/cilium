// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
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

var (
	ErrNackReceived = errors.New("NACK received")
)

// ResourceVersionAckObserver defines the HandleResourceVersionAck method
// which is called whenever a node acknowledges having applied a version of
// the resources of a given type.
type ResourceVersionAckObserver interface {
	// HandleResourceVersionAck notifies that the node with the given NodeIP
	// has acknowledged having applied the resources.
	// Calls to this function must not block.
	HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, nodeIP string, resourceNames []string, typeURL string, detail string)
}

// AckingResourceMutatorRevertFunc is a function which reverts the effects of
// an update on a AckingResourceMutator.
// The completion, if not nil, is called back when the new resource update is
// ACKed by the Envoy nodes.
type AckingResourceMutatorRevertFunc func(completion *completion.Completion)

type AckingResourceMutatorRevertFuncList []AckingResourceMutatorRevertFunc

func (rl AckingResourceMutatorRevertFuncList) Revert(wg *completion.WaitGroup) {
	// Revert the listed funcions in reverse order
	for i := len(rl) - 1; i >= 0; i-- {
		var c *completion.Completion
		if wg != nil {
			c = wg.AddCompletion()
		}
		rl[i](c)
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

	// UseCurrent inserts a completion that allows the caller to wait for the current
	// version of the given typeURL to be ACKed.
	UseCurrent(typeURL string, nodeIDs []string, wg *completion.WaitGroup)

	// DeleteNode frees resources held for the named node
	DeleteNode(nodeID string)

	// Delete deletes a resource from this set by name and increases the cache's
	// version number atomically if the resource is actually deleted.
	// The completion is called back when the new deleted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Delete(typeURL string, resourceName string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc
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
	// The key is the IPv4 address in string format for an Istio sidecar,
	// or "127.0.0.1" for the host proxy.
	ackedVersions map[string]uint64

	// pendingCompletions is the list of updates that are pending completion.
	pendingCompletions map[*completion.Completion]*pendingCompletion
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
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
	}
}

// AddVersionCompletion adds a completion to wait for any ACK for the
// version and type URL, ignoring the ACKed resource names.
func (m *AckingResourceMutatorWrapper) addVersionCompletion(typeURL string, version uint64, nodeIDs []string, c *completion.Completion) {
	comp := &pendingCompletion{
		version:                 version,
		typeURL:                 typeURL,
		remainingNodesResources: make(map[string]map[string]struct{}, len(nodeIDs)),
	}
	for _, nodeID := range nodeIDs {
		comp.remainingNodesResources[nodeID] = nil
	}
	m.pendingCompletions[c] = comp
}

// DeleteNode frees resources held for the named nodes
func (m *AckingResourceMutatorWrapper) DeleteNode(nodeID string) {
	m.locker.Lock()
	defer m.locker.Unlock()

	delete(m.ackedVersions, nodeID)
}

func (m *AckingResourceMutatorWrapper) Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	var updated bool
	var revert ResourceMutatorRevertFunc
	m.version, updated, revert = m.mutator.Upsert(typeURL, resourceName, resource)

	if !updated {
		if wg != nil {
			m.useCurrent(typeURL, nodeIDs, wg, callback)
		}
		return func(completion *completion.Completion) {}
	}

	if wg != nil {
		// Create a new completion
		c := wg.AddCompletionWithCallback(callback)
		if _, found := m.pendingCompletions[c]; found {
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:      typeURL,
				logfields.XDSResourceName: resourceName,
			}).Fatalf("attempt to reuse completion to upsert xDS resource: %v", c)
		}

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
	}

	// Returned revert function locks again, so it can NOT be called from 'callback' directly,
	// as 'callback' is called with the lock already held.
	return func(completion *completion.Completion) {
		m.locker.Lock()
		defer m.locker.Unlock()

		if revert != nil {
			m.version, _ = revert()

			if completion != nil {
				// We don't know whether the revert did an Upsert or a Delete, so as a
				// best effort, just wait for any ACK for the version and type URL,
				// and ignore the ACKed resource names, like for a Delete.
				m.addVersionCompletion(typeURL, m.version, nodeIDs, completion)
			}
		}
	}
}

func (m *AckingResourceMutatorWrapper) useCurrent(typeURL string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) {
	if !m.currentVersionAcked(nodeIDs) {
		// Add a completion object for 'version' so that the caller may wait for the N/ACK
		m.addVersionCompletion(typeURL, m.version, nodeIDs, wg.AddCompletionWithCallback(callback))
	}
}

// UseCurrent adds a completion to the WaitGroup if the current
// version of the cached resource has not been acked yet, allowing the
// caller to wait for the ACK.
func (m *AckingResourceMutatorWrapper) UseCurrent(typeURL string, nodeIDs []string, wg *completion.WaitGroup) {
	m.locker.Lock()
	defer m.locker.Unlock()

	m.useCurrent(typeURL, nodeIDs, wg, nil)
}

func (m *AckingResourceMutatorWrapper) currentVersionAcked(nodeIDs []string) bool {
	for _, node := range nodeIDs {
		if acked, exists := m.ackedVersions[node]; !exists || acked < m.version {
			ackLog := log.WithFields(logrus.Fields{
				logfields.XDSCachedVersion: m.version,
				logfields.XDSAckedVersion:  acked,
				logfields.XDSClientNode:    node,
			})
			ackLog.Debugf("Node has not acked the current cached version yet")
			return false
		}
	}
	return true
}

func (m *AckingResourceMutatorWrapper) Delete(typeURL string, resourceName string, nodeIDs []string, wg *completion.WaitGroup, callback func(error)) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	// Always delete the resource, even if the completion's context was
	// canceled before we even started, since we have no way to signal whether
	// the resource is actually deleted.

	// There is no explicit ACK for resource deletion in the xDS protocol.
	// As a best effort, just wait for any ACK for the version and type URL,
	// and ignore the ACKed resource names.

	var updated bool
	var revert ResourceMutatorRevertFunc
	m.version, updated, revert = m.mutator.Delete(typeURL, resourceName)

	if !updated {
		if wg != nil {
			m.useCurrent(typeURL, nodeIDs, wg, callback)
		}
		return func(completion *completion.Completion) {}
	}

	if wg != nil {
		c := wg.AddCompletionWithCallback(callback)
		if _, found := m.pendingCompletions[c]; found {
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:      typeURL,
				logfields.XDSResourceName: resourceName,
			}).Fatalf("attempt to reuse completion to delete xDS resource: %v", c)
		}

		m.addVersionCompletion(typeURL, m.version, nodeIDs, c)
	}

	return func(completion *completion.Completion) {
		m.locker.Lock()
		defer m.locker.Unlock()

		if revert != nil {
			m.version, _ = revert()

			if completion != nil {
				// We don't know whether the revert had any effect at all, so as a
				// best effort, just wait for any ACK for the version and type URL,
				// and ignore the ACKed resource names, like for a Delete.
				m.addVersionCompletion(typeURL, m.version, nodeIDs, completion)
			}
		}
	}
}

// 'ackVersion' is the last version that was acked. 'nackVersion', if greater than 'nackVersion', is the last version that was NACKed.
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
						// Completed. Notify and remove from pending list.
						if pending.version <= ackVersion {
							ackLog.Debugf("completing ACK: %v", pending)
							comp.Complete(nil)
						} else {
							ackLog.Debugf("completing NACK: %v", pending)
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
