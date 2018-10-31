// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"errors"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	envoy_api_v2_core "github.com/cilium/proxy/go/envoy/api/v2/core"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
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
	ErrNackReceived error = errors.New("NACK received")
)

// ResourceVersionAckObserver defines the HandleResourceVersionAck method
// which is called whenever a node acknowledges having applied a version of
// the resources of a given type.
type ResourceVersionAckObserver interface {
	// HandleResourceVersionAck notifies that the node with the given Node ID
	// has acknowledged having applied the resources.
	// Calls to this function must not block.
	HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, node *envoy_api_v2_core.Node, resourceNames []string, typeURL string, detail string)
}

// AckingResourceMutatorRevertFunc is a function which reverts the effects of
// an update on a AckingResourceMutator.
// The completion is called back when the new resource update is
// ACKed by the Envoy nodes.
type AckingResourceMutatorRevertFunc func(completion *completion.Completion)

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
	Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, completion *completion.Completion) AckingResourceMutatorRevertFunc

	// Delete deletes a resource from this set by name and increases the cache's
	// version number atomically if the resource is actually deleted.
	// The completion is called back when the new deleted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Delete(typeURL string, resourceName string, nodeIDs []string, completion *completion.Completion) AckingResourceMutatorRevertFunc
}

// AckingResourceMutatorWrapper is an AckingResourceMutator which wraps a
// ResourceMutator to notifies callers when resource updates are ACKed by
// nodes.
// AckingResourceMutatorWrapper also implements ResourceVersionAckObserver in
// order to be notified of ACKs from nodes.
type AckingResourceMutatorWrapper struct {
	// mutator is the wrapped resource mutator.
	mutator ResourceMutator

	// nodeToID extracts a string identifier from an Envoy Node identifier in
	// an ACK notification, which is then compared to nodeIDs passed to Upsert
	// and Delete.
	nodeToID NodeToIDFunc

	// locker locks all accesses to pendingCompletions.
	locker lock.Mutex

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
// to wrap the given ResourceMutator. The given NodeToIDFunc is used to extract
// a string identifier from an Envoy Node identifier.
func NewAckingResourceMutatorWrapper(mutator ResourceMutator, nodeToID NodeToIDFunc) *AckingResourceMutatorWrapper {
	return &AckingResourceMutatorWrapper{
		mutator:            mutator,
		nodeToID:           nodeToID,
		pendingCompletions: make(map[*completion.Completion]*pendingCompletion),
	}
}

func (m *AckingResourceMutatorWrapper) addDeleteCompletion(typeURL string, version uint64, nodeIDs []string, c *completion.Completion) {
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

func (m *AckingResourceMutatorWrapper) Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, c *completion.Completion) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	version, _, revert := m.mutator.Upsert(typeURL, resourceName, resource, true)

	if c != nil {
		if _, found := m.pendingCompletions[c]; found {
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:      typeURL,
				logfields.XDSResourceName: resourceName,
			}).Fatalf("attempt to reuse completion to upsert xDS resource: %v", c)
		}

		comp := &pendingCompletion{
			version:                 version,
			typeURL:                 typeURL,
			remainingNodesResources: make(map[string]map[string]struct{}, len(nodeIDs)),
		}
		for _, nodeID := range nodeIDs {
			comp.remainingNodesResources[nodeID] = make(map[string]struct{}, 1)
			comp.remainingNodesResources[nodeID][resourceName] = struct{}{}
		}
		m.pendingCompletions[c] = comp
	}

	return func(completion *completion.Completion) {
		m.locker.Lock()
		defer m.locker.Unlock()

		version, _ := revert(true)

		if completion != nil {
			// We don't know whether the revert did an Upsert or a Delete, so as a
			// best effort, just wait for any ACK for the version and type URL,
			// and ignore the ACKed resource names, like for a Delete.
			m.addDeleteCompletion(typeURL, version, nodeIDs, completion)
		}
	}
}

func (m *AckingResourceMutatorWrapper) Delete(typeURL string, resourceName string, nodeIDs []string, c *completion.Completion) AckingResourceMutatorRevertFunc {
	m.locker.Lock()
	defer m.locker.Unlock()

	// Always delete the resource, even if the completion's context was
	// canceled before we even started, since we have no way to signal whether
	// the resource is actually deleted.

	// There is no explicit ACK for resource deletion in the xDS protocol.
	// As a best effort, just wait for any ACK for the version and type URL,
	// and ignore the ACKed resource names.

	version, _, revert := m.mutator.Delete(typeURL, resourceName, true)

	if c != nil {
		if _, found := m.pendingCompletions[c]; found {
			log.WithFields(logrus.Fields{
				logfields.XDSTypeURL:      typeURL,
				logfields.XDSResourceName: resourceName,
			}).Fatalf("attempt to reuse completion to delete xDS resource: %v", c)
		}

		m.addDeleteCompletion(typeURL, version, nodeIDs, c)
	}

	return func(completion *completion.Completion) {
		m.locker.Lock()
		defer m.locker.Unlock()

		version, _ := revert(true)

		if completion != nil {
			// We don't know whether the revert had any effect at all, so as a
			// best effort, just wait for any ACK for the version and type URL,
			// and ignore the ACKed resource names, like for a Delete.
			m.addDeleteCompletion(typeURL, version, nodeIDs, completion)
		}
	}
}

// 'ackVersion' is the last version that was acked. 'nackVersion', if greater than 'nackVersion', is the last version that was NACKed.
func (m *AckingResourceMutatorWrapper) HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, node *envoy_api_v2_core.Node, resourceNames []string, typeURL string, detail string) {
	ackLog := log.WithFields(logrus.Fields{
		logfields.XDSVersionInfo: ackVersion,
		logfields.XDSNonce:       nackVersion,
		logfields.XDSClientNode:  node,
		logfields.XDSTypeURL:     typeURL,
	})

	nodeID, err := m.nodeToID(node)
	if err != nil {
		// Ignore ACKs from unknown or misconfigured nodes which have invalid
		// node identifiers.
		ackLog.WithError(err).Warning("invalid ID in Node identifier; ignoring ACK")
		return
	}

	m.locker.Lock()
	defer m.locker.Unlock()

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
				remainingResourceNames, found := pending.remainingNodesResources[nodeID]
				if found {
					for _, name := range resourceNames {
						delete(remainingResourceNames, name)
					}
					if len(remainingResourceNames) == 0 {
						delete(pending.remainingNodesResources, nodeID)
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
