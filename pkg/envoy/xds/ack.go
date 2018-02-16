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
	"github.com/cilium/cilium/pkg/completion"
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
)

// ResourceVersionAckObserver defines the HandleResourceVersionAck method
// which is called whenever a node acknowledges having applied a version of
// the resources of a given type.
type ResourceVersionAckObserver interface {
	// HandleResourceVersionAck notifies that the node with the given Node ID
	// has acknowledged having applied the resources.
	// Calls to this function must not block.
	HandleResourceVersionAck(version uint64, node *envoy_api_v2_core.Node, resourceNames []string, typeURL string)
}

// AckingResourceMutator is a variant of ResourceMutator which calls back a
// Completion when a resource update is ACKed by a set of Envoy nodes.
type AckingResourceMutator interface {
	// Upsert inserts or updates a resource from this set by name and increases
	// the set's version number atomically if the resource is actually inserted
	// or updated.
	// The completion is called back when the new upserted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, completion *completion.Completion)

	// Delete deletes a resource from this set by name and increases the cache's
	// version number atomically if the resource is actually deleted.
	// The completion is called back when the new deleted resources' version is
	// ACKed by the Envoy nodes which IDs are given in nodeIDs.
	Delete(typeURL string, resourceName string, nodeIDs []string, completion *completion.Completion)
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
	pendingCompletions []*pendingCompletion
}

// pendingCompletion is an update that is pending completion.
type pendingCompletion struct {
	// completion is the Completion given in the update call.
	completion *completion.Completion

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
		mutator:  mutator,
		nodeToID: nodeToID,
	}
}

func (m *AckingResourceMutatorWrapper) Upsert(typeURL string, resourceName string, resource proto.Message, nodeIDs []string, completion *completion.Completion) {
	m.locker.Lock()
	defer m.locker.Unlock()

	if completion.Context().Err() != nil {
		// The context was canceled before we even started.
		log.WithFields(logrus.Fields{
			logfields.XDSTypeURL: typeURL,
		}).Warnf("context cancelled: %s", completion.Context().Err())
		return
	}

	version, _ := m.mutator.Upsert(typeURL, resourceName, resource, true)

	comp := &pendingCompletion{
		completion:              completion,
		version:                 version,
		typeURL:                 typeURL,
		remainingNodesResources: make(map[string]map[string]struct{}, len(nodeIDs)),
	}

	for _, nodeID := range nodeIDs {
		comp.remainingNodesResources[nodeID] = make(map[string]struct{}, 1)
		comp.remainingNodesResources[nodeID][resourceName] = struct{}{}
	}

	m.pendingCompletions = append(m.pendingCompletions, comp)
}

func (m *AckingResourceMutatorWrapper) Delete(typeURL string, resourceName string, nodeIDs []string, completion *completion.Completion) {
	m.locker.Lock()
	defer m.locker.Unlock()

	if completion.Context().Err() != nil {
		// The context was canceled before we even started.
		log.WithFields(logrus.Fields{
			logfields.XDSTypeURL: typeURL,
		}).Warnf("context cancelled: %s", completion.Context().Err())
		return
	}

	// There is no explicit ACK for resource deletion in the xDS protocol.
	// As a best effort, just wait for any ACK for the version and type URL,
	// and ignore the ACKed resource names.

	version, _ := m.mutator.Delete(typeURL, resourceName, true)

	comp := &pendingCompletion{
		completion:              completion,
		version:                 version,
		typeURL:                 typeURL,
		remainingNodesResources: make(map[string]map[string]struct{}, len(nodeIDs)),
	}

	for _, nodeID := range nodeIDs {
		comp.remainingNodesResources[nodeID] = nil
	}

	m.pendingCompletions = append(m.pendingCompletions, comp)
}

func (m *AckingResourceMutatorWrapper) HandleResourceVersionAck(version uint64, node *envoy_api_v2_core.Node, resourceNames []string, typeURL string) {
	ackLog := log.WithFields(logrus.Fields{
		logfields.XDSVersionInfo: version,
		logfields.XDSClientNode:  node,
		logfields.XDSTypeURL:     typeURL,
	})

	nodeID, err := m.nodeToID(node)
	if err != nil {
		// Ignore ACKs from unknown or misconfigured nodes which have invalid
		// node identifiers.
		ackLog.Warning("invalid ID in Node identifier; ignoring ACK")
		return
	}

	m.locker.Lock()
	defer m.locker.Unlock()

	remainingCompletions := make([]*pendingCompletion, 0, len(m.pendingCompletions))

	for _, comp := range m.pendingCompletions {
		if comp.completion.Context().Err() != nil {
			// Completion was canceled or timed out.
			// Remove from pending list.
			ackLog.Debugf("completion context was canceled: %v", comp)
			continue
		}

		if comp.version <= version && comp.typeURL == typeURL {
			// Get the set of resource names we are still waiting for the node
			// to ACK.
			remainingResourceNames, found := comp.remainingNodesResources[nodeID]
			if found {
				for _, name := range resourceNames {
					delete(remainingResourceNames, name)
				}
				if len(remainingResourceNames) == 0 {
					delete(comp.remainingNodesResources, nodeID)
				}
				if len(comp.remainingNodesResources) == 0 {
					// Completed. Notify and remove from pending list.
					ackLog.Debug("completing ACK: %v", comp)
					comp.completion.Complete()
					continue
				}

			}
		}

		// Completion didn't match or is still waiting for some ACKs. Keep it
		// in the pending list.
		remainingCompletions = append(remainingCompletions, comp)
	}

	m.pendingCompletions = remainingCompletions
}
