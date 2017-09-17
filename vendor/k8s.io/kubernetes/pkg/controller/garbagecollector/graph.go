/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package garbagecollector

import (
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type objectReference struct {
	metav1.OwnerReference
	// This is needed by the dynamic client
	Namespace string
}

func (s objectReference) String() string {
	return fmt.Sprintf("[%s/%s, namespace: %s, name: %s, uid: %s]", s.APIVersion, s.Kind, s.Namespace, s.Name, s.UID)
}

// The single-threaded GraphBuilder.processGraphChanges() is the sole writer of the
// nodes. The multi-threaded GarbageCollector.attemptToDeleteItem() reads the nodes.
// WARNING: node has different locks on different fields. setters and getters
// use the respective locks, so the return values of the getters can be
// inconsistent.
type node struct {
	identity objectReference
	// dependents will be read by the orphan() routine, we need to protect it with a lock.
	dependentsLock sync.RWMutex
	// dependents are the nodes that have node.identity as a
	// metadata.ownerReference.
	dependents map[*node]struct{}
	// this is set by processGraphChanges() if the object has non-nil DeletionTimestamp
	// and has the FinalizerDeleteDependents.
	deletingDependents     bool
	deletingDependentsLock sync.RWMutex
	// this records if the object's deletionTimestamp is non-nil.
	beingDeleted     bool
	beingDeletedLock sync.RWMutex
	// when processing an Update event, we need to compare the updated
	// ownerReferences with the owners recorded in the graph.
	owners []metav1.OwnerReference
}

// An object is on a one way trip to its final deletion if it starts being
// deleted, so we only provide a function to set beingDeleted to true.
func (n *node) markBeingDeleted() {
	n.beingDeletedLock.Lock()
	defer n.beingDeletedLock.Unlock()
	n.beingDeleted = true
}

func (n *node) isBeingDeleted() bool {
	n.beingDeletedLock.RLock()
	defer n.beingDeletedLock.RUnlock()
	return n.beingDeleted
}

func (n *node) markDeletingDependents() {
	n.deletingDependentsLock.Lock()
	defer n.deletingDependentsLock.Unlock()
	n.deletingDependents = true
}

func (n *node) isDeletingDependents() bool {
	n.deletingDependentsLock.RLock()
	defer n.deletingDependentsLock.RUnlock()
	return n.deletingDependents
}

func (ownerNode *node) addDependent(dependent *node) {
	ownerNode.dependentsLock.Lock()
	defer ownerNode.dependentsLock.Unlock()
	ownerNode.dependents[dependent] = struct{}{}
}

func (ownerNode *node) deleteDependent(dependent *node) {
	ownerNode.dependentsLock.Lock()
	defer ownerNode.dependentsLock.Unlock()
	delete(ownerNode.dependents, dependent)
}

func (ownerNode *node) dependentsLength() int {
	ownerNode.dependentsLock.RLock()
	defer ownerNode.dependentsLock.RUnlock()
	return len(ownerNode.dependents)
}

// Note that this function does not provide any synchronization guarantees;
// items could be added to or removed from ownerNode.dependents the moment this
// function returns.
func (ownerNode *node) getDependents() []*node {
	ownerNode.dependentsLock.RLock()
	defer ownerNode.dependentsLock.RUnlock()
	var ret []*node
	for dep := range ownerNode.dependents {
		ret = append(ret, dep)
	}
	return ret
}

// blockingDependents returns the dependents that are blocking the deletion of
// n, i.e., the dependent that has an ownerReference pointing to n, and
// the BlockOwnerDeletion field of that ownerReference is true.
// Note that this function does not provide any synchronization guarantees;
// items could be added to or removed from ownerNode.dependents the moment this
// function returns.
func (n *node) blockingDependents() []*node {
	dependents := n.getDependents()
	var ret []*node
	for _, dep := range dependents {
		for _, owner := range dep.owners {
			if owner.UID == n.identity.UID && owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion {
				ret = append(ret, dep)
			}
		}
	}
	return ret
}

// String renders node as a string using fmt. Acquires a read lock to ensure the
// reflective dump of dependents doesn't race with any concurrent writes.
func (n *node) String() string {
	n.dependentsLock.RLock()
	defer n.dependentsLock.RUnlock()
	return fmt.Sprintf("%#v", n)
}

type concurrentUIDToNode struct {
	uidToNodeLock sync.RWMutex
	uidToNode     map[types.UID]*node
}

func (m *concurrentUIDToNode) Write(node *node) {
	m.uidToNodeLock.Lock()
	defer m.uidToNodeLock.Unlock()
	m.uidToNode[node.identity.UID] = node
}

func (m *concurrentUIDToNode) Read(uid types.UID) (*node, bool) {
	m.uidToNodeLock.RLock()
	defer m.uidToNodeLock.RUnlock()
	n, ok := m.uidToNode[uid]
	return n, ok
}

func (m *concurrentUIDToNode) Delete(uid types.UID) {
	m.uidToNodeLock.Lock()
	defer m.uidToNodeLock.Unlock()
	delete(m.uidToNode, uid)
}
