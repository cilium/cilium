/*
Copyright The ORAS Authors.
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

package graph

import (
	"context"
	"errors"
	"sync"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/container/set"
	"oras.land/oras-go/v2/internal/descriptor"
	"oras.land/oras-go/v2/internal/status"
	"oras.land/oras-go/v2/internal/syncutil"
)

// Memory is a memory based PredecessorFinder.
type Memory struct {
	// nodes has the following properties and behaviors:
	//  1. a node exists in Memory.nodes if and only if it exists in the memory
	//  2. Memory.nodes saves the ocispec.Descriptor map keys, which are used by
	//    the other fields.
	nodes map[descriptor.Descriptor]ocispec.Descriptor

	// predecessors has the following properties and behaviors:
	//  1. a node exists in Memory.predecessors if it has at least one predecessor
	//    in the memory, regardless of whether or not the node itself exists in
	//    the memory.
	//  2. a node does not exist in Memory.predecessors, if it doesn't have any predecessors
	//    in the memory.
	predecessors map[descriptor.Descriptor]set.Set[descriptor.Descriptor]

	// successors has the following properties and behaviors:
	//  1. a node exists in Memory.successors if and only if it exists in the memory.
	//  2. a node's entry in Memory.successors is always consistent with the actual
	//    content of the node, regardless of whether or not each successor exists
	//    in the memory.
	successors map[descriptor.Descriptor]set.Set[descriptor.Descriptor]

	lock sync.RWMutex
}

// NewMemory creates a new memory PredecessorFinder.
func NewMemory() *Memory {
	return &Memory{
		nodes:        make(map[descriptor.Descriptor]ocispec.Descriptor),
		predecessors: make(map[descriptor.Descriptor]set.Set[descriptor.Descriptor]),
		successors:   make(map[descriptor.Descriptor]set.Set[descriptor.Descriptor]),
	}
}

// Index indexes predecessors for each direct successor of the given node.
func (m *Memory) Index(ctx context.Context, fetcher content.Fetcher, node ocispec.Descriptor) error {
	_, err := m.index(ctx, fetcher, node)
	return err
}

// Index indexes predecessors for all the successors of the given node.
func (m *Memory) IndexAll(ctx context.Context, fetcher content.Fetcher, node ocispec.Descriptor) error {
	// track content status
	tracker := status.NewTracker()
	var fn syncutil.GoFunc[ocispec.Descriptor]
	fn = func(ctx context.Context, region *syncutil.LimitedRegion, desc ocispec.Descriptor) error {
		// skip the node if other go routine is working on it
		_, committed := tracker.TryCommit(desc)
		if !committed {
			return nil
		}
		successors, err := m.index(ctx, fetcher, desc)
		if err != nil {
			if errors.Is(err, errdef.ErrNotFound) {
				// skip the node if it does not exist
				return nil
			}
			return err
		}
		if len(successors) > 0 {
			// traverse and index successors
			return syncutil.Go(ctx, nil, fn, successors...)
		}
		return nil
	}
	return syncutil.Go(ctx, nil, fn, node)
}

// Predecessors returns the nodes directly pointing to the current node.
// Predecessors returns nil without error if the node does not exists in the
// store. Like other operations, calling Predecessors() is go-routine safe.
// However, it does not necessarily correspond to any consistent snapshot of
// the stored contents.
func (m *Memory) Predecessors(_ context.Context, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	key := descriptor.FromOCI(node)
	set, exists := m.predecessors[key]
	if !exists {
		return nil, nil
	}
	var res []ocispec.Descriptor
	for k := range set {
		res = append(res, m.nodes[k])
	}
	return res, nil
}

// Remove removes the node from its predecessors and successors, and returns the
// dangling root nodes caused by the deletion.
func (m *Memory) Remove(node ocispec.Descriptor) []ocispec.Descriptor {
	m.lock.Lock()
	defer m.lock.Unlock()

	nodeKey := descriptor.FromOCI(node)
	var danglings []ocispec.Descriptor
	// remove the node from its successors' predecessor list
	for successorKey := range m.successors[nodeKey] {
		predecessorEntry := m.predecessors[successorKey]
		predecessorEntry.Delete(nodeKey)

		// if none of the predecessors of the node still exists, we remove the
		// predecessors entry and return it as a dangling node. Otherwise, we do
		// not remove the entry.
		if len(predecessorEntry) == 0 {
			delete(m.predecessors, successorKey)
			if _, exists := m.nodes[successorKey]; exists {
				danglings = append(danglings, m.nodes[successorKey])
			}
		}
	}
	delete(m.successors, nodeKey)
	delete(m.nodes, nodeKey)
	return danglings
}

// DigestSet returns the set of node digest in memory.
func (m *Memory) DigestSet() set.Set[digest.Digest] {
	m.lock.RLock()
	defer m.lock.RUnlock()

	s := set.New[digest.Digest]()
	for desc := range m.nodes {
		s.Add(desc.Digest)
	}
	return s
}

// index indexes predecessors for each direct successor of the given node.
func (m *Memory) index(ctx context.Context, fetcher content.Fetcher, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	successors, err := content.Successors(ctx, fetcher, node)
	if err != nil {
		return nil, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()

	// index the node
	nodeKey := descriptor.FromOCI(node)
	m.nodes[nodeKey] = node

	// for each successor, put it into the node's successors list, and
	// put node into the succeesor's predecessors list
	successorSet := set.New[descriptor.Descriptor]()
	m.successors[nodeKey] = successorSet
	for _, successor := range successors {
		successorKey := descriptor.FromOCI(successor)
		successorSet.Add(successorKey)
		predecessorSet, exists := m.predecessors[successorKey]
		if !exists {
			predecessorSet = set.New[descriptor.Descriptor]()
			m.predecessors[successorKey] = predecessorSet
		}
		predecessorSet.Add(nodeKey)
	}
	return successors, nil
}

// Exists checks if the node exists in the graph
func (m *Memory) Exists(node ocispec.Descriptor) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()

	nodeKey := descriptor.FromOCI(node)
	_, exists := m.nodes[nodeKey]
	return exists
}
