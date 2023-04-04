// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"sync"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/stream"
)

type LocalNode struct {
	types.Node
	// OptOutNodeEncryption will make the local node opt-out of node-to-node
	// encryption
	OptOutNodeEncryption bool
}

// LocalNodeInitializer specifies how to build the initial local node object.
type LocalNodeInitializer interface {
	InitLocalNode(*LocalNode) error
}

// LocalNodeStore is the canonical owner for the local node object and provides
// a reactive API for observing and updating the state.
type LocalNodeStore interface {
	// Changes to the local node are observable via Observe()
	stream.Observable[LocalNode]

	// Update modifies the local node with a mutator. The updated value
	// is passed to observers.
	Update(func(*LocalNode))

	// Get retrieves the current local node. Use Get() only for inspecting the state,
	// e.g. in API handlers. Do not assume the value does not change over time.
	// Blocks until the store has been initialized.
	Get() LocalNode
}

// LocalNodeStoreCell provides the LocalNodeStore instance.
// The LocalNodeStore is the canonical owner of `types.Node` for the local node and
// provides a reactive API for observing and updating it.
//
// This currently returns the singleton instance instead of constructing a fresh
// one with newLocalNodeStore() in order to keep the semantics of the global getters/setters
// as is.
var LocalNodeStoreCell = cell.Provide(
	func() LocalNodeStore { return localNode },
)

// LocalNodeStoreParams are the inputs needed for constructing LocalNodeStore.
type LocalNodeStoreParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Init      LocalNodeInitializer `optional:"true"`
}

// localNodeStore implements the LocalNodeStore using a simple in-memory
// backing. Reflecting the new state to persistent stores, e.g. kvstore or k8s
// is left to observers.
type localNodeStore struct {
	stream.Observable[LocalNode]

	mu   lock.Mutex
	cond *sync.Cond

	valid    bool
	value    LocalNode
	emit     func(LocalNode)
	complete func(error)
}

var _ LocalNodeStore = &localNodeStore{}

func NewLocalNodeStore(params LocalNodeStoreParams) (LocalNodeStore, error) {
	src, emit, complete := stream.Multicast[LocalNode](stream.EmitLatest)

	s := &localNodeStore{
		Observable: src,
	}
	s.cond = sync.NewCond(&s.mu)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if params.Init != nil {
				if err := params.Init.InitLocalNode(&s.value); err != nil {
					return err
				}
			}
			s.valid = true
			s.emit = emit
			s.complete = complete
			s.cond.Broadcast()
			emit(s.value)
			return nil
		},
		OnStop: func(hive.HookContext) error {
			s.mu.Lock()
			s.complete(nil)
			s.complete = nil
			s.emit = nil
			s.mu.Unlock()
			return nil
		},
	})

	return s, nil
}

// defaultLocalNodeStore constructs the default instance for the LocalNodeStore used by
// address.go.
func defaultLocalNodeStore() LocalNodeStore {
	src, emit, complete := stream.Multicast[LocalNode](stream.EmitLatest)
	s := &localNodeStore{
		Observable: src,
		valid:      true,
		emit:       emit,
		complete:   complete,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *localNodeStore) Get() LocalNode {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Block until the value has been initialized.
	for !s.valid {
		s.cond.Wait()
	}

	return s.value
}

func (s *localNodeStore) Update(update func(*LocalNode)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	update(&s.value)

	if s.emit != nil {
		s.emit(s.value)
	}
}
