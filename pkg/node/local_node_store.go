// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"io"
	"sync"

	"github.com/cilium/stream"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/types"
)

type LocalNode struct {
	types.Node
	// OptOutNodeEncryption will make the local node opt-out of node-to-node
	// encryption
	OptOutNodeEncryption bool
	// Unique identifier of the Kubernetes node, used to construct the
	// corresponding owner reference.
	UID k8stypes.UID
	// ID of the node assigned by the cloud provider.
	ProviderID string
}

// LocalNodeSynchronizer specifies how to build, and keep synchronized the local
// node object.
type LocalNodeSynchronizer interface {
	InitLocalNode(context.Context, *LocalNode) error
	SyncLocalNode(context.Context, *LocalNodeStore)
}

// LocalNodeStoreCell provides the LocalNodeStore instance.
// The LocalNodeStore is the canonical owner of `types.Node` for the local node and
// provides a reactive API for observing and updating it.
var LocalNodeStoreCell = cell.Module(
	"local-node-store",
	"Provides LocalNodeStore for observing and updating local node info",

	cell.Provide(NewLocalNodeStore),
)

// LocalNodeStoreParams are the inputs needed for constructing LocalNodeStore.
type LocalNodeStoreParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Sync      LocalNodeSynchronizer `optional:"true"`
}

// LocalNodeStore is the canonical owner for the local node object and provides
// a reactive API for observing and updating the state.
type LocalNodeStore struct {
	// Changes to the local node are observable.
	stream.Observable[LocalNode]

	// mu is the main LocalNodeStore mutex, which protects the access to the
	// different fields during all operations. getMu, instead, is a separate
	// mutex which is used to guard updates of the value field, as well as its
	// access by the Get() method. The reason for using two separate mutexes
	// being that we don't want Get() to be blocked while calling emit, as
	// that synchronously calls into all subscribers, which is a potentially
	// expensive operation, and a possible source of deadlocks (e.g., one of
	// the subscribers needs to acquire another mutex, which is held by a
	// separate goroutine trying to call LocalNodeStore.Get()). In addition,
	// getMu also guards the complete field, as it is used by Get() to
	// determine that the LocalNodeStore was stopped. When both mu and getMu
	// are to be acquired together, mu shall be always acquired first.
	mu    lock.Mutex
	getMu lock.RWMutex

	value    LocalNode
	hasValue <-chan struct{}
	emit     func(LocalNode)
	complete func(error)
}

func NewTestLocalNodeStore(mockNode LocalNode) *LocalNodeStore {
	src, emit, complete := stream.Multicast[LocalNode](stream.EmitLatest)
	emit(mockNode)
	return &LocalNodeStore{
		Observable: src,
		emit:       emit,
		complete:   complete,
		value:      mockNode,
		hasValue: func() <-chan struct{} {
			ch := make(chan struct{})
			close(ch)
			return ch
		}(),
	}
}

func NewLocalNodeStore(params LocalNodeStoreParams) (*LocalNodeStore, error) {
	src, emit, complete := stream.Multicast[LocalNode](stream.EmitLatest)
	hasValue := make(chan struct{})

	s := &LocalNodeStore{
		Observable: src,
		value: LocalNode{Node: types.Node{
			// Explicitly initialize the labels and annotations maps, so that
			// we don't need to always check for nil values.
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
		}},
		hasValue: hasValue,
	}

	bctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if params.Sync != nil {
				if err := params.Sync.InitLocalNode(ctx, &s.value); err != nil {
					return err
				}

				// Start the synchronization process in background
				wg.Add(1)
				go func() {
					params.Sync.SyncLocalNode(bctx, s)
					wg.Done()
				}()
			}

			// Set the global variable still used by getters
			// and setters in address.go. We're setting it in Start
			// to catch uses of it before it's initialized.
			localNode = s

			s.emit = emit
			s.complete = complete
			emit(s.value)
			close(hasValue)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			// Stop the synchronization process (no-op if it had not been started)
			cancel()
			wg.Wait()

			s.mu.Lock()
			s.complete(nil)
			s.getMu.Lock()
			s.complete = nil
			s.emit = nil
			s.getMu.Unlock()
			s.mu.Unlock()

			localNode = nil
			return nil
		},
	})

	return s, nil
}

// Get retrieves the current local node. Use Get() only for inspecting the state,
// e.g. in API handlers. Do not assume the value does not change over time.
// Blocks until the store has been initialized.
func (s *LocalNodeStore) Get(ctx context.Context) (LocalNode, error) {
	select {
	case <-s.hasValue:
		s.getMu.RLock()
		defer s.getMu.RUnlock()

		if s.complete == nil {
			// Return EOF when the LocalNodeStore is stopped, to preserve the
			// same behavior of stream.First[LocalNode].
			return LocalNode{}, io.EOF
		}

		return s.value, nil

	case <-ctx.Done():
		return LocalNode{}, ctx.Err()
	}
}

// Update modifies the local node with a mutator. The updated value
// is passed to observers. Calling LocalNodeStore.Get() from the
// mutation function is forbidden, and would result in a deadlock.
func (s *LocalNodeStore) Update(update func(*LocalNode)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.getMu.Lock()
	update(&s.value)
	s.getMu.Unlock()

	if s.emit != nil {
		s.emit(s.value)
	}
}
