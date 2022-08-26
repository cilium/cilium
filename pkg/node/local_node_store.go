package node

import (
	"context"
	"sync"

	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/stream"
)

type LocalNodeInitializer interface {
	InitLocalNode(*types.Node)
}

type LocalNodeInitializerFunc func(*types.Node)

func (f LocalNodeInitializerFunc) InitLocalNode(n *types.Node) { f(n) }

type LocalNodeStoreParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	Inits     []LocalNodeInitializer `group:"local-node-init"`
}

// LocalNodeStore provides access to information about the local node.
type LocalNodeStore interface {
	// Observe subscribes to changes on the local node until ctx is
	// cancelled.
	Observe(ctx context.Context,
		next func(types.Node),
		complete func(error))

	// Update modifies the local node with a mutator. The updated value
	// is passed to observers.
	Update(func(*types.Node))

	// Get retrieves the current local node. Use Get() only for inspecting the state,
	// e.g. in API handlers. Do not assume the value does not change over time.
	Get() types.Node
}

var LocalNodeStoreCell = hive.NewCell(
	"local-node-store",

	fx.Provide(newLocalNodeStore),
)

// localNodeStore implements the LocalNodeStore using a simple in-memory
// backing. Reflecting the new state to persistent stores, e.g. kvstore or k8s
// is left to observers.
type localNodeStore struct {
	mu   lock.Mutex
	cond *sync.Cond
	stream.Observable[types.Node]

	valid    bool
	value    types.Node
	emit     func(types.Node)
	complete func(error)
}

var _ LocalNodeStore = &localNodeStore{}

func newLocalNodeStore(params LocalNodeStoreParams) (LocalNodeStore, error) {
	src, emit, complete := stream.Multicast[types.Node](stream.EmitLatest)

	s := &localNodeStore{
		Observable: src,
	}
	s.cond = sync.NewCond(&s.mu)

	params.Lifecycle.Append(fx.Hook{
		OnStart: func(context.Context) error {
			s.mu.Lock()
			for _, init := range params.Inits {
				init.InitLocalNode(&s.value)
			}
			s.valid = true
			s.emit = emit
			s.complete = complete
			s.mu.Unlock()
			s.cond.Broadcast()
			return nil
		},
		OnStop: func(context.Context) error {
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

func (s *localNodeStore) Get() types.Node {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Block until the value has been initialized.
	for !s.valid {
		s.cond.Wait()
	}

	return s.value
}

func (s *localNodeStore) Update(update func(*types.Node)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	update(&s.value)

	if s.emit != nil {
		s.emit(s.value)
	}
}
