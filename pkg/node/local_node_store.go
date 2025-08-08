// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

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

	cell.Provide(
		NewLocalNodeTable,
		statedb.RWTable[*LocalNode].ToTable,
	),

	cell.Provide(NewLocalNodeStore),
)

// LocalNodeStoreParams are the inputs needed for constructing LocalNodeStore.
type LocalNodeStoreParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	Sync      LocalNodeSynchronizer `optional:"true"`
	DB        *statedb.DB
	Nodes     statedb.RWTable[*LocalNode]
	Jobs      job.Group
}

// LocalNodeStore is the canonical owner for the local node object and provides
// a reactive API for observing and updating the state.
type LocalNodeStore struct {
	db    *statedb.DB
	nodes statedb.RWTable[*LocalNode]
}

func NewLocalNodeStore(params LocalNodeStoreParams) (*LocalNodeStore, error) {

	initNode := &LocalNode{
		Node: types.Node{
			// Explicitly initialize the labels and annotations maps, so that
			// we don't need to always check for nil values.
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
			Source:      source.Unspec,
		},
		Local: &LocalNodeInfo{},
	}

	var initDone func(statedb.WriteTxn)
	wtxn := params.DB.WriteTxn(params.Nodes)
	if params.Sync != nil {
		// Register an initializer if a LocalNodeSynchronizer is given
		initDone = params.Nodes.RegisterInitializer(wtxn, "LocalNodeSynchronizer")
	} else {
		// No synchronizer, insert the initial node immediately.
		params.Nodes.Insert(wtxn, initNode)
	}
	wtxn.Commit()

	s := &LocalNodeStore{params.DB, params.Nodes}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if params.Sync != nil {
				wtxn := params.DB.WriteTxn(params.Nodes)
				err := params.Sync.InitLocalNode(ctx, initNode)
				params.Nodes.Insert(wtxn, initNode)
				initDone(wtxn)
				wtxn.Commit()

				if err != nil {
					return err
				}

				// Start the synchronization process in background
				params.Jobs.Add(
					job.OneShot(
						"sync-local-node",
						func(ctx context.Context, _ cell.Health) error {
							params.Sync.SyncLocalNode(ctx, s)
							return nil
						},
					))
			}

			// Set the global variable still used by getters
			// and setters in address.go. We're setting it in Start
			// to catch uses of it before it's initialized.
			localNode = s
			return nil
		},
		OnStop: func(cell.HookContext) error {
			localNode = nil
			return nil
		},
	})

	return s, nil
}

// Observe changes to the local node state.
func (s *LocalNodeStore) Observe(ctx context.Context, next func(LocalNode), complete func(error)) {
	stream.Map(
		stream.Filter(
			statedb.Observable(s.db, s.nodes),
			// Only care about non-deleted local nodes. The local node is never deleted.
			func(ev statedb.Change[*LocalNode]) bool {
				return !ev.Deleted && ev.Object != nil && ev.Object.Local != nil
			},
		),
		func(ev statedb.Change[*LocalNode]) LocalNode {
			return *ev.Object
		},
	).Observe(ctx, next, complete)
}

// Get retrieves the current local node. Use Get() only for inspecting the state,
// e.g. in API handlers. Do not assume the value does not change over time.
// Blocks until the store has been initialized.
func (s *LocalNodeStore) Get(ctx context.Context) (LocalNode, error) {
	_, initWatch := s.nodes.Initialized(s.db.ReadTxn())
	select {
	case <-initWatch:
	case <-ctx.Done():
		return LocalNode{}, ctx.Err()
	}

	ln, _, found := s.nodes.Get(s.db.ReadTxn(), LocalNodeQuery)
	if !found {
		return LocalNode{}, errors.New("Local node not found")
	}
	return *ln, nil
}

// Update modifies the local node with a mutator.
func (s *LocalNodeStore) Update(update func(*LocalNode)) {
	txn := s.db.WriteTxn(s.nodes)
	defer txn.Commit()
	ln, _, found := s.nodes.Get(txn, LocalNodeQuery)
	if !found {
		panic("BUG: No local node exists")
	}
	ln = ln.DeepCopy()
	update(ln)
	if ln.Local == nil {
		panic("BUG: Updated LocalNode has nil Local")
	}
	s.nodes.Insert(txn, ln)
}

func NewTestLocalNodeStore(mockNode LocalNode) *LocalNodeStore {
	db := statedb.New()
	tbl, err := NewLocalNodeTable(db)
	if err != nil {
		panic(err)
	}
	if mockNode.Local == nil {
		mockNode.Local = &LocalNodeInfo{}
	}
	txn := db.WriteTxn(tbl)
	tbl.Insert(txn, &mockNode)
	txn.Commit()
	return &LocalNodeStore{db, tbl}
}
