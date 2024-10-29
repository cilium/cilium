// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/node/types"
)

type LocalNode = TableNode

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
	DB        *statedb.DB
	Table     statedb.Table[*TableNode]
}

// LocalNodeStore is the canonical owner for the local node object and provides
// a reactive API for observing and updating the state.
type LocalNodeStore struct {
	db    *statedb.DB
	table statedb.RWTable[*TableNode]
}

func NewTestLocalNodeStore(mockNode LocalNode) *LocalNodeStore {
	db := statedb.New()
	tbl, _ := NewNodesTable(db)
	s := &LocalNodeStore{db, tbl}
	s.Update(func(l *LocalNode) {
		*l = mockNode
	})
	return s
}

func NewLocalNodeStore(params LocalNodeStoreParams) (*LocalNodeStore, error) {
	s := &LocalNodeStore{
		db:    params.DB,
		table: params.Table.(statedb.RWTable[*TableNode]),
	}

	var wg sync.WaitGroup
	syncCtx, cancel := context.WithCancel(context.Background())
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if params.Sync != nil {
				var initErr error
				s.Update(func(l *LocalNode) {
					// Explicitly initialize the labels and annotations maps, so that
					// we don't need to always check for nil values.
					l.Labels = make(map[string]string)
					l.Annotations = make(map[string]string)

					initErr = params.Sync.InitLocalNode(ctx, l)
				})
				if initErr != nil {
					return initErr
				}

				// Start the synchronization process in background
				wg.Add(1)
				go func() {
					defer wg.Done()
					params.Sync.SyncLocalNode(syncCtx, s)
				}()
			}

			// Set the global variable still used by getters
			// and setters in address.go. We're setting it in Start
			// to catch uses of it before it's initialized.
			localNode = s

			return nil
		},
		OnStop: func(cell.HookContext) error {
			cancel()
			wg.Wait()
			localNode = nil
			return nil
		},
	})

	return s, nil
}

func (s *LocalNodeStore) Observe(ctx context.Context, next func(*LocalNode), complete func(error)) {
	go func() {
		for {
			n, watch, ok := GetLocalNode(s.db.ReadTxn(), s.table)
			if ok {
				next(n)
			}

			select {
			case <-watch:
			case <-ctx.Done():
				complete(nil)
				return
			}
		}
	}()
}

// Get retrieves the current local node. Use Get() only for inspecting the state,
// e.g. in API handlers. Do not assume the value does not change over time.
// Blocks until the store has been initialized.
func (s *LocalNodeStore) Get(ctx context.Context) (*LocalNode, error) {
	n, _, ok := GetLocalNode(s.db.ReadTxn(), s.table)
	if !ok {
		return nil, errors.New("not found")
	}
	return n, nil
}

// Update modifies the local node with a mutator. The updated value
// is passed to observers. Calling LocalNodeStore.Get() from the
// mutation function is forbidden, and would result in a deadlock.
func (s *LocalNodeStore) Update(update func(*LocalNode)) {
	txn := s.db.WriteTxn(s.table)
	defer txn.Commit()
	n, _, ok := GetLocalNode(txn, s.table)
	if ok {
		n = n.Clone()
	} else {
		n = NewTableNode(types.Node{}, &LocalNodeAttrs{})
	}
	update(n)
	n.SetPending()
	s.table.Insert(txn, n)
}
