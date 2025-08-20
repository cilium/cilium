// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
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

	Logger      *slog.Logger
	Lifecycle   cell.Lifecycle
	Sync        LocalNodeSynchronizer
	DB          *statedb.DB
	Nodes       statedb.RWTable[*LocalNode]
	Jobs        job.Group
	ClusterInfo cmtypes.ClusterInfo
}

// LocalNodeStore is the canonical owner for the local node object and provides
// a reactive API for observing and updating the state.
type LocalNodeStore struct {
	db    *statedb.DB
	nodes statedb.RWTable[*LocalNode]
}

func NewLocalNodeStore(params LocalNodeStoreParams) (*LocalNodeStore, error) {
	wtxn := params.DB.WriteTxn(params.Nodes)

	// Register an initializer that'll mark the table initialized once we're done
	// with [LocalNodeSynchronizer.InitLocalNode].
	initDone := params.Nodes.RegisterInitializer(wtxn, "LocalNodeSynchronizer")

	// Insert the skeleton local node.
	params.Nodes.Insert(wtxn,
		&LocalNode{
			Node: types.Node{
				Name:      types.GetName(),
				Cluster:   params.ClusterInfo.Name,
				ClusterID: params.ClusterInfo.ID,
				// Explicitly initialize the labels and annotations maps, so that
				// we don't need to always check for nil values.
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
				Source:      source.Unspec,
			},
			Local: &LocalNodeInfo{},
		})
	wtxn.Commit()

	s := &LocalNodeStore{params.DB, params.Nodes}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			wtxn := params.DB.WriteTxn(params.Nodes)
			n, _, _ := params.Nodes.Get(wtxn, LocalNodeQuery)
			// Delete the initial one as name might change.
			params.Nodes.Delete(wtxn, n)

			n = n.DeepCopy()
			err := params.Sync.InitLocalNode(ctx, n)
			params.Nodes.Insert(wtxn, n)
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

// observeRatePerSecond sets the maximum number of [LocalNode] updates per second that
// [LocalNodeStore.Observe] emits. This avoids unnecessary computation when there's
// many rapid changes to the local node.
const observeRatePerSecond = 5

// Observe changes to the local node state.
func (s *LocalNodeStore) Observe(ctx context.Context, next func(LocalNode), complete func(error)) {
	go func() {
		// Wait until initialized before starting to observe.
		_, initWatch := s.nodes.Initialized(s.db.ReadTxn())
		select {
		case <-initWatch:
		case <-ctx.Done():
			complete(ctx.Err())
			return
		}

		limiter := rate.NewLimiter(time.Second/observeRatePerSecond, 1)
		defer limiter.Stop()

		defer complete(nil)
		for {
			lns, _, watch, _ := s.nodes.GetWatch(s.db.ReadTxn(), LocalNodeQuery)
			next(*lns)
			if err := limiter.Wait(ctx); err != nil {
				return
			}
			select {
			case <-watch:
			case <-ctx.Done():
				return
			}
		}
	}()
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
		panic("BUG: No local node exists")
	}

	return *ln, nil
}

// Update modifies the local node with a mutator.
func (s *LocalNodeStore) Update(update func(*LocalNode)) {
	txn := s.db.WriteTxn(s.nodes)
	defer txn.Abort()
	ln, _, found := s.nodes.Get(txn, LocalNodeQuery)
	if !found {
		panic("BUG: No local node exists")
	}
	orig := ln
	ln = ln.DeepCopy()
	update(ln)
	if ln.Local == nil {
		panic("BUG: Updated LocalNode has nil Local")
	}

	if ln.DeepEqual(orig) {
		// No changes.
		return
	}

	if orig.Fullname() != ln.Fullname() {
		// Name or cluster has changed, delete first to remove it from the name index.
		s.nodes.Delete(txn, orig)
	}

	s.nodes.Insert(txn, ln)
	txn.Commit()
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

// LocalNodeStoreTestCell is a convenience for tests that provides a no-op
// [LocalNodeSynchronizer]. Use [LocalNodeStoreCell] in tests when you want
// to provide your own [LocalNodeSynchronizer].
var LocalNodeStoreTestCell = cell.Group(
	cell.Provide(NewNopLocalNodeSynchronizer),
	LocalNodeStoreCell,
)

type nopLocalNodeSynchronizer struct{}

// InitLocalNode implements LocalNodeSynchronizer.
func (n nopLocalNodeSynchronizer) InitLocalNode(context.Context, *LocalNode) error {
	return nil
}

// SyncLocalNode implements LocalNodeSynchronizer.
func (n nopLocalNodeSynchronizer) SyncLocalNode(context.Context, *LocalNodeStore) {
}

var _ LocalNodeSynchronizer = nopLocalNodeSynchronizer{}

func NewNopLocalNodeSynchronizer() LocalNodeSynchronizer {
	return nopLocalNodeSynchronizer{}

}
