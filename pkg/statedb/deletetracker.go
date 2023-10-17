// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"sync/atomic"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/statedb/index"
)

// baseDeleteTracker implements delete tracking for a the raw 'object'
// type. Used to implement the typed 'DeleteTracker[Obj]' and delete
// tracking for the gRPC service.
type baseDeleteTracker struct {
	db          *DB
	trackerName string
	tableMeta   TableMeta
	revision    atomic.Uint64
}

// setRevision is called to set the starting low watermark when
// this deletion tracker is inserted into the table.
func (dt *baseDeleteTracker) setRevision(rev uint64) {
	dt.revision.Store(rev)
}

// getRevision is called by the graveyard garbage collector to
// compute the global low watermark.
func (dt *baseDeleteTracker) getRevision() uint64 {
	return dt.revision.Load()
}

// Deleted returns an iterator for deleted objects in this table starting from
// 'minRevision'. The deleted objects are not garbage-collected unless 'Mark' is
// called!
func (dt *baseDeleteTracker) deleted(txn *txn, minRevision Revision) *iradix.Iterator[object] {
	indexTxn := txn.getTxn().indexReadTxn(dt.tableMeta.Name(), GraveyardRevisionIndex)
	iter := indexTxn.Root().Iterator()
	iter.SeekLowerBound(index.Uint64(minRevision))
	return iter
}

// Mark the revision up to which deleted objects have been processed. This sets
// the low watermark for deleted object garbage collection.
func (dt *baseDeleteTracker) Mark(upTo Revision) {
	// Store the new low watermark and trigger a round of garbage collection.
	dt.revision.Store(upTo)
	select {
	case dt.db.gcTrigger <- struct{}{}:
	default:
	}
}

func (dt *baseDeleteTracker) Close() {
	// Remove the delete tracker from the table.
	txn := dt.db.WriteTxn(dt.tableMeta).getTxn()
	db := txn.db
	table := txn.modifiedTables[dt.tableMeta.Name()]
	if table == nil {
		panic("BUG: Table missing from write transaction")
	}
	table.deleteTrackers, _, _ = table.deleteTrackers.Delete([]byte(dt.trackerName))
	txn.Commit()

	db.metrics.TableDeleteTrackerCount.With(prometheus.Labels{
		"table": dt.tableMeta.Name(),
	}).Dec()

	// Trigger garbage collection without this delete tracker to garbage
	// collect any deleted objects that may not have been consumed.
	select {
	case db.gcTrigger <- struct{}{}:
	default:
	}

}

// process is a helper to iterate updates and deletes to a table in revision order.
//
// The 'processFn' is called for each updated or deleted object in order. If an error
// is returned by the function the iteration is stopped and the revision at which
// processing failed and the error is returned. The caller can then retry processing
// again from this revision by providing it as the 'minRevision'.
func (dt *baseDeleteTracker) process(txn ReadTxn, minRevision Revision, processFn func(obj any, deleted bool, rev Revision) error) (Revision, <-chan struct{}, error) {
	upTo := txn.getTxn().GetRevision(dt.tableMeta.Name())

	// Get all new and updated objects with revision number equal or
	// higher than 'minRevision'.
	// The returned watch channel watches the whole table and thus
	// is closed when either insert or delete happens.
	indexTxn := txn.getTxn().indexReadTxn(dt.tableMeta.Name(), RevisionIndex)
	root := indexTxn.Root()
	watch, _, _ := root.GetWatch(nil)
	updatedIter := root.Iterator()
	updatedIter.SeekLowerBound(index.Uint64(minRevision))

	// Get deleted objects with revision equal or higher than 'minRevision'.
	deletedIter := dt.deleted(txn.getTxn(), minRevision)

	// Combine the iterators into one. This can be done as insert and delete
	// both assign the object a new fresh monotonically increasing revision
	// number.
	iter := NewDualIterator[any](&iterator[any]{deletedIter}, &iterator[any]{updatedIter})

	for obj, rev, isDeleted, ok := iter.Next(); ok; obj, rev, isDeleted, ok = iter.Next() {
		err := processFn(obj, isDeleted, rev)
		if err != nil {
			// Mark deleted objects processed up to previous revision since we may
			// not have processed all objects with this revision fully yet.
			dt.Mark(rev - 1)

			// Processing failed, stop here and try again from this same revision.
			closedWatch := make(chan struct{})
			close(closedWatch)
			return rev, closedWatch, err
		}

	}

	// Fully processed up to latest table revision. GC deleted objects
	// and return the next revision.
	dt.Mark(upTo)
	return upTo + 1, watch, nil
}

// DeleteTracker tracks deleted objects.
type DeleteTracker[Obj any] struct{ baseDeleteTracker }

func newDeleteTracker[Obj any](db *DB, table Table[Obj], trackerName string) *DeleteTracker[Obj] {
	return &DeleteTracker[Obj]{
		baseDeleteTracker: baseDeleteTracker{
			db:          db,
			trackerName: trackerName,
			tableMeta:   table,
		},
	}
}

// Deleted returns an iterator for deleted objects in this table starting from
// 'minRevision'. The deleted objects are not garbage-collected unless 'Mark' is
// called!
func (dt *DeleteTracker[Obj]) Deleted(txn ReadTxn, minRevision Revision) Iterator[Obj] {
	return &iterator[Obj]{dt.deleted(txn.getTxn(), minRevision)}
}

// Process is a helper to iterate updates and deletes to a table in revision order.
//
// The 'processFn' is called for each updated or deleted object in order. If an error
// is returned by the function the iteration is stopped and the revision at which
// processing failed and the error is returned. The caller can then retry processing
// again from this revision by providing it as the 'minRevision'.
func (dt *DeleteTracker[Obj]) Process(txn ReadTxn, minRevision Revision, processFn func(obj Obj, deleted bool, rev Revision) error) (Revision, <-chan struct{}, error) {
	return dt.process(txn, minRevision,
		func(obj any, deleted bool, rev Revision) error {
			return processFn(obj.(Obj), deleted, rev)
		})
}
