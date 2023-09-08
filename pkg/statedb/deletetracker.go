// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/statedb/index"
)

type DeleteTracker[Obj any] struct {
	db          *DB
	trackerName string
	table       Table[Obj]
	revision    atomic.Uint64
}

// setRevision is called to set the starting low watermark when
// this deletion tracker is inserted into the table.
func (dt *DeleteTracker[Obj]) setRevision(rev uint64) {
	dt.revision.Store(rev)
}

// getRevision is called by the graveyard garbage collector to
// compute the global low watermark.
func (dt *DeleteTracker[Obj]) getRevision() uint64 {
	return dt.revision.Load()
}

// Deleted returns an iterator for deleted objects in this table starting from
// 'minRevision'. The deleted objects are not garbage-collected unless 'Mark' is
// called!
func (dt *DeleteTracker[Obj]) Deleted(txn ReadTxn, minRevision Revision) Iterator[Obj] {
	indexTxn := txn.getTxn().indexReadTxn(dt.table.Name(), GraveyardRevisionIndex)
	iter := indexTxn.Root().Iterator()
	iter.SeekLowerBound(index.Uint64(minRevision))
	return &iterator[Obj]{iter}
}

// Mark the revision up to which deleted objects have been processed. This sets
// the low watermark for deleted object garbage collection.
func (dt *DeleteTracker[Obj]) Mark(upTo Revision) {
	// Store the new low watermark and trigger a round of garbage collection.
	dt.revision.Store(upTo)
	select {
	case dt.db.gcTrigger <- struct{}{}:
	default:
	}
}

func (dt *DeleteTracker[Obj]) Close() {
	// Remove the delete tracker from the table.
	txn := dt.db.WriteTxn(dt.table).getTxn()
	db := txn.db
	table := txn.modifiedTables[dt.table.Name()]
	if table == nil {
		panic("BUG: Table missing from write transaction")
	}
	table.deleteTrackers, _, _ = table.deleteTrackers.Delete([]byte(dt.trackerName))
	txn.Commit()

	db.metrics.TableDeleteTrackerCount.With(prometheus.Labels{
		"table": dt.table.Name(),
	}).Dec()

	// Trigger garbage collection without this delete tracker to garbage
	// collect any deleted objects that may not have been consumed.
	select {
	case db.gcTrigger <- struct{}{}:
	default:
	}

}

// Process is a helper to iterate updates and deletes to a table in revision order.
//
// The 'processFn' is called for each updated or deleted object in order. If an error
// is returned by the function the iteration is stopped and the revision at which
// processing failed and the error is returned. The caller can then retry processing
// again from this revision by providing it as the 'minRevision'.
func (dt *DeleteTracker[Obj]) Process(txn ReadTxn, minRevision Revision, processFn func(obj Obj, deleted bool, rev Revision) error) (Revision, <-chan struct{}, error) {
	upTo := dt.table.Revision(txn)

	// Get all new and updated objects with revision number equal or
	// higher than 'minRevision'.
	// The returned watch channel watches the whole table and thus
	// is closed when either insert or delete happens.
	updatedIter, watch := dt.table.LowerBound(txn, ByRevision[Obj](minRevision))

	// Get deleted objects with revision equal or higher than 'minRevision'.
	deletedIter := dt.Deleted(txn.getTxn(), minRevision)

	// Combine the iterators into one. This can be done as insert and delete
	// both assign the object a new fresh monotonically increasing revision
	// number.
	iter := NewDualIterator[Obj](deletedIter, updatedIter)

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
