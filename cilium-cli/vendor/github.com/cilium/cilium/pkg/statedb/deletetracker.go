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

	// revision is the last observed revision. Starts out at zero
	// in which case the garbage collector will not care about this
	// tracker when considering which objects to delete.
	revision atomic.Uint64
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
	indexTxn := txn.getTxn().mustIndexReadTxn(dt.table.Name(), GraveyardRevisionIndex)
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

// IterateWithError iterates updates and deletes to a table in revision order.
//
// The 'processFn' is called for each updated or deleted object in order. If an error
// is returned by the function the iteration is stopped and the error is returned.
// On further calls the processing continues from the next unprocessed (or error'd) revision.
func (dt *DeleteTracker[Obj]) IterateWithError(txn ReadTxn, processFn func(obj Obj, deleted bool, rev Revision) error) (<-chan struct{}, error) {
	upTo := dt.table.Revision(txn)
	lastRevision := dt.revision.Load()

	// Get all new and updated objects with revision number equal or
	// higher than 'minRevision'.
	// The returned watch channel watches the whole table and thus
	// is closed when either insert or delete happens.
	updatedIter, watch := dt.table.LowerBound(txn, ByRevision[Obj](lastRevision+1))

	// Get deleted objects with revision equal or higher than 'minRevision'.
	deletedIter := dt.Deleted(txn.getTxn(), lastRevision+1)

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
			return closedWatchChannel, err
		}

	}

	// Fully processed up to latest table revision. GC deleted objects
	// and return the next revision.
	dt.Mark(upTo)
	return watch, nil
}

// Iterate over updated and deleted objects in revision order.
func (dt *DeleteTracker[Obj]) Iterate(txn ReadTxn, iterateFn func(obj Obj, deleted bool, rev Revision)) <-chan struct{} {
	watch, _ := dt.IterateWithError(txn, func(obj Obj, deleted bool, rev Revision) error {
		iterateFn(obj, deleted, rev)
		return nil
	})
	return watch
}

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()
