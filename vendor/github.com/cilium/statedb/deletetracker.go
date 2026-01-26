// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"sync/atomic"

	"github.com/cilium/statedb/index"
)

type deleteTracker[Obj any] struct {
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
func (dt *deleteTracker[Obj]) setRevision(rev uint64) {
	dt.revision.Store(rev)
}

// getRevision is called by the graveyard garbage collector to
// compute the global low watermark.
func (dt *deleteTracker[Obj]) getRevision() uint64 {
	return dt.revision.Load()
}

// Deleted returns an iterator for deleted objects in this table starting from
// 'minRevision'. The deleted objects are not garbage-collected unless 'Mark' is
// called!
func (dt *deleteTracker[Obj]) deleted(txn ReadTxn, minRevision Revision) *iterator[Obj] {
	indexEntry := txn.root()[dt.table.tablePos()].indexes[GraveyardRevisionIndexPos]
	objs, _ := indexEntry.lowerBoundNext(index.Uint64(minRevision))
	return &iterator[Obj]{objs}
}

// Mark the revision up to which deleted objects have been processed. This sets
// the low watermark for deleted object garbage collection.
func (dt *deleteTracker[Obj]) mark(upTo Revision) {
	// Store the new low watermark and trigger a round of garbage collection.
	dt.revision.Store(upTo)
	select {
	case dt.db.gcTrigger <- struct{}{}:
	default:
	}
}

func (dt *deleteTracker[Obj]) close() {
	if dt.db == nil {
		return
	}

	// Remove the delete tracker from the table.
	wtxn := dt.db.WriteTxn(dt.table)
	txn := wtxn.unwrap()
	dt.db = nil
	db := txn.db
	table := txn.tableEntries[dt.table.tablePos()]
	if !table.locked {
		panic("BUG: Table not locked")
	}
	_, _, updated := table.deleteTrackers.Delete([]byte(dt.trackerName))
	table.deleteTrackers = &updated
	wtxn.Commit()

	db.metrics.DeleteTrackerCount(dt.table.Name(), table.deleteTrackers.Len())

	// Trigger garbage collection without this delete tracker to garbage
	// collect any deleted objects that may not have been consumed.
	select {
	case db.gcTrigger <- struct{}{}:
	default:
	}

}

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()
