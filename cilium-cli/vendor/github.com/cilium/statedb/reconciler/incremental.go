// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// incrementalRound is the shared context for incremental reconciliation and retries.
type incrementalRound[Obj comparable] struct {
	metrics        Metrics
	moduleID       cell.FullModuleID
	config         *Config[Obj]
	retries        *retries
	primaryIndexer statedb.Indexer[Obj]
	db             *statedb.DB
	ctx            context.Context
	txn            statedb.ReadTxn
	table          statedb.RWTable[Obj]

	// numReconciled counts the number of objects that have been reconciled in this
	// round, both for new & changed objects and for retried objects. If
	// Config.IncrementalBatchSize is reached the round is stopped.
	// This allows for timely reporting of status when lot of objects have changed and
	// reconciliation per object is slow.
	numReconciled int

	// results collects the results of update operations.
	// The results are committed in a separate write transaction in order to
	// not lock the table while reconciling. If an object has changed in the meanwhile
	// the stale reconciliation result for that object is dropped.
	results map[Obj]opResult
}

// opResult is the outcome from reconciling a single object
type opResult struct {
	original any              // the original object
	rev      statedb.Revision // revision of the object
	err      error
}

func (r *reconciler[Obj]) incremental(ctx context.Context, txn statedb.ReadTxn, changes statedb.ChangeIterator[Obj]) []error {
	round := incrementalRound[Obj]{
		moduleID:       r.ModuleID,
		metrics:        r.metrics,
		config:         &r.Config,
		retries:        r.retries,
		primaryIndexer: r.primaryIndexer,
		db:             r.DB,
		ctx:            ctx,
		txn:            txn,
		table:          r.Config.Table,
		results:        make(map[Obj]opResult),
	}

	// Reconcile new and changed objects using either Operations
	// or BatchOperations.
	if r.Config.BatchOperations != nil {
		round.batch(changes)
	} else {
		round.single(changes)
	}

	// Process objects that need to be retried that were not cleared.
	round.processRetries()

	// Finally commit the status updates.
	newErrors := round.commitStatus()

	// Since all failures are retried, we can return the errors from the retry
	// queue which includes both errors occurred in this round and the old
	// errors.
	errs := round.retries.errors()
	round.metrics.IncrementalReconciliationErrors(r.ModuleID, newErrors, len(errs))
	return errs
}

func (round *incrementalRound[Obj]) single(changes statedb.ChangeIterator[Obj]) {
	// Iterate in revision order through new and changed objects.
	for change, _, ok := changes.Next(); ok; change, _, ok = changes.Next() {
		obj := change.Object

		status := round.config.GetObjectStatus(obj)
		if !change.Deleted && status.Kind != StatusKindPending {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear retries as the object has changed.
		round.retries.Clear(obj)

		round.processSingle(obj, change.Revision, change.Deleted)
		round.numReconciled++
		if round.numReconciled >= round.config.IncrementalRoundSize {
			break
		}
	}
}

func (round *incrementalRound[Obj]) batch(changes statedb.ChangeIterator[Obj]) {
	ops := round.config.BatchOperations
	updateBatch := []BatchEntry[Obj]{}
	deleteBatch := []BatchEntry[Obj]{}

	for change, rev, ok := changes.Next(); ok; change, rev, ok = changes.Next() {
		obj := change.Object

		status := round.config.GetObjectStatus(obj)
		if !change.Deleted && status.Kind != StatusKindPending {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear an existing retry as the object has changed.
		round.retries.Clear(obj)

		// Clone the object so we or the operations can mutate it.
		orig := obj
		obj = round.config.CloneObject(obj)

		if change.Deleted {
			deleteBatch = append(deleteBatch, BatchEntry[Obj]{Object: obj, Revision: rev, original: orig})
		} else {
			updateBatch = append(updateBatch, BatchEntry[Obj]{Object: obj, Revision: rev, original: orig})
		}

		round.numReconciled++
		if round.numReconciled >= round.config.IncrementalRoundSize {
			break
		}
	}

	// Process the delete batch first to make room.
	if len(deleteBatch) > 0 {
		start := time.Now()
		ops.DeleteBatch(round.ctx, round.txn, deleteBatch)
		round.metrics.IncrementalReconciliationDuration(
			round.moduleID,
			OpDelete,
			time.Since(start),
		)
		for _, entry := range deleteBatch {
			if entry.Result != nil {
				// Delete failed, queue a retry for it.
				round.retries.Add(entry.original, entry.Revision, true, entry.Result)
			}
		}
	}

	// And then the update batch.
	if len(updateBatch) > 0 {
		start := time.Now()
		ops.UpdateBatch(round.ctx, round.txn, updateBatch)
		round.metrics.IncrementalReconciliationDuration(
			round.moduleID,
			OpUpdate,
			time.Since(start),
		)

		for _, entry := range updateBatch {
			if entry.Result == nil {
				round.retries.Clear(entry.Object)
			}
			round.results[entry.Object] = opResult{rev: entry.Revision, err: entry.Result, original: entry.original}
		}
	}
}

func (round *incrementalRound[Obj]) processRetries() {
	now := time.Now()
	for round.numReconciled < round.config.IncrementalRoundSize {
		item, ok := round.retries.Top()
		if !ok || item.retryAt.After(now) {
			break
		}
		round.retries.Pop()
		round.processSingle(item.object.(Obj), item.rev, item.delete)
		round.numReconciled++
	}
}

func (round *incrementalRound[Obj]) processSingle(obj Obj, rev statedb.Revision, delete bool) {
	start := time.Now()

	var (
		err error
		op  string
	)
	if delete {
		op = OpDelete
		err = round.config.Operations.Delete(round.ctx, round.txn, obj)
		if err != nil {
			// Deletion failed. Retry again later.
			round.retries.Add(obj, rev, true, err)
		}
	} else {
		// Clone the object so it can be mutated by Update()
		orig := obj
		obj = round.config.CloneObject(obj)
		op = OpUpdate
		err = round.config.Operations.Update(round.ctx, round.txn, obj)
		round.results[obj] = opResult{original: orig, rev: rev, err: err}
	}
	round.metrics.IncrementalReconciliationDuration(round.moduleID, op, time.Since(start))

	if err == nil {
		round.retries.Clear(obj)
	}
}

func (round *incrementalRound[Obj]) commitStatus() (numErrors int) {
	if len(round.results) == 0 {
		// Nothing to commit.
		return
	}

	wtxn := round.db.WriteTxn(round.table)
	defer wtxn.Commit()

	// Commit status for updated objects.
	for obj, result := range round.results {
		// Update the object if it is unchanged. It may happen that the object has
		// been updated in the meanwhile, in which case we ignore the status as the
		// update will be picked up by next reconciliation round.
		var status Status
		if result.err == nil {
			status = StatusDone()
		} else {
			status = StatusError(result.err)
			numErrors++
		}
		_, _, err := round.table.CompareAndSwap(wtxn, result.rev,
			round.config.SetObjectStatus(obj, status))

		if result.err != nil && err == nil {
			// Reconciliation of the object had failed and the status was updated
			// successfully (object had not changed). Queue the retry for the object.
			newRevision := round.table.Revision(wtxn)
			round.retries.Add(result.original.(Obj), newRevision, false, result.err)
		} else if result.err != nil && err != nil {
			fmt.Printf("FAIL queued %v for retry due to %s ! %s\n", result.original, result.err, err)
		}
	}
	return
}
