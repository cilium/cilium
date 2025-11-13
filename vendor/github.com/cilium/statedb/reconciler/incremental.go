// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"iter"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// incremental is the shared context for incremental reconciliation and retries.
type incremental[Obj comparable] struct {
	metrics        Metrics
	moduleID       cell.FullModuleID
	config         *config[Obj]
	retries        *retries
	primaryIndexer statedb.Indexer[Obj]
	db             *statedb.DB
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
	id       uint64 // the "pending" identifier
}

func (incr *incremental[Obj]) run(ctx context.Context, txn statedb.ReadTxn, changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) []error {
	// Reconcile new and changed objects using either Operations
	// or BatchOperations.
	if incr.config.BatchOperations != nil {
		incr.batch(ctx, txn, changes)
	} else {
		incr.single(ctx, txn, changes)
	}

	// Process objects that need to be retried that were not cleared.
	incr.processRetries(ctx, txn)

	// Finally commit the status updates.
	newErrors := incr.commitStatus()

	// Since all failures are retried, we can return the errors from the retry
	// queue which includes both errors occurred in this round and the old
	// errors.
	errs := incr.retries.errors()
	incr.metrics.ReconciliationErrors(incr.moduleID, newErrors, len(errs))

	// Prepare for next round
	incr.numReconciled = 0
	clear(incr.results)

	return errs
}

func (incr *incremental[Obj]) single(ctx context.Context, txn statedb.ReadTxn, changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) {
	// Iterate in revision order through new and changed objects.
	for change, rev := range changes {
		obj := change.Object

		status := incr.config.GetObjectStatus(obj)
		if !change.Deleted && !status.IsPendingOrRefreshing() {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear retries as the object has changed.
		incr.retries.Clear(obj)

		incr.processSingle(ctx, txn, obj, rev, change.Deleted)
		incr.numReconciled++
		if incr.numReconciled >= incr.config.IncrementalRoundSize {
			break
		}
	}
}

func (incr *incremental[Obj]) batch(ctx context.Context, txn statedb.ReadTxn, changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) {
	ops := incr.config.BatchOperations
	updateBatch := []BatchEntry[Obj]{}
	deleteBatch := []BatchEntry[Obj]{}

	for change, rev := range changes {
		obj := change.Object

		status := incr.config.GetObjectStatus(obj)
		if !change.Deleted && !status.IsPendingOrRefreshing() {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear an existing retry as the object has changed.
		incr.retries.Clear(obj)

		// Clone the object so we or the operations can mutate it.
		orig := obj
		obj = incr.config.CloneObject(obj)

		if change.Deleted {
			deleteBatch = append(deleteBatch, BatchEntry[Obj]{Object: obj, Revision: rev, original: orig})
		} else {
			updateBatch = append(updateBatch, BatchEntry[Obj]{Object: obj, Revision: rev, original: orig})
		}

		incr.numReconciled++
		if incr.numReconciled >= incr.config.IncrementalRoundSize {
			break
		}
	}

	// Process the delete batch first to make room.
	if len(deleteBatch) > 0 {
		start := time.Now()
		ops.DeleteBatch(ctx, txn, deleteBatch)
		incr.metrics.ReconciliationDuration(
			incr.moduleID,
			OpDelete,
			time.Since(start),
		)
		for _, entry := range deleteBatch {
			if entry.Result != nil {
				// Delete failed, queue a retry for it.
				incr.retries.Add(entry.original, entry.Revision, true, entry.Result)
			}
		}
	}

	// And then the update batch.
	if len(updateBatch) > 0 {
		start := time.Now()
		ops.UpdateBatch(ctx, txn, updateBatch)
		incr.metrics.ReconciliationDuration(
			incr.moduleID,
			OpUpdate,
			time.Since(start),
		)

		for _, entry := range updateBatch {
			status := incr.config.GetObjectStatus(entry.Object)
			if entry.Result == nil {
				incr.retries.Clear(entry.Object)
			}
			incr.results[entry.Object] = opResult{rev: entry.Revision, id: status.ID, err: entry.Result, original: entry.original}
		}
	}
}

func (incr *incremental[Obj]) processRetries(ctx context.Context, txn statedb.ReadTxn) {
	now := time.Now()
	for incr.numReconciled < incr.config.IncrementalRoundSize {
		item, ok := incr.retries.Top()
		if !ok || item.retryAt.After(now) {
			break
		}
		incr.retries.Pop()
		incr.processSingle(ctx, txn, item.object.(Obj), item.rev, item.delete)
		incr.numReconciled++
	}
}

func (incr *incremental[Obj]) processSingle(ctx context.Context, txn statedb.ReadTxn, obj Obj, rev statedb.Revision, delete bool) {
	start := time.Now()

	var (
		err error
		op  string
	)
	if delete {
		op = OpDelete
		err = incr.config.Operations.Delete(ctx, txn, rev, obj)
		if err != nil {
			// Deletion failed. Retry again later.
			incr.retries.Add(obj, rev, true, err)
		}
	} else {
		// Clone the object so it can be mutated by Update()
		orig := obj
		obj = incr.config.CloneObject(obj)
		op = OpUpdate
		err = incr.config.Operations.Update(ctx, txn, rev, obj)
		status := incr.config.GetObjectStatus(obj)
		incr.results[obj] = opResult{original: orig, id: status.ID, rev: rev, err: err}
	}
	incr.metrics.ReconciliationDuration(incr.moduleID, op, time.Since(start))

	if err == nil {
		incr.retries.Clear(obj)
	}
}

func (incr *incremental[Obj]) commitStatus() (numErrors int) {
	if len(incr.results) == 0 {
		// Nothing to commit.
		return
	}

	wtxn := incr.db.WriteTxn(incr.table)
	defer wtxn.Commit()

	// Commit status for updated objects.
	for obj, result := range incr.results {
		// Update the object if it is unchanged. It may happen that the object has
		// been updated in the meanwhile, in which case we skip updating the status
		// and reprocess the object on the next round.

		var status Status
		if result.err == nil {
			status = StatusDone()
		} else {
			status = StatusError(result.err)
			numErrors++
		}

		current, exists, err := incr.table.CompareAndSwap(wtxn, result.rev, incr.config.SetObjectStatus(obj, status))
		if errors.Is(err, statedb.ErrRevisionNotEqual) && exists {
			// The object had changed. Check if the pending status still carries the same
			// identifier and if so update the object. This is an optimization for supporting
			// multiple reconcilers per object to avoid repeating work when only the
			// reconciliation status had changed.
			//
			// The limitation of this approach is that we cannot support the reconciler
			// modifying the object during reconciliation as the following will forget
			// the changes.
			currentStatus := incr.config.GetObjectStatus(current)
			if currentStatus.Kind == StatusKindPending && currentStatus.ID == result.id {
				current = incr.config.CloneObject(current)
				current = incr.config.SetObjectStatus(current, status)
				incr.table.Insert(wtxn, current)
			}
		}

		if result.err != nil && err == nil {
			// Reconciliation of the object had failed and the status was updated
			// successfully (object had not changed). Queue the retry for the object.
			newRevision := incr.table.Revision(wtxn)
			incr.retries.Add(result.original.(Obj), newRevision, false, result.err)
		}
	}
	return
}
