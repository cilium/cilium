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

// incrementalRound is the shared context for incremental reconciliation and retries.
type incrementalRound[Obj comparable] struct {
	metrics        Metrics
	moduleID       cell.FullModuleID
	config         *config[Obj]
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
	id       uint64 // the "pending" identifier
}

func (r *reconciler[Obj]) incremental(ctx context.Context, txn statedb.ReadTxn, changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) []error {
	round := incrementalRound[Obj]{
		moduleID:       r.ModuleID,
		metrics:        r.config.Metrics,
		config:         &r.config,
		retries:        r.retries,
		primaryIndexer: r.primaryIndexer,
		db:             r.DB,
		ctx:            ctx,
		txn:            txn,
		table:          r.config.Table,
		results:        make(map[Obj]opResult),
	}

	// Reconcile new and changed objects using either Operations
	// or BatchOperations.
	if r.config.BatchOperations != nil {
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
	round.metrics.ReconciliationErrors(r.ModuleID, newErrors, len(errs))
	return errs
}

func (round *incrementalRound[Obj]) single(changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) {
	// Iterate in revision order through new and changed objects.
	for change, rev := range changes {
		obj := change.Object

		status := round.config.GetObjectStatus(obj)
		if !change.Deleted && !status.IsPendingOrRefreshing() {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear retries as the object has changed.
		round.retries.Clear(obj)

		round.processSingle(obj, rev, change.Deleted)
		round.numReconciled++
		if round.numReconciled >= round.config.IncrementalRoundSize {
			break
		}
	}
}

func (round *incrementalRound[Obj]) batch(changes iter.Seq2[statedb.Change[Obj], statedb.Revision]) {
	ops := round.config.BatchOperations
	updateBatch := []BatchEntry[Obj]{}
	deleteBatch := []BatchEntry[Obj]{}

	for change, rev := range changes {
		obj := change.Object

		status := round.config.GetObjectStatus(obj)
		if !change.Deleted && !status.IsPendingOrRefreshing() {
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
		round.metrics.ReconciliationDuration(
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
		round.metrics.ReconciliationDuration(
			round.moduleID,
			OpUpdate,
			time.Since(start),
		)

		for _, entry := range updateBatch {
			status := round.config.GetObjectStatus(entry.Object)
			if entry.Result == nil {
				round.retries.Clear(entry.Object)
			}
			round.results[entry.Object] = opResult{rev: entry.Revision, id: status.ID, err: entry.Result, original: entry.original}
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
		status := round.config.GetObjectStatus(obj)
		round.results[obj] = opResult{original: orig, id: status.ID, rev: rev, err: err}
	}
	round.metrics.ReconciliationDuration(round.moduleID, op, time.Since(start))

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
		// been updated in the meanwhile, in which case we skip updating the status
		// and reprocess the object on the next round.

		var status Status
		if result.err == nil {
			status = StatusDone()
		} else {
			status = StatusError(result.err)
			numErrors++
		}

		current, exists, err := round.table.CompareAndSwap(wtxn, result.rev, round.config.SetObjectStatus(obj, status))
		if errors.Is(err, statedb.ErrRevisionNotEqual) && exists {
			// The object had changed. Check if the pending status still carries the same
			// identifier and if so update the object. This is an optimization for supporting
			// multiple reconcilers per object to avoid repeating work when only the
			// reconciliation status had changed.
			//
			// The limitation of this approach is that we cannot support the reconciler
			// modifying the object during reconciliation as the following will forget
			// the changes.
			currentStatus := round.config.GetObjectStatus(current)
			if currentStatus.Kind == StatusKindPending && currentStatus.ID == result.id {
				current = round.config.CloneObject(current)
				current = round.config.SetObjectStatus(current, status)
				round.table.Insert(wtxn, current)
			}
		}

		if result.err != nil && err == nil {
			// Reconciliation of the object had failed and the status was updated
			// successfully (object had not changed). Queue the retry for the object.
			newRevision := round.table.Revision(wtxn)
			round.retries.Add(result.original.(Obj), newRevision, false, result.err)
		}
	}
	return
}
