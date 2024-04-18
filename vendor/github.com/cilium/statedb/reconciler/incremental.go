// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
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

	errs []error
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
	round.commitStatus()

	r.metrics.IncrementalReconciliationErrors(r.ModuleID, round.errs)

	return round.errs
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

		err := round.processSingle(obj, change.Revision, change.Deleted)
		if err != nil {
			round.errs = append(round.errs, err)
		}
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
		obj = round.config.CloneObject(obj)

		if change.Deleted {
			deleteBatch = append(deleteBatch, BatchEntry[Obj]{Object: obj, Revision: rev})
		} else {
			updateBatch = append(updateBatch, BatchEntry[Obj]{Object: obj, Revision: rev})
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
				round.errs = append(round.errs, entry.Result)
				round.retries.Add(entry.Object)
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
				// Reconciling succeeded, so clear the retries.
				round.retries.Clear(entry.Object)
				round.results[entry.Object] = opResult{rev: entry.Revision, status: StatusDone()}
			} else {
				round.errs = append(round.errs, entry.Result)
				round.results[entry.Object] = opResult{rev: entry.Revision, status: StatusError(entry.Result)}
			}
		}
	}
}

func (round *incrementalRound[Obj]) processRetries() {
	now := time.Now()
	for round.numReconciled < round.config.IncrementalRoundSize {
		robj, retryAt, ok := round.retries.Top()
		if !ok || retryAt.After(now) {
			break
		}
		round.retries.Pop()

		obj, rev, found := round.table.Get(round.txn, round.primaryIndexer.QueryFromObject(robj.(Obj)))
		if found {
			status := round.config.GetObjectStatus(obj)
			if status.Kind != StatusKindError {
				continue
			}
		} else {
			obj = robj.(Obj)
		}

		err := round.processSingle(obj, rev, !found)
		if err != nil {
			round.errs = append(round.errs, err)
		}

		round.numReconciled++
	}
}

func (round *incrementalRound[Obj]) processSingle(obj Obj, rev statedb.Revision, delete bool) error {
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
			round.retries.Add(obj)
		}
	} else {
		// Clone the object so it can be mutated by Update()
		obj = round.config.CloneObject(obj)
		op = OpUpdate
		err = round.config.Operations.Update(round.ctx, round.txn, obj)
		if err == nil {
			round.results[obj] = opResult{rev: rev, status: StatusDone()}
		} else {
			round.results[obj] = opResult{rev: rev, status: StatusError(err)}
		}
	}
	round.metrics.IncrementalReconciliationDuration(round.moduleID, op, time.Since(start))

	if err == nil {
		// Reconciling succeeded, so clear the object.
		round.retries.Clear(obj)
	}

	return err

}

func (round *incrementalRound[Obj]) commitStatus() {
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
		round.table.CompareAndSwap(wtxn, result.rev, round.config.SetObjectStatus(obj, result.status))

		if result.status.Kind == StatusKindError {
			// Reconciling the object failed, so add it to be retried now that its
			// status is updated.
			round.retries.Add(obj)
		}
	}
}
