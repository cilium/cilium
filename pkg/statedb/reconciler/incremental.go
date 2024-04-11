// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

// incrementalRound is the shared context for incremental reconciliation and retries.
type incrementalRound[Obj comparable] struct {
	metrics        *Metrics
	config         *Config[Obj]
	retries        *retries
	primaryIndexer statedb.Indexer[Obj]
	db             *statedb.DB
	ctx            context.Context
	txn            statedb.ReadTxn
	table          statedb.RWTable[Obj]
	oldRevision    statedb.Revision

	// numReconciled counts the number of objects that have been reconciled in this
	// round, both for new & changed objects and for retried objects. If
	// Config.IncrementalBatchSize is reached the round is stopped.
	// This allows for timely reporting of status when lot of objects have changed and
	// reconciliation per object is slow.
	numReconciled int

	// results collects the results of update and delete operations.
	// The results are committed in a separate write transaction in order to
	// not lock the table while reconciling. If an object has changed in the meanwhile
	// the stale reconciliation result for that object is dropped.
	results map[Obj]opResult

	errs []error
}

func (r *reconciler[Obj]) incremental(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision) (statedb.Revision, <-chan struct{}, error) {
	round := incrementalRound[Obj]{
		metrics:        r.Metrics,
		config:         &r.Config,
		retries:        r.retries,
		primaryIndexer: r.primaryIndexer,
		db:             r.DB,
		oldRevision:    rev,
		ctx:            ctx,
		txn:            txn,
		table:          r.Table,
		results:        make(map[Obj]opResult),
	}

	// Reconcile new and changed objects using either Operations
	// or BatchOperations.
	var newRevision statedb.Revision
	if r.Config.BatchOperations != nil {
		newRevision = round.batch(maps.Clone(r.labels))
	} else {
		newRevision = round.single(maps.Clone(r.labels))
	}

	// Process objects that need to be retried that were not cleared.
	round.processRetries(maps.Clone(r.labels))

	// Finally commit the status updates.
	watch := round.commitStatus()

	if round.numReconciled >= r.Config.IncrementalRoundSize {
		// Round size limit was hit, use a closed watch channel to retrigger
		// incremental reconciliation immediately.
		watch = closedWatchChannel
	}

	r.Metrics.IncrementalReconciliationTotalErrors.With(r.labels).Add(float64(len(round.errs)))
	r.Metrics.IncrementalReconciliationCurrentErrors.With(r.labels).Set(float64(len(round.errs)))
	r.Metrics.IncrementalReconciliationCount.With(r.labels).Add(1)

	if len(round.errs) > 0 {
		return newRevision, watch, fmt.Errorf("incremental: %w", joinErrors(round.errs))
	}
	return newRevision, watch, nil
}

func (round *incrementalRound[Obj]) single(labels prometheus.Labels) statedb.Revision {
	// Iterate in revision order through new and changed objects.
	newRevision := round.oldRevision
	iter, _ := round.table.LowerBound(round.txn, statedb.ByRevision[Obj](round.oldRevision+1))
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		newRevision = rev

		status := round.config.GetObjectStatus(obj)
		if status.Kind != StatusKindPending {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear retries as the object has changed.
		round.retries.Clear(obj)

		err := round.processSingle(obj, rev, status, labels)
		if err != nil {
			round.errs = append(round.errs, err)
		}

		round.numReconciled++
		if round.numReconciled >= round.config.IncrementalRoundSize {
			break
		}
	}
	return newRevision
}

func (round *incrementalRound[Obj]) batch(labels prometheus.Labels) statedb.Revision {
	ops := round.config.BatchOperations
	updateBatch := []BatchEntry[Obj]{}
	deleteBatch := []BatchEntry[Obj]{}

	// Iterate in revision order through new and changed objects.
	newRevision := round.oldRevision
	iter, _ := round.table.LowerBound(round.txn, statedb.ByRevision[Obj](round.oldRevision+1))
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		newRevision = rev

		status := round.config.GetObjectStatus(obj)
		if status.Kind != StatusKindPending {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear an existing retry as the object has changed.
		round.retries.Clear(obj)

		if status.Delete {
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
		labels[LabelOperation] = OpDelete
		round.metrics.IncrementalReconciliationDuration.With(labels).Observe(
			float64(time.Since(start)) / float64(time.Second),
		)
		for _, entry := range deleteBatch {
			if entry.Result == nil {
				// Reconciling succeeded, so clear the retries.
				round.retries.Clear(entry.Object)
				round.results[entry.Object] = opResult{rev: entry.Revision, delete: true}
			} else {
				round.errs = append(round.errs, entry.Result)
				round.results[entry.Object] = opResult{rev: entry.Revision, status: StatusError(true, entry.Result)}
			}
		}
	}

	// And then the update batch.
	if len(updateBatch) > 0 {
		start := time.Now()
		ops.UpdateBatch(round.ctx, round.txn, updateBatch)
		labels[LabelOperation] = OpUpdate
		round.metrics.IncrementalReconciliationDuration.With(labels).Observe(
			float64(time.Since(start)) / float64(time.Second),
		)

		for _, entry := range updateBatch {
			if entry.Result == nil {
				// Reconciling succeeded, so clear the retries.
				round.retries.Clear(entry.Object)
				round.results[entry.Object] = opResult{rev: entry.Revision, status: StatusDone()}
			} else {
				round.errs = append(round.errs, entry.Result)
				round.results[entry.Object] = opResult{rev: entry.Revision, status: StatusError(false, entry.Result)}
			}
		}
	}
	return newRevision
}

func (round *incrementalRound[Obj]) processRetries(labels prometheus.Labels) {
	now := time.Now()
	for round.numReconciled < round.config.IncrementalRoundSize {
		robj, retryAt, ok := round.retries.Top()
		if !ok || retryAt.After(now) {
			break
		}
		round.retries.Pop()

		obj, rev, ok := round.table.First(round.txn, round.primaryIndexer.QueryFromObject(robj.(Obj)))
		if !ok {
			// Object has been deleted unexpectedly (e.g. from outside
			// the reconciler). Assume that it can be forgotten about.
			round.retries.Clear(robj)
			continue
		}

		status := round.config.GetObjectStatus(obj)
		if status.Kind != StatusKindError {
			continue
		}

		err := round.processSingle(obj, rev, status, labels)
		if err != nil {
			round.errs = append(round.errs, err)
		}

		round.numReconciled++
	}
}

func (round *incrementalRound[Obj]) processSingle(obj Obj, rev statedb.Revision, status Status, labels prometheus.Labels) error {
	start := time.Now()

	var err error
	if status.Delete {
		labels[LabelOperation] = OpDelete
		err = round.config.Operations.Delete(round.ctx, round.txn, obj)
		if err == nil {
			round.results[obj] = opResult{rev: rev, delete: true}
		} else {
			round.results[obj] = opResult{rev: rev, status: StatusError(true, err)}
		}
	} else {
		labels[LabelOperation] = OpUpdate
		err = round.config.Operations.Update(round.ctx, round.txn, obj, nil /* changed */)
		if err == nil {
			round.results[obj] = opResult{rev: rev, status: StatusDone()}
		} else {
			round.results[obj] = opResult{rev: rev, status: StatusError(false, err)}
		}
	}
	round.metrics.IncrementalReconciliationDuration.With(labels).Observe(
		float64(time.Since(start)) / float64(time.Second),
	)

	if err == nil {
		// Reconciling succeeded, so clear the object.
		round.retries.Clear(obj)
	}

	return err

}

func (round *incrementalRound[Obj]) commitStatus() <-chan struct{} {
	if len(round.results) == 0 {
		// Nothing to commit.
		_, watch := round.table.All(round.txn)
		return watch
	}

	wtxn := round.db.WriteTxn(round.table)
	defer wtxn.Commit()

	// The revision before committing the status updates.
	revBeforeWrite := round.table.Revision(wtxn)

	// Commit status for updated objects.
	for obj, result := range round.results {
		if result.delete {
			round.table.CompareAndDelete(wtxn, result.rev, obj)
			continue
		}

		// Update the object if it is unchanged. It may happen that the object has
		// been updated in the meanwhile, in which case we ignore the status as the
		// update will be picked up by next reconciliation round.
		round.table.CompareAndSwap(wtxn, result.rev, round.config.WithObjectStatus(obj, result.status))

		if result.status.Kind == StatusKindError {
			// Reconciling the object failed, so add it to be retried now that it's
			// status is updated.
			round.retries.Add(obj)
		}
	}

	watch := closedWatchChannel
	if round.oldRevision == revBeforeWrite {
		// No changes happened between the ReadTxn and this WriteTxn. Grab a new
		// watch channel of the root to only watch for new changes after
		// this write.
		//
		// If changes did happen, we'll return a closed watch channel and
		// immediately reconcile again.
		_, watch = round.table.All(wtxn)
	}
	return watch
}
