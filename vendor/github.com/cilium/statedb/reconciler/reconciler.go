// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

type reconciler[Obj comparable] struct {
	Params
	config               config[Obj]
	retries              *retries
	externalPruneTrigger chan struct{}
	primaryIndexer       statedb.Indexer[Obj]
	progress             *progressTracker
}

func (r *reconciler[Obj]) Prune() {
	select {
	case r.externalPruneTrigger <- struct{}{}:
	default:
	}
}

func (r *reconciler[Obj]) WaitUntilReconciled(ctx context.Context, untilRevision statedb.Revision) (statedb.Revision, statedb.Revision, error) {
	return r.progress.wait(ctx, untilRevision)
}

func (r *reconciler[Obj]) reconcileLoop(ctx context.Context, health cell.Health) error {
	var pruneTickerChan <-chan time.Time
	if r.config.PruneInterval > 0 {
		pruneTicker := time.NewTicker(r.config.PruneInterval)
		defer pruneTicker.Stop()
		pruneTickerChan = pruneTicker.C
	}

	// Create the change iterator to watch for inserts and deletes to the table.
	wtxn := r.DB.WriteTxn(r.config.Table)
	changeIterator, err := r.config.Table.Changes(wtxn)
	startTxn := wtxn.Commit()
	if err != nil {
		return fmt.Errorf("watching for changes failed: %w", err)
	}
	defer changeIterator.Close()

	var (
		tableWatchChan       = closedWatchChannel
		pruneRequested       = false
		initialSetReconciled = false
		initialTxn           statedb.ReadTxn

		incremental = incremental[Obj]{
			moduleID:       r.ModuleID,
			name:           r.config.Name,
			metrics:        r.config.Metrics,
			config:         &r.config,
			retries:        r.retries,
			primaryIndexer: r.primaryIndexer,
			db:             r.DB,
			table:          r.config.Table,
			results:        make(map[Obj]opResult),
			lastRevision:   0,
		}
	)
	_, tableInitWatch := r.config.Table.Initialized(startTxn)

	for {
		// Throttle a bit before reconciliation to allow for a bigger batch to arrive and
		// for objects to settle.
		if err := r.config.RateLimiter.Wait(ctx); err != nil {
			return err
		}

		// Wait for trigger
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.retries.Wait():
			// Object(s) are ready to be retried
		case <-tableWatchChan:
			// Table has changed
		case <-tableInitWatch:
			// Table has been initialized
		case <-pruneTickerChan:
			pruneRequested = true
		case <-r.externalPruneTrigger:
			pruneRequested = true
		}

		// Pin the snapshot when initialization is observed and drain it across
		// rounds. Otherwise concurrent writes could move initial objects past
		// the revision being reconciled and allow pruning before their first attempt.
		txn := initialTxn
		if txn == nil {
			txn = r.DB.ReadTxn()
			if !initialSetReconciled {
				if initialized, _ := r.config.Table.Initialized(txn); initialized {
					// Table has become initialized. Keep processing this snapshot
					// until we've done enough rounds to exhaust it and we can
					// perform the initial pruning.
					initialTxn = txn
					tableInitWatch = nil
					pruneRequested = pruneRequested || r.config.PruneInterval != 0
				}
			}
		}
		var changes iter.Seq2[statedb.Change[Obj], statedb.Revision]
		changes, tableWatchChan = changeIterator.Next(txn)
		if initialTxn != nil {
			// Wrap 'changes' to track when we've processed all changes in the
			// snapshot after table initialization.
			seq := changes
			changes = func(yield func(statedb.Change[Obj], statedb.Revision) bool) {
				for change, rev := range seq {
					if !yield(change, rev) {
						return
					}
				}
				initialSetReconciled = true
			}
		}

		// Perform incremental reconciliation and retries of previously failed
		// objects.
		errs, retryLowWatermark := incremental.run(ctx, txn, changes)
		r.progress.update(incremental.lastRevision, retryLowWatermark)

		if initialSetReconciled {
			// Prune if it's requested and we've attempted reconciliation of all objects
			// in the initial snapshot. Use that same snapshot for the initial prune
			// so it does not include newer objects that have not been attempted yet.
			if pruneRequested {
				if err := r.prune(ctx, txn); err != nil {
					errs = append(errs, err)
				}
				pruneRequested = false
			}
			initialTxn = nil
		}

		if len(errs) == 0 {
			health.OK(
				fmt.Sprintf("OK, %d object(s)", r.config.Table.NumObjects(txn)))
		} else {
			health.Degraded(
				fmt.Sprintf("%d error(s)", len(errs)),
				joinErrors(errs))
		}
	}
}

// prune performs the Prune operation to delete unexpected objects in the target system.
func (r *reconciler[Obj]) prune(ctx context.Context, txn statedb.ReadTxn) error {
	iter := r.config.Table.All(txn)
	start := time.Now()
	err := r.config.Operations.Prune(ctx, txn, iter)
	if err != nil {
		r.Log.Warn("Reconciler: failed to prune objects", "error", err, "pruneInterval", r.config.PruneInterval)
		err = fmt.Errorf("prune: %w", err)
	}
	r.config.Metrics.PruneDuration(r.ModuleID, r.config.Name, time.Since(start))
	r.config.Metrics.PruneError(r.ModuleID, r.config.Name, err)
	return err
}

func (r *reconciler[Obj]) refreshLoop(ctx context.Context, health cell.Health) error {
	lastRevision := statedb.Revision(0)

	refreshTimer := time.NewTimer(0)
	defer refreshTimer.Stop()

	for {
		// Wait until it's time to refresh.
		select {
		case <-ctx.Done():
			return nil

		case <-refreshTimer.C:
		}

		durationUntilRefresh := r.config.RefreshInterval

		// Iterate over the objects in revision order, e.g. oldest modification first.
		// We look for objects that are older than [RefreshInterval] and mark them for
		// refresh in order for them to be reconciled again.
		seq := r.config.Table.LowerBound(r.DB.ReadTxn(), statedb.ByRevision[Obj](lastRevision+1))
		indexer := r.config.Table.PrimaryIndexer()

		for obj, rev := range seq {
			status := r.config.GetObjectStatus(obj)

			// The duration elapsed since this object was last updated.
			updatedSince := time.Since(status.UpdatedAt)

			// Have we reached an object that is newer than RefreshInterval?
			// If so, wait until this now oldest object's UpdatedAt exceeds RefreshInterval.
			if updatedSince < r.config.RefreshInterval {
				durationUntilRefresh = r.config.RefreshInterval - updatedSince
				break
			}

			lastRevision = rev

			if status.Kind == StatusKindDone {
				if r.config.RefreshRateLimiter != nil {
					// Limit the rate at which objects are marked for refresh to avoid disrupting
					// normal work.
					if err := r.config.RefreshRateLimiter.Wait(ctx); err != nil {
						break
					}
				}

				// Mark the object for refreshing. We make the assumption that refreshing is spread over
				// time enough that batching of the writes is not useful here.
				wtxn := r.DB.WriteTxn(r.config.Table)
				obj, newRev, ok := r.config.Table.Get(wtxn, indexer.QueryFromObject(obj))
				if ok && rev == newRev {
					obj = r.config.SetObjectStatus(r.config.CloneObject(obj), StatusRefreshing())
					r.config.Table.Insert(wtxn, obj)
				}
				wtxn.Commit()
			}
		}

		refreshTimer.Reset(durationUntilRefresh)
		health.OK(fmt.Sprintf("Next refresh in %s", durationUntilRefresh))
	}
}
