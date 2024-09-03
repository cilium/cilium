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

type reconciler[Obj comparable] struct {
	Params
	config               config[Obj]
	retries              *retries
	externalPruneTrigger chan struct{}
	primaryIndexer       statedb.Indexer[Obj]
}

func (r *reconciler[Obj]) Prune() {
	select {
	case r.externalPruneTrigger <- struct{}{}:
	default:
	}
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
	changes, err := r.config.Table.Changes(wtxn)
	txn := wtxn.Commit()
	if err != nil {
		return fmt.Errorf("watching for changes failed: %w", err)
	}

	tableWatchChan := closedWatchChannel

	externalPrune := false

	tableInitialized := false
	_, tableInitWatch := r.config.Table.Initialized(txn)

	for {
		// Throttle a bit before reconciliation to allow for a bigger batch to arrive and
		// for objects to settle.
		if err := r.config.RateLimiter.Wait(ctx); err != nil {
			return err
		}

		prune := false

		// Wait for trigger
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.retries.Wait():
			// Object(s) are ready to be retried
		case <-tableWatchChan:
			// Table has changed
		case <-tableInitWatch:
			tableInitialized = true
			tableInitWatch = nil

			// Do an immediate pruning now as the table has finished
			// initializing and pruning is enabled.
			prune = r.config.PruneInterval != 0
		case <-pruneTickerChan:
			prune = true
		case <-r.externalPruneTrigger:
			externalPrune = true
		}

		// Grab a new snapshot and refresh the changes iterator to read
		// in the new changes.
		txn = r.DB.ReadTxn()
		tableWatchChan = changes.Watch(txn)

		// Perform incremental reconciliation and retries of previously failed
		// objects.
		errs := r.incremental(ctx, txn, changes)

		if tableInitialized && (prune || externalPrune) {
			if err := r.prune(ctx, txn); err != nil {
				errs = append(errs, err)
			}
			externalPrune = false
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
	r.config.Metrics.PruneDuration(r.ModuleID, time.Since(start))
	r.config.Metrics.PruneError(r.ModuleID, err)
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
		iter := r.config.Table.LowerBound(r.DB.ReadTxn(), statedb.ByRevision[Obj](lastRevision+1))
		indexer := r.config.Table.PrimaryIndexer()
		for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
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
