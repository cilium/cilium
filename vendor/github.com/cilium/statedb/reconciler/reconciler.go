// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"golang.org/x/time/rate"
)

// Register creates a new reconciler and registers to the application
// lifecycle. To be used with cell.Invoke when the API of the reconciler
// is not needed.
func Register[Obj comparable](cfg Config[Obj], params Params) error {
	_, err := New(cfg, params)
	return err
}

// New creates and registers a new reconciler.
func New[Obj comparable](cfg Config[Obj], p Params) (Reconciler[Obj], error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if cfg.RateLimiter == nil {
		cfg.RateLimiter = defaultRoundRateLimiter()
	}

	if cfg.RefreshRateLimiter == nil {
		cfg.RefreshRateLimiter = defaultRoundRateLimiter()
	}

	metrics := cfg.Metrics
	if metrics == nil {
		if p.DefaultMetrics == nil {
			metrics = NewUnpublishedExpVarMetrics()
		} else {
			metrics = p.DefaultMetrics
		}
	}

	idx := cfg.Table.PrimaryIndexer()
	objectToKey := func(o any) index.Key {
		return idx.ObjectToKey(o.(Obj))
	}
	r := &reconciler[Obj]{
		Params:               p,
		Config:               cfg,
		metrics:              metrics,
		retries:              newRetries(cfg.RetryBackoffMinDuration, cfg.RetryBackoffMaxDuration, objectToKey),
		externalPruneTrigger: make(chan struct{}, 1),
		primaryIndexer:       idx,
	}

	g := p.Jobs.NewGroup(p.Health)

	g.Add(job.OneShot("reconcile", r.reconcileLoop))
	if r.Config.RefreshInterval > 0 {
		g.Add(job.OneShot("refresh", r.refreshLoop))
	}
	p.Lifecycle.Append(g)

	return r, nil
}

type Params struct {
	cell.In

	Lifecycle      cell.Lifecycle
	Log            *slog.Logger
	DB             *statedb.DB
	Jobs           job.Registry
	ModuleID       cell.FullModuleID
	Health         cell.Health
	DefaultMetrics Metrics `optional:"true"`
}

type reconciler[Obj comparable] struct {
	Params
	Config               Config[Obj]
	metrics              Metrics
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
	if r.Config.PruneInterval > 0 {
		pruneTicker := time.NewTicker(r.Config.PruneInterval)
		defer pruneTicker.Stop()
		pruneTickerChan = pruneTicker.C
	}

	// Create the change iterator to watch for inserts and deletes to the table.
	wtxn := r.DB.WriteTxn(r.Config.Table)
	changes, err := r.Config.Table.Changes(wtxn)
	txn := wtxn.Commit()
	if err != nil {
		return fmt.Errorf("watching for changes failed: %w", err)
	}

	tableWatchChan := closedWatchChannel

	for {
		// Throttle a bit before reconciliation to allow for a bigger batch to arrive and
		// for objects to settle.
		if err := r.Config.RateLimiter.Wait(ctx); err != nil {
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
		case <-pruneTickerChan:
			prune = true
		case <-r.externalPruneTrigger:
			prune = true
		}

		// Grab a new snapshot and refresh the changes iterator to read
		// in the new changes.
		txn = r.DB.ReadTxn()
		tableWatchChan = changes.Watch(txn)

		// Perform incremental reconciliation and retries of previously failed
		// objects.
		errs := r.incremental(ctx, txn, changes)

		// Prune objects if pruning is requested and table is fully initialized.
		if prune && r.Config.Table.Initialized(txn) {
			if err := r.prune(ctx, txn); err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) == 0 {
			health.OK(
				fmt.Sprintf("OK, %d objects", r.Config.Table.NumObjects(txn)))
		} else {
			health.Degraded(
				fmt.Sprintf("%d failure(s)", len(errs)),
				joinErrors(errs))
		}
	}
}

// prune performs the Prune operation to delete unexpected objects in the target system.
func (r *reconciler[Obj]) prune(ctx context.Context, txn statedb.ReadTxn) error {
	iter, _ := r.Config.Table.All(txn)
	start := time.Now()
	err := r.Config.Operations.Prune(ctx, txn, iter)
	if err != nil {
		err = fmt.Errorf("prune failed: %w", err)
	}
	r.metrics.PruneDuration(r.ModuleID, time.Since(start))
	r.metrics.PruneError(r.ModuleID, err)

	return err
}

func (r *reconciler[Obj]) refreshLoop(ctx context.Context, health cell.Health) error {
	lastRevision := statedb.Revision(0)

	refreshTimer := time.NewTimer(r.Config.RefreshInterval)
	defer refreshTimer.Stop()

	health.OK(fmt.Sprintf("Refreshing in %s", r.Config.RefreshInterval))
outer:
	for {
		// Wait until it's time to refresh.
		select {
		case <-ctx.Done():
			return nil

		case <-refreshTimer.C:
		}

		now := time.Now()

		// Iterate over the objects in revision order, e.g. oldest modification first.
		// We look for objects that are older than [RefreshInterval] and mark them for
		// pending in order for them to be reconciled again.
		iter, _ := r.Config.Table.LowerBound(r.DB.ReadTxn(), statedb.ByRevision[Obj](lastRevision+1))
		indexer := r.Config.Table.PrimaryIndexer()
		for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
			status := r.Config.GetObjectStatus(obj)

			// Have we reached an object that is newer than RefreshInterval?
			if now.Sub(status.UpdatedAt) < r.Config.RefreshInterval {
				// Reset the timer to fire when this now oldest object should be
				// refreshed.
				nextRefreshIn := min(
					0,
					now.Sub(status.UpdatedAt)-r.Config.RefreshInterval,
				)
				refreshTimer.Reset(nextRefreshIn)
				health.OK(fmt.Sprintf("Refreshing in %s", nextRefreshIn))
				continue outer
			}

			lastRevision = rev

			if status.Kind == StatusKindDone {
				if r.Config.RefreshRateLimiter != nil {
					// Limit the rate at which objects are marked for refresh to avoid disrupting
					// normal work.
					if err := r.Config.RefreshRateLimiter.Wait(ctx); err != nil {
						break
					}
				}

				// Mark the object for refreshing. We make the assumption that refreshing is spread over
				// time enough that batching of the writes is not useful here.
				wtxn := r.DB.WriteTxn(r.Config.Table)
				obj, newRev, ok := r.Config.Table.Get(wtxn, indexer.QueryFromObject(obj))
				if ok && rev == newRev {
					obj = r.Config.SetObjectStatus(r.Config.CloneObject(obj), StatusRefreshing())
					r.Config.Table.Insert(wtxn, obj)
				}
				wtxn.Commit()
			}
		}

		// Since we reached here there were no objects. Set the timer for the full
		// RefreshInterval.
		refreshTimer.Reset(r.Config.RefreshInterval)
	}
}

func defaultRoundRateLimiter() *rate.Limiter {
	// By default limit the rate of reconciliation rounds to 100 times per second.
	// This enables the reconciler to operate on batches of objects at a time, which
	// enables efficient use of the batch operations and amortizes the cost of WriteTxn.
	return rate.NewLimiter(100.0, 1)
}

func defaultRefreshRateLimiter() *rate.Limiter {
	// By default limit the object refresh rate to 100 objects per second. This avoids a
	// stampade of refreshes that could delay normal updates.
	return rate.NewLimiter(100.0, 1)
}
