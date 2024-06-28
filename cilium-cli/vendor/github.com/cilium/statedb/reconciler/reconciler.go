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
		Params:              p,
		Config:              cfg,
		metrics:             metrics,
		retries:             newRetries(cfg.RetryBackoffMinDuration, cfg.RetryBackoffMaxDuration, objectToKey),
		externalFullTrigger: make(chan struct{}, 1),
		primaryIndexer:      idx,
	}

	g := p.Jobs.NewGroup(p.Health)

	g.Add(job.OneShot("reconciler-loop", r.loop))
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
	Config              Config[Obj]
	metrics             Metrics
	retries             *retries
	externalFullTrigger chan struct{}
	primaryIndexer      statedb.Indexer[Obj]
}

func (r *reconciler[Obj]) TriggerFullReconciliation() {
	select {
	case r.externalFullTrigger <- struct{}{}:
	default:
	}
}

// WaitForReconciliation blocks until all objects have been reconciled or the context
// has cancelled.
func WaitForReconciliation[Obj any](ctx context.Context, db *statedb.DB, table statedb.Table[Obj], statusIndex statedb.Index[Obj, StatusKind]) error {
	for {
		txn := db.ReadTxn()

		// See if there are any pending or error'd objects.
		_, _, watchPending, okPending := table.GetWatch(txn, statusIndex.Query(StatusKindPending))
		_, _, watchError, okError := table.GetWatch(txn, statusIndex.Query(StatusKindError))
		if !okPending && !okError {
			return nil
		}

		// Wait for updates before checking again.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watchPending:
		case <-watchError:
		}
	}
}

func (r *reconciler[Obj]) loop(ctx context.Context, health cell.Health) error {
	var fullReconTickerChan <-chan time.Time
	if r.Config.FullReconcilationInterval > 0 {
		fullReconTicker := time.NewTicker(r.Config.FullReconcilationInterval)
		defer fullReconTicker.Stop()
		fullReconTickerChan = fullReconTicker.C
	}

	// Create the change iterator to watch for inserts and deletes to the table.
	wtxn := r.DB.WriteTxn(r.Config.Table)
	changes, err := r.Config.Table.Changes(wtxn)
	txn := wtxn.Commit()
	if err != nil {
		return fmt.Errorf("watching for changes failed: %w", err)
	}

	tableWatchChan := closedWatchChannel
	fullReconciliation := false

	for {
		if r.Config.RateLimiter != nil {
			if err := r.Config.RateLimiter.Wait(ctx); err != nil {
				return err
			}
		}

		// Wait for trigger
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-fullReconTickerChan:
			fullReconciliation = true
		case <-r.externalFullTrigger:
			fullReconciliation = true

		case <-r.retries.Wait():
			// Object(s) are ready to be retried

		case <-tableWatchChan:
			// Table has changed
		}

		// Perform incremental reconciliation and retries of previously failed
		// objects.
		errs := r.incremental(ctx, txn, changes)

		// Refresh the transaction to read the new changes.
		txn = r.DB.ReadTxn()
		tableWatchChan = changes.Watch(txn)

		if fullReconciliation && r.Config.Table.Initialized(txn) {
			// Time to perform a full reconciliation. An incremental reconciliation
			// has been performed prior to this, so the assumption is that everything
			// is up to date (provided incremental reconciliation did not fail). We
			// report full reconciliation disparencies as they're indicative of something
			// interfering with Cilium operations.

			// Clear full reconciliation even if there's errors. Individual objects
			// will be retried via the retry queue.
			fullReconciliation = false

			errs = append(errs, r.full(ctx, txn)...)
		}

		if len(errs) == 0 {
			health.OK(
				fmt.Sprintf("OK, %d objects", r.Config.Table.NumObjects(txn)))
		} else {
			health.Degraded(
				fmt.Sprintf("%d error(s)", len(errs)),
				joinErrors(errs))
		}
	}
}
