// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
)

// Register creates a new reconciler and registers to the application
// lifecycle. To be used with cell.Invoke when the API of the reconciler
// is not needed.
func Register[Obj comparable](p Params[Obj]) error {
	_, err := New(p)
	return err
}

// New creates and registers a new reconciler.
func New[Obj comparable](p Params[Obj]) (Reconciler[Obj], error) {
	if err := p.Config.validate(); err != nil {
		return nil, err
	}

	idx := p.Table.PrimaryIndexer()
	objectToKey := func(o any) index.Key {
		return idx.ObjectToKey(o.(Obj))
	}
	r := &reconciler[Obj]{
		Params:              p,
		retries:             newRetries(p.Config.RetryBackoffMinDuration, p.Config.RetryBackoffMaxDuration, objectToKey),
		externalFullTrigger: make(chan struct{}, 1),
		labels: prometheus.Labels{
			LabelModuleId: string(p.ModuleId),
		},
		primaryIndexer: idx,
	}

	g := p.Jobs.NewGroup(p.Health)

	g.Add(job.OneShot("reconciler-loop", r.loop))
	p.Lifecycle.Append(g)

	return r, nil
}

type Params[Obj comparable] struct {
	cell.In

	Config    Config[Obj]
	Lifecycle cell.Lifecycle
	DB        *statedb.DB
	Table     statedb.RWTable[Obj]
	Jobs      job.Registry
	Metrics   *Metrics
	ModuleId  cell.ModuleID
	Health    cell.Health
}

type reconciler[Obj comparable] struct {
	Params[Obj]
	retries             *retries
	externalFullTrigger chan struct{}
	primaryIndexer      statedb.Indexer[Obj]
	labels              prometheus.Labels
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
		_, _, watchPending, okPending := table.FirstWatch(txn, statusIndex.Query(StatusKindPending))
		_, _, watchError, okError := table.FirstWatch(txn, statusIndex.Query(StatusKindError))
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
	if r.Config.RateLimiter != nil {
		defer r.Config.RateLimiter.Stop()
	}

	tableWatchChan := closedWatchChannel
	revision := statedb.Revision(0)
	fullReconciliation := false

	for {
		if r.Config.RateLimiter != nil {
			r.Config.RateLimiter.Wait(ctx)
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

		var (
			err  error
			errs []error
			txn  = r.DB.ReadTxn()
		)

		// Perform incremental reconciliation and retries of previously failed
		// objects.
		revision, tableWatchChan, err = r.incremental(ctx, txn, revision)
		if err != nil {
			errs = append(errs, err)
		}

		if fullReconciliation {
			// Time to perform a full reconciliation. An incremental reconciliation
			// has been performed prior to this, so the assumption is that everything
			// is up to date (provided incremental reconciliation did not fail). We
			// report full reconciliation disparencies as they're indicative of something
			// interfering with Cilium operations.

			// Clear full reconciliation even if there's errors. Individual objects
			// will be retried via the retry queue.
			fullReconciliation = false

			var err error
			revision, err = r.full(ctx, txn, revision)
			if err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) == 0 {
			health.OK(fmt.Sprintf("OK, %d objects", r.Table.NumObjects(txn)))
		} else {
			health.Degraded("Reconciliation failed", errors.Join(errs...))
		}
	}
}
