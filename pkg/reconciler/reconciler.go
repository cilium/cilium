package reconciler

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/statedb"
)

type params[Obj Reconcilable[Obj]] struct {
	cell.In

	Config      Config
	Lifecycle   hive.Lifecycle
	Log         logrus.FieldLogger
	DB          *statedb.DB
	Table       statedb.RWTable[Obj]
	StatusIndex statedb.Index[Obj, StatusKind]
	Target      Target[Obj]
	Jobs        job.Registry
	Metrics     *reconcilerMetrics
	ModuleId    cell.ModuleId
	Health      cell.HealthReporter
}

type reconciler[Obj Reconcilable[Obj]] struct {
	params[Obj]

	labels prometheus.Labels
}

func New[Obj Reconcilable[Obj]](p params[Obj]) Reconciler[Obj] {
	r := &reconciler[Obj]{
		params: p,
		labels: prometheus.Labels{
			LabelModuleId: string(p.ModuleId),
		},
	}

	g := p.Jobs.NewGroup()
	g.Add(job.OneShot("reconciler-loop", r.loop))
	p.Lifecycle.Append(g)
	return r
}

func (r *reconciler[Obj]) loop(ctx context.Context) error {
	r.Log.Info("reconciler started")

	fullReconTicker := time.NewTicker(r.Config.FullReconcilationInterval)
	defer fullReconTicker.Stop()

	backoff := backoff.Exponential{
		Min: r.Config.RetryBackoffMinDuration,
		Max: r.Config.RetryBackoffMaxDuration,
	}
	retryAttempt := 0
	retryTimer, stopRetryTimer := inctimer.New()
	defer stopRetryTimer()
	var retryChan <-chan time.Time

	scheduleRetry := func() {
		retryAttempt++
		t := backoff.Duration(retryAttempt)
		retryChan = retryTimer.After(t)
	}

	tableWatchChan := closedWatchChannel()

	revision := statedb.Revision(0)

	fullReconciliation := false

	for {

		r.Log.Info("Waiting for trigger")

		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-fullReconTicker.C:
			fullReconciliation = true

		case <-tableWatchChan:
		case <-retryChan:
		}

		txn := r.DB.ReadTxn()

		var err error

		r.Log.Info("Incremental reconciliation")
		revision, tableWatchChan, err = r.incremental(ctx, txn, revision)
		if err != nil {
			r.Log.WithError(err).Warn("Incremental reconcilation failed, retrying")
			r.Health.Degraded("Incremental reconciliation failure", err)
			scheduleRetry()
			continue
		}

		if fullReconciliation {
			r.Log.Info("Full reconciliation")

			// Time to perform a full reconciliation. An incremental reconciliation
			// has been performed prior to this, so the assumption is that everything
			// is up to date (provided incremental reconciliation did not fail). We
			// report full reconciliation disparencies as they're indicative of something
			// interfering with Cilium operations.
			var err error
			revision, err = r.full(ctx, txn, revision)
			if err != nil {
				r.Log.WithError(err).Warn("Full reconciliation failed, retrying")
				r.Health.Degraded("Full reconciliation failure", err)
				scheduleRetry()
				continue
			}
		}

		// Clear retries after success.
		retryChan = nil
		retryAttempt = 0
		stopRetryTimer()
		fullReconciliation = false
		r.Health.OK("Nominal")
	}
}

func (r *reconciler[Obj]) incremental(
	ctx context.Context,
	txn statedb.ReadTxn,
	lastRev statedb.Revision,
) (statedb.Revision, <-chan struct{}, error) {
	start := time.Now()

	// In order to not lock the table while doing potentially expensive operations,
	// we collect the reconciliation statuses for the objects and then commit them
	// afterwards. If the object has changed in the meanwhile the status update for
	// the old object is skipped.
	type result struct {
		rev    statedb.Revision
		status Status
	}
	updateResults := make(map[Obj]result)
	toBeDeleted := make(map[Obj]statedb.Revision)

	// lastSuccessRev is the highest revision that was successfully reconciled
	// without any failures prior to it. This revision will be used in the next
	// reconciliation round.
	lastSuccessRev := statedb.Revision(lastRev)
	var errs []error

	// Iterate in revision order through new, changed or failed objects.
	iter, watch := r.Table.LowerBound(txn, statedb.ByRevision[Obj](lastRev+1))
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		status := obj.GetStatus()

		// Ignore objects that have already been marked as reconciled.
		if status.Kind == StatusKindDone {
			if len(errs) == 0 {
				lastSuccessRev = rev
			}
			continue
		}

		var err error
		if status.Delete {
			err = r.Target.Delete(obj)
			if err == nil {
				toBeDeleted[obj] = rev
			} else {
				updateResults[obj] = result{rev, StatusError(true, err)}
			}
		} else {
			err = r.Target.Update(obj)
			if err == nil {
				updateResults[obj] = result{rev, StatusDone()}
			} else {
				updateResults[obj] = result{rev, StatusError(false, err)}
			}
		}

		if len(errs) == 0 && err == nil {
			// Keep track of the last successfully processed revision so
			// on retry we can skip everything that has already been
			// processed.
			lastSuccessRev = rev
		} else if err != nil {
			errs = append(errs, err)
		}
	}

	wtxn := r.DB.WriteTxn(r.Table)
	defer wtxn.Commit()

	// Commit status for updated objects.
	for obj, result := range updateResults {
		// Update the object if it is unchanged. It may happen that the object has
		// been updated in the meanwhile, in which case we ignore the status as the
		// update will be picked up by next reconciliation round.
		r.Table.CompareAndSwap(wtxn, result.rev, obj.WithStatus(result.status))
	}

	// Delete the objects that had been successfully deleted from target.
	// The object is only deleted if it has not been changed.
	for obj, rev := range toBeDeleted {
		r.Table.CompareAndDelete(wtxn, rev, obj)
	}

	r.Metrics.IncrementalReconciliationTotalErrors.With(r.labels).Add(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCurrentErrors.With(r.labels).Set(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCount.With(r.labels).Add(1)
	r.Metrics.IncrementalReconciliationDuration.With(r.labels).Observe(
		float64(time.Since(start)) / float64(time.Second),
	)

	r.Log.Infof("Incremental done (%d, %s)", lastSuccessRev, errs)

	return lastSuccessRev, watch, errors.Join(errs...)
}

func (r *reconciler[Obj]) full(ctx context.Context, txn statedb.ReadTxn, lastRev statedb.Revision) (statedb.Revision, error) {
	start := time.Now()

	defer r.Metrics.FullReconciliationCount.With(r.labels).Add(1)

	iter, _ := r.Table.All(txn)

	outOfSync, err := r.Target.Sync(iter)

	r.Metrics.FullReconciliationDuration.With(r.labels).Observe(
		float64(time.Since(start)) / float64(time.Second),
	)

	if err != nil {
		r.Metrics.FullReconciliationTotalErrors.With(r.labels).Add(1)
		// Sync failed, assume no changes and keep at the last revision.
		return lastRev, err
	}

	if outOfSync {
		r.Metrics.FullReconciliationOutOfSyncCount.With(r.labels).Add(1)
	}

	// Sync succeeded up to latest revision. Continue incremental reconciliation from
	// this revision.
	return r.Table.Revision(txn), nil
}

func closedWatchChannel() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
