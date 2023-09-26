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

func Register[Obj Reconcilable[Obj]](p params[Obj]) {
	r := &reconciler[Obj]{
		params: p,
		labels: prometheus.Labels{
			LabelModuleId: string(p.ModuleId),
		},
	}

	g := p.Jobs.NewGroup()
	g.Add(job.OneShot("reconciler-loop", r.loop))
	p.Lifecycle.Append(g)
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

	scheduleRetry := func() time.Duration {
		retryAttempt++
		t := backoff.Duration(retryAttempt)
		retryChan = retryTimer.After(t)
		return t
	}

	tableWatchChan := closedWatchChannel()

	revision := statedb.Revision(0)

	fullReconciliation := false

	for {
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

		revision, tableWatchChan, err = r.incremental(ctx, txn, revision)
		if err != nil {
			wait := scheduleRetry()
			r.Log.WithError(err).Warnf("Incremental reconcilation failed, retrying in %s", wait)
			r.Health.Degraded("Incremental reconciliation failure", err)
			continue
		}

		if fullReconciliation {
			// Time to perform a full reconciliation. An incremental reconciliation
			// has been performed prior to this, so the assumption is that everything
			// is up to date (provided incremental reconciliation did not fail). We
			// report full reconciliation disparencies as they're indicative of something
			// interfering with Cilium operations.
			var err error
			revision, err = r.full(ctx, txn, revision)
			if err != nil {
				wait := scheduleRetry()
				r.Log.WithError(err).Warnf("Full reconciliation failed, retrying in %s", wait)
				r.Health.Degraded("Full reconciliation failure", err)
				continue
			}
		}

		// Clear retries after success.
		retryChan = nil
		retryAttempt = 0
		stopRetryTimer()
		fullReconciliation = false

		// TODO: stats in health, e.g. number of objects and so on.
		r.Health.OK("Nominal")
	}
}

func (r *reconciler[Obj]) incremental(
	ctx context.Context,
	txn statedb.ReadTxn,
	lastRev statedb.Revision,
) (statedb.Revision, <-chan struct{}, error) {

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

		start := time.Now()

		var err error
		if status.Delete {
			err = r.Target.Delete(ctx, obj)
			if err == nil {
				toBeDeleted[obj] = rev
			} else {
				updateResults[obj] = result{rev, StatusError(true, err)}
			}
		} else {
			err = r.Target.Update(ctx, obj)
			if err == nil {
				updateResults[obj] = result{rev, StatusDone()}
			} else {
				updateResults[obj] = result{rev, StatusError(false, err)}
			}
		}

		r.Metrics.IncrementalReconciliationDuration.With(r.labels).Observe(
			float64(time.Since(start)) / float64(time.Second),
		)

		if len(errs) == 0 && err == nil {
			// Keep track of the last successfully processed revision so
			// on retry we can skip everything that has already been
			// processed.
			lastSuccessRev = rev
		} else if err != nil {
			errs = append(errs, err)
		}
	}

	{
		wtxn := r.DB.WriteTxn(r.Table)

		oldRev := r.Table.Revision(txn)
		newRev := r.Table.Revision(wtxn)

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

		if oldRev == newRev {
			// No changes happened between the ReadTxn and this WriteTxn. Since
			// we wrote the table the 'watch' channel has closed. Grab a new
			// watch channel of the root to only watch for new changes after
			// this write.
			_, watch = r.Table.All(wtxn)
		}

		wtxn.Commit()
	}

	r.Metrics.IncrementalReconciliationTotalErrors.With(r.labels).Add(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCurrentErrors.With(r.labels).Set(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCount.With(r.labels).Add(1)

	return lastSuccessRev, watch, errors.Join(errs...)
}

func (r *reconciler[Obj]) full(ctx context.Context, txn statedb.ReadTxn, lastRev statedb.Revision) (statedb.Revision, error) {
	start := time.Now()

	defer r.Metrics.FullReconciliationCount.With(r.labels).Add(1)

	iter, _ := r.Table.All(txn)

	outOfSync, err := r.Target.Sync(ctx, iter)

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
