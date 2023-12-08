// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

// Register creates a new reconciler and registers to the application
// lifecycle. To be used with cell.Invoke when the API of the reconciler
// is not needed.
func Register[Obj comparable](p params[Obj]) error {
	_, err := New(p)
	return err
}

// New creates and registers a new reconciler.
func New[Obj comparable](p params[Obj]) (Reconciler[Obj], error) {
	if err := p.Config.validate(); err != nil {
		return nil, err
	}

	idx := p.Table.PrimaryIndexer()
	objectToKey := func(o any) []byte {
		return idx.ObjectToKey(o.(Obj))
	}
	r := &reconciler[Obj]{
		params:              p,
		retries:             newRetries(p.Config.RetryBackoffMinDuration, p.Config.RetryBackoffMaxDuration, objectToKey),
		externalFullTrigger: make(chan struct{}, 1),
		labels: prometheus.Labels{
			LabelModuleId: string(p.ModuleId),
		},
		primaryIndexer: idx,
	}

	g := p.Jobs.NewGroup(p.Scope)

	g.Add(job.OneShot("reconciler-loop", r.loop))
	p.Lifecycle.Append(g)

	return r, nil
}

type params[Obj comparable] struct {
	cell.In

	Config     Config[Obj]
	Lifecycle  hive.Lifecycle
	Log        logrus.FieldLogger
	DB         *statedb.DB
	Table      statedb.RWTable[Obj]
	Operations Operations[Obj]
	Jobs       job.Registry
	Metrics    *Metrics
	ModuleId   cell.ModuleID
	Scope      cell.Scope
}

type reconciler[Obj comparable] struct {
	params[Obj]

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
func (r *reconciler[Obj]) WaitForReconciliation(ctx context.Context) error {
	for {
		txn := r.DB.ReadTxn()

		// See if there are any pending or error'd objects.
		_, _, watchPending, okPending := r.Table.FirstWatch(txn, r.Config.StatusIndex.Query(StatusKindPending))
		_, _, watchError, okError := r.Table.FirstWatch(txn, r.Config.StatusIndex.Query(StatusKindError))
		if !okPending && !okError {
			return nil
		}

		// Delay a bit to avoid querying often.
		time.Sleep(10 * time.Millisecond)

		// Wait for updates before checking again.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watchPending:
		case <-watchError:
		}
	}
}

func (r *reconciler[Obj]) loop(ctx context.Context, health cell.HealthReporter) error {
	var fullReconTickerChan <-chan time.Time
	if r.Config.FullReconcilationInterval > 0 {
		fullReconTicker := time.NewTicker(r.Config.FullReconcilationInterval)
		defer fullReconTicker.Stop()
		fullReconTickerChan = fullReconTicker.C
	}

	tableWatchChan := closedWatchChannel
	revision := statedb.Revision(0)
	fullReconciliation := false

	for {
		// Wait for trigger
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-fullReconTickerChan:
			fullReconciliation = true
		case <-r.externalFullTrigger:
			fullReconciliation = true

		case <-r.retries.Wait():

		case <-tableWatchChan:
		}

		txn := r.DB.ReadTxn()

		var (
			err  error
			errs []error
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
			health.Degraded("Reconciliation failed", joinErrors(errs))
		}
	}
}

type opResult struct {
	rev    statedb.Revision
	status Status
}

func (r *reconciler[Obj]) incremental(
	ctx context.Context,
	rtxn statedb.ReadTxn,
	lastRev statedb.Revision,
) (statedb.Revision, <-chan struct{}, error) {
	// In order to not lock the table while doing potentially expensive operations,
	// we collect the reconciliation statuses for the objects and then commit them
	// afterwards. If the object has changed in the meanwhile the status update for
	// the old object is skipped.
	updateResults := make(map[Obj]opResult)
	toBeDeleted := make(map[Obj]statedb.Revision)
	labels := maps.Clone(r.labels)
	errs := []error{}

	// Function to process the new&changed objects and retries.
	process := func(obj Obj, rev statedb.Revision, status Status) error {
		start := time.Now()

		var err error
		if status.Delete {
			labels[LabelOperation] = OpDelete
			err = r.Operations.Delete(ctx, rtxn, obj)
			if err == nil {
				toBeDeleted[obj] = rev
			} else {
				updateResults[obj] = opResult{rev, StatusError(true, err)}
			}
		} else {
			labels[LabelOperation] = OpUpdate
			_, err = r.Operations.Update(ctx, rtxn, obj)
			if err == nil {
				updateResults[obj] = opResult{rev, StatusDone()}
			} else {
				updateResults[obj] = opResult{rev, StatusError(false, err)}
			}
		}
		r.Metrics.IncrementalReconciliationDuration.With(labels).Observe(
			float64(time.Since(start)) / float64(time.Second),
		)

		if err != nil {
			// Reconciling the object failed, so add it to be retried.
			r.retries.Add(obj)
		} else {
			// Reconciling succeeded, so clear the object.
			r.retries.Clear(obj)
		}

		return err
	}

	// Keep track of the number of objects that have been reconciled in this
	// round and stop when it's above Config.IncrementalBatchSize. This allows
	// for timely reporting of status when lot of objects have changed and
	// reconciliation per object is slow.
	numReconciled := 0

	// Iterate in revision order through new and changed objects.
	newRevision := lastRev
	iter, _ := r.Table.LowerBound(rtxn, statedb.ByRevision[Obj](lastRev+1))
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		newRevision = rev

		status := r.Config.GetObjectStatus(obj)
		if status.Kind != StatusKindPending {
			// Only process objects that are pending reconciliation, e.g.
			// changed from outside.
			// Failures (e.g. StatusKindError) are processed via the retry queue.
			continue
		}

		// Clear an existing retry as the object has changed.
		r.retries.Clear(obj)

		err := process(obj, rev, status)
		if err != nil {
			errs = append(errs, err)
		}

		numReconciled++
		if numReconciled >= r.Config.IncrementalBatchSize {
			break
		}
	}

	// Process objects that are ready to be retried.
	now := time.Now()
	for numReconciled < r.Config.IncrementalBatchSize {
		robj, retryAt, ok := r.retries.Top()
		if !ok || retryAt.After(now) {
			break
		}
		r.retries.Pop()

		obj, rev, ok := r.Table.First(rtxn, r.primaryIndexer.QueryFromObject(robj.(Obj)))
		if !ok {
			// Object has been deleted unexpectedly (e.g. from outside
			// the reconciler). Assume that it can be forgotten about.
			r.retries.Clear(obj)
			continue
		}

		status := r.Config.GetObjectStatus(obj)
		if status.Kind != StatusKindError {
			continue
		}

		err := process(obj, rev, status)
		if err != nil {
			errs = append(errs, err)
		}

		numReconciled++
	}

	watch := closedWatchChannel

	// Commit status updates.
	{
		wtxn := r.DB.WriteTxn(r.Table)

		oldRev := r.Table.Revision(rtxn)
		newRev := r.Table.Revision(wtxn)

		// Commit status for updated objects.
		for obj, result := range updateResults {
			// Update the object if it is unchanged. It may happen that the object has
			// been updated in the meanwhile, in which case we ignore the status as the
			// update will be picked up by next reconciliation round.
			r.Table.CompareAndSwap(wtxn, result.rev, r.Config.WithObjectStatus(obj, result.status))
		}

		// Delete the objects that had been successfully deleted..
		// The object is only deleted if it has not been changed in the meanwhile.
		for obj, rev := range toBeDeleted {
			r.Table.CompareAndDelete(wtxn, rev, obj)
		}

		if oldRev == newRev {
			// No changes happened between the ReadTxn and this WriteTxn. Since
			// we wrote the table the 'watch' channel has closed. Grab a new
			// watch channel of the root to only watch for new changes after
			// this write.
			//
			// If changes did happen, we'll return a closed watch channel and
			// immediately reconcile again.
			_, watch = r.Table.All(wtxn)
		}

		wtxn.Commit()
	}

	if numReconciled >= r.Config.IncrementalBatchSize {
		// Batch size limit was hit, use a closed watch channel to retrigger
		// incremental reconciliation.
		watch = closedWatchChannel
	}

	r.Metrics.IncrementalReconciliationTotalErrors.With(r.labels).Add(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCurrentErrors.With(r.labels).Set(float64(len(errs)))
	r.Metrics.IncrementalReconciliationCount.With(r.labels).Add(1)

	if len(errs) > 0 {
		return newRevision, watch, fmt.Errorf("incremental: %w", joinErrors(errs))
	}
	return newRevision, watch, nil
}

func (r *reconciler[Obj]) full(ctx context.Context, txn statedb.ReadTxn, lastRev statedb.Revision) (statedb.Revision, error) {
	defer r.Metrics.FullReconciliationCount.With(r.labels).Add(1)

	var errs []error
	outOfSync := false

	// First perform pruning to make room in the target.
	iter, _ := r.Table.All(txn)
	start := time.Now()
	if err := r.Operations.Prune(ctx, txn, iter); err != nil {
		outOfSync = true
		errs = append(errs, fmt.Errorf("pruning failed: %w", err))
	}
	labels := maps.Clone(r.labels)
	labels[LabelOperation] = OpPrune
	r.Metrics.FullReconciliationDuration.With(labels).Observe(
		float64(time.Since(start)) / float64(time.Second),
	)

	// Call Update() for each desired object to validate that it is up-to-date.
	updateResults := make(map[Obj]opResult)
	iter, _ = r.Table.All(txn) // Grab a new iterator as Prune() may have consumed it.
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		start := time.Now()
		changed, err := r.Operations.Update(ctx, txn, obj)

		labels := maps.Clone(r.labels)
		labels[LabelOperation] = OpUpdate
		r.Metrics.FullReconciliationDuration.With(labels).Observe(
			float64(time.Since(start)) / float64(time.Second),
		)

		outOfSync = outOfSync || changed
		if err == nil {
			updateResults[obj] = opResult{rev, StatusDone()}
			r.retries.Clear(obj)
		} else {
			updateResults[obj] = opResult{rev, StatusError(false, err)}
			errs = append(errs, err)
		}
	}

	// Increment the out-of-sync counter if full reconciliation catched any out-of-sync
	// objects.
	if outOfSync {
		r.Metrics.FullReconciliationOutOfSyncCount.With(r.labels).Add(1)
	}

	// Commit the new desired object status. This is performed separately in order
	// to not lock the table when performing long-running target operations.
	// If the desired object has been updated in the meanwhile the status update is dropped.
	if len(updateResults) > 0 {
		wtxn := r.DB.WriteTxn(r.Table)
		for obj, result := range updateResults {
			obj = r.Config.WithObjectStatus(obj, result.status)
			_, _, err := r.Table.CompareAndSwap(wtxn, result.rev, obj)
			if err == nil && result.status.Kind != StatusKindDone {
				// Object had not changed in the meantime, queue the retry.
				r.retries.Add(obj)
			}
		}
		wtxn.Commit()
	}

	if len(errs) > 0 {
		r.Metrics.FullReconciliationTotalErrors.With(r.labels).Add(1)
		return r.Table.Revision(txn), fmt.Errorf("full: %w", joinErrors(errs))
	}

	// Sync succeeded up to latest revision. Continue incremental reconciliation from
	// this revision.
	return r.Table.Revision(txn), nil
}

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

const (
	// maxJoinedErrors limits the number of errors to join and return from
	// failed reconciliation. This avoids constructing a massive error for
	// health status when many operations fail at once.
	maxJoinedErrors = 10
)

func omittedError(n int) error {
	return fmt.Errorf("%d further errors omitted", n)
}

func joinErrors(errs []error) error {
	if len(errs) > maxJoinedErrors {
		errs = append(slices.Clone(errs)[:maxJoinedErrors], omittedError(len(errs)))
	}
	return errors.Join(errs...)
}
