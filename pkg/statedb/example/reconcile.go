// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

var reconcilerCell = cell.Module(
	"reconciler",
	"Backend reconciler",
	cell.Invoke(registerReconciler),
)

type reconcilerParams struct {
	cell.In

	Backends  statedb.RWTable[Backend]
	DB        *statedb.DB
	Lifecycle cell.Lifecycle
	Log       logrus.FieldLogger
	Registry  job.Registry
	Scope     cell.Scope
	Reporter  cell.HealthReporter
}

func registerReconciler(p reconcilerParams) {
	g := p.Registry.NewGroup(p.Scope)
	r := &reconciler{
		reconcilerParams: p,
		handle:           &backendsHandle{backends: sets.New[BackendID]()},
	}
	g.Add(job.OneShot("reconcile-loop", r.reconcileLoop))
	p.Lifecycle.Append(g)
}

type reconciler struct {
	reconcilerParams

	handle *backendsHandle
}

func (r *reconciler) reconcileLoop(ctx context.Context, health cell.HealthReporter) error {
	defer r.Reporter.Stopped("Stopped")

	wtxn := r.DB.WriteTxn(r.Backends)
	deleteTracker, err := r.Backends.DeleteTracker(wtxn, "backends-reconciler")
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer deleteTracker.Close()

	txn := r.DB.ReadTxn()
	minRevision := statedb.Revision(0)

	// Limit processing rate to 10 op/s.
	burst := int64(10)
	limiter := rate.NewLimiter(time.Second, burst)

	// Backoff on failures.
	backoff := backoff.Exponential{
		Min: 100 * time.Millisecond,
		Max: time.Second,
	}

	for {
		tableRevision := r.Backends.Revision(txn)
		r.Log.WithField("minRevision", minRevision).Info("Reconciling backends")

		// Process upserts and deletions between minRevision..maxRevision.
		// Returns the new revision to run the next query from.
		newRevision, watch, processErr := deleteTracker.Process(
			txn,
			minRevision,
			func(be Backend, deleted bool, rev statedb.Revision) error {
				if err := limiter.Wait(ctx); err != nil {
					return err
				}
				if deleted {
					err := r.handle.Delete(be)
					if err != nil {
						r.Log.WithError(err).WithField("revision", rev).WithField("id", be.ID).Warn("Failed to delete backend")
					}
					return err
				} else {
					err := r.handle.Insert(be)
					if err != nil {
						r.Log.WithError(err).WithField("revision", rev).WithField("id", be.ID).Warn("Failed to insert backend")
					}
					return err
				}
			},
		)

		minRevision = newRevision

		if processErr != nil {
			r.Reporter.Degraded(fmt.Sprintf("Failure at revision %d, latest is %d", minRevision, tableRevision), processErr)
			if err := backoff.Wait(ctx); err != nil {
				return err
			}
		} else {
			backoff.Reset()
			r.Reporter.OK(fmt.Sprintf("All processed up to %d", minRevision))

			fmt.Printf(">>> validate revision %d\n", newRevision)
			r.validate(txn)
		}

		// Wait until something changes or we're being stopped.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		// Refresh the read transaction to read the new version of the state.
		txn = r.DB.ReadTxn()
	}
}

func (r *reconciler) validate(txn statedb.ReadTxn) {

	iter, _ := r.Backends.All(txn)
	n := 0
	objs := []Backend{}
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		n++
		objs = append(objs, obj)
	}
	if n != r.handle.backends.Len() {
		panic(fmt.Sprintf("validate failed, expected %+v, seeing %+v", objs, r.handle.backends))
	}
}

// backendsHandle implements a fake "BPF map" implementation
// that fails often.
type backendsHandle struct {
	backends sets.Set[BackendID]
}

func maybeFail(op string, id BackendID) error {
	// Fails 10% of the time
	if rand.Intn(10) == 0 {
		return fmt.Errorf("failure to %s %s", op, id)
	}
	return nil
}

func (h *backendsHandle) Insert(b Backend) error {
	if err := maybeFail("Insert", b.ID); err != nil {
		return err
	}
	fmt.Printf(">>> Insert %s\n", b.ID)
	h.backends.Insert(b.ID)
	return nil
}

func (h *backendsHandle) Delete(b Backend) error {
	if err := maybeFail("Delete", b.ID); err != nil {
		return err
	}
	fmt.Printf(">>> Delete %s\n", b.ID)
	h.backends.Delete(b.ID)
	return nil
}
