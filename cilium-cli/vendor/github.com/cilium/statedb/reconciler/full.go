// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/statedb"
)

// full performs full reconciliation of all objects. First the Prune() operations is performed to clean up and then
// Update() is called for each object. Full reconciliation is used to recover from unexpected outside modifications.
func (r *reconciler[Obj]) full(ctx context.Context, txn statedb.ReadTxn) []error {
	var errs []error
	ops := r.Config.Operations

	// First perform pruning to make room in the target.
	iter, _ := r.Config.Table.All(txn)
	start := time.Now()
	if err := ops.Prune(ctx, txn, iter); err != nil {
		errs = append(errs, fmt.Errorf("pruning failed: %w", err))
	}
	r.metrics.FullReconciliationDuration(r.ModuleID, OpPrune, time.Since(start))

	// Call Update() for each desired object to validate that it is up-to-date.
	updateResults := make(map[Obj]opResult)
	iter, _ = r.Config.Table.All(txn) // Grab a new iterator as Prune() may have consumed it.
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		start := time.Now()
		orig := obj
		obj = r.Config.CloneObject(obj)
		err := ops.Update(ctx, txn, obj)
		r.metrics.FullReconciliationDuration(r.ModuleID, OpUpdate, time.Since(start))

		updateResults[obj] = opResult{rev: rev, err: err, original: orig}
		if err == nil {
			r.retries.Clear(obj)
		} else {
			errs = append(errs, err)
		}
	}

	// Commit the new desired object status. This is performed separately in order
	// to not lock the table when performing long-running target operations.
	// If the desired object has been updated in the meanwhile the status update is dropped.
	if len(updateResults) > 0 {
		wtxn := r.DB.WriteTxn(r.Config.Table)
		for obj, result := range updateResults {
			var status Status
			if result.err == nil {
				status = StatusDone()
			} else {
				status = StatusError(result.err)
			}
			obj = r.Config.SetObjectStatus(obj, status)
			_, _, err := r.Config.Table.CompareAndSwap(wtxn, result.rev, obj)
			if err == nil && result.err != nil {
				// Object had not changed in the meantime, queue the retry for
				// the failure.
				newRevision := r.Config.Table.Revision(wtxn)
				r.retries.Add(result.original.(Obj), newRevision, false, result.err)
			}
		}
		wtxn.Commit()
	}

	r.metrics.FullReconciliationErrors(r.ModuleID, errs)

	return errs
}
