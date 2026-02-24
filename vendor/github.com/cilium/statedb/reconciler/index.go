// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

// NewStatusIndex creates a status index for a table of reconcilable objects.
// This is optional and should be only used when there is a need to often check that all
// objects are fully reconciled that outweighs the cost of maintaining a status index.
func NewStatusIndex[Obj any](getObjectStatus func(Obj) Status) statedb.Index[Obj, StatusKind] {
	return statedb.Index[Obj, StatusKind]{
		Name: "status",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(getObjectStatus(obj).Kind.Key())
		},
		FromKey: StatusKind.Key,
		Unique:  false,
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
