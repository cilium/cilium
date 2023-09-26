package reconciler

import (
	"context"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

func NewStatusIndex[Obj Reconcilable[Obj]]() statedb.Index[Obj, StatusKind] {
	return statedb.Index[Obj, StatusKind]{
		Name: "status",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.String(string(obj.GetStatus().Kind)))
		},
		FromKey: func(k StatusKind) index.Key {
			return index.String(string(k))
		},
		Unique: false,
	}
}

// WaitForReconciliation blocks until all objects have been reconciled or the context
// has cancelled.
func WaitForReconciliation[Obj Reconcilable[Obj], Table statedb.Table[Obj]](
	ctx context.Context,
	db *statedb.DB,
	table Table,
	statusIndex statedb.Index[Obj, StatusKind],
) error {
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
