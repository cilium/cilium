// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"

	"github.com/cilium/stream"
)

// Observable creates an observable from the given table for observing the changes
// to the table as a stream of events.
//
// For high-churn tables it's advisable to apply rate-limiting to the stream to
// decrease overhead (stream.Throttle).
func Observable[Obj any](db *DB, table Table[Obj]) stream.Observable[Change[Obj]] {
	return &observable[Obj]{db, table}
}

type observable[Obj any] struct {
	db    *DB
	table Table[Obj]
}

func (to *observable[Obj]) Observe(ctx context.Context, next func(Change[Obj]), complete func(error)) {
	go func() {
		txn := to.db.WriteTxn(to.table)
		iter, err := to.table.Changes(txn)
		txn.Commit()
		if err != nil {
			complete(err)
			return
		}
		defer complete(nil)

		for {
			changes, watch := iter.Next(to.db.ReadTxn())
			for change := range changes {
				if ctx.Err() != nil {
					break
				}
				next(change)
			}
			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()
}
