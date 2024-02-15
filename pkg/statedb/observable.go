// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"

	"github.com/cilium/stream"
)

type Event[Obj any] struct {
	Object   Obj
	Revision Revision
	Deleted  bool
}

// Observable creates an observable from the given table for observing the changes
// to the table as a stream of events.
//
// For high-churn tables it's advisable to apply rate-limiting to the stream to
// decrease overhead (stream.Throttle).
func Observable[Obj any](db *DB, table Table[Obj]) stream.Observable[Event[Obj]] {
	return &observable[Obj]{db, table}
}

type observable[Obj any] struct {
	db    *DB
	table Table[Obj]
}

func (to *observable[Obj]) Observe(ctx context.Context, next func(Event[Obj]), complete func(error)) {
	go func() {
		wtxn := to.db.WriteTxn(to.table)
		dt, err := to.table.DeleteTracker(wtxn, "Observe")
		wtxn.Commit()
		if err != nil {
			complete(err)
			return
		}
		defer dt.Close()
		defer complete(nil)

		for {
			watch := dt.Iterate(to.db.ReadTxn(),
				func(obj Obj, deleted bool, rev uint64) {
					next(Event[Obj]{
						Object:   obj,
						Revision: rev,
						Deleted:  deleted,
					})
				})

			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()
}
