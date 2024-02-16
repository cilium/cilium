// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"context"

	"github.com/cilium/cilium/pkg/stream"
)

type Event[Obj any] struct {
	Object   Obj
	Revision Revision

	// Sync is true when this is a synchronization event. This means that the
	// current contents of the table at the time of Observe() have been sent
	// and further events are incremental updates.
	Sync    bool
	Deleted bool
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

		synced := false

		for {
			watch := dt.Iterate(to.db.ReadTxn(),
				func(obj Obj, deleted bool, rev uint64) {
					next(Event[Obj]{
						Object:   obj,
						Revision: rev,
						Deleted:  deleted,
					})
				})

			if !synced {
				synced = true
				next(Event[Obj]{Sync: true})
			}

			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()
}
