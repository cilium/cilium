package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
)

func followExamples(jg job.Group, db *statedb.DB, table statedb.Table[Example]) {
	jg.Add(job.OneShot(
		"follow",
		func(ctx context.Context, _ cell.Health) error {
			// Start tracking changes to the table. This instructs the database
			// to keep deleted objects off to the side for us to observe.
			wtxn := db.WriteTxn(table)
			changeIterator, err := table.Changes(wtxn)
			wtxn.Commit()
			if err != nil {
				return err
			}

			for {
				// Iterate over the changed objects.
				changes, watch := changeIterator.Next(db.ReadTxn())
				for change, rev := range changes {
					e := change.Object
					fmt.Printf("ID: %d, CreatedAt: %s (revision: %d, deleted: %v)\n",
						e.ID, e.CreatedAt.Format(time.Stamp), rev, change.Deleted)
				}
				// Wait until there's new changes to consume.
				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				}
			}
		},
	))
}

func main() {
	hive.New(
		cell.Module("app", "Example app",
			Cell,
			cell.Invoke(followExamples),
		),
	).Run(logging.DefaultSlogLogger)
}
