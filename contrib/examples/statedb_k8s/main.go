package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
)

func followPods(jg job.Group, db *statedb.DB, table statedb.Table[*v1.Pod]) {
	jg.Add(job.OneShot(
		"follow-pods",
		func(ctx context.Context, _ cell.Health) error {
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
					pod := change.Object
					fmt.Printf("Pod(%s/%s): %s (revision: %d, deleted: %v)\n",
						pod.Namespace, pod.Name, pod.Status.Phase,
						rev, change.Deleted)
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

var app = cell.Module(
	"app",
	"Example app",

	client.Cell, // client.Clientset
	PodsCell,    // Table[*Pod]

	cell.Invoke(followPods),
)

func main() {
	h := hive.New(app)
	h.RegisterFlags(pflag.CommandLine)
	if err := pflag.CommandLine.Parse(os.Args); err != nil {
		panic(err)
	}
	h.Run(logging.DefaultSlogLogger)
}
