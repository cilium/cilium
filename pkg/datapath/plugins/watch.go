// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/plugins/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

func registerDPPWatcher(jg job.Group, db *statedb.DB, table statedb.Table[*api_v2alpha1.CiliumDatapathPlugin], orchestrator datapath.Orchestrator, registry types.Registry, synced syncChan, logger *slog.Logger) {
	if !registry.IsEnabled() {
		return
	}

	jg.Add(job.OneShot(
		"follow",
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
				for change, _ := range changes {
					e := change.Object

					if change.Deleted {
						logger.Info("Datapath plugin deleted", logfields.Name, e.Name)

						registry.Unregister(e)
					} else {
						logger.Info("Datapath plugin updated",
							logfields.Name, e.Name,
							logfields.Object, e,
						)

						registry.Register(e)
					}
				}

				initialized, _ := table.Initialized(db.ReadTxn())
				if initialized {
					if synced != nil {
						close(synced)
						synced = nil
					}
					logger.Info("Reinitialize datapath")
					if err := orchestrator.Reinitialize(ctx); err != nil {
						logger.Error("Failed to reinitialize datapath", logfields.Error, err)
					}
				}

				logger.Info("JORDAN wait")
				// Wait until there's new changes to consume.
				select {
				case <-ctx.Done():
					logger.Info("JORDAN nil exit")
					return nil
				case <-watch:
				}
				logger.Info("JORDAN wakeup")
			}
		},
	))
}
