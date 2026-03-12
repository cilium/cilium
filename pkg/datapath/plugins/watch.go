// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/plugins/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func registerDPPWatcher(jg job.Group, db *statedb.DB, table statedb.Table[*api_v2alpha1.CiliumDatapathPlugin], orchestrator endpoint.Orchestrator, registry types.Registry, synced syncChan, logger *slog.Logger) {
	if !option.Config.EnableDatapathPlugins {
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

			// Wait until the statedb table is at least as up to
			// date as the initial state of the k8s API server.
			// We want to make sure that the registry is fully
			// up to date before letting datapath (re)initialization
			// happen; otherwise, it's possible for Cilium to
			// program the datapath using some intermediate
			// configuration that's not intended resulting in
			// temporary removal of plugin programs, etc.
			_, init := table.Initialized(db.ReadTxn())
			select {
			case <-init:
			case <-ctx.Done():
				return ctx.Err()
			}

			for {
				logger.Info("Process changes to CiliumDatapathPlugin table")
				changes, watch := changeIterator.Next(db.ReadTxn())
				for change := range changes {
					e := change.Object

					if change.Deleted {
						registry.Unregister(e)
					} else {
						registry.Register(e)
					}
				}

				// Signal to the registry that it has been fully
				// initialized.
				if synced != nil {
					close(synced)
					synced = nil
				}

				logger.Info("Reinitialize datapath")
				if err := orchestrator.Reinitialize(ctx); err != nil {
					logger.Error("Failed to reinitialize datapath", logfields.Error, err)
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
