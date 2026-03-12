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
	"github.com/cilium/cilium/pkg/option"
)

func registerDPPWatcher(jg job.Group, db *statedb.DB, table statedb.Table[*api_v2alpha1.CiliumDatapathPlugin], orchestrator endpoint.Orchestrator, registry types.Registry, logger *slog.Logger) {
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
