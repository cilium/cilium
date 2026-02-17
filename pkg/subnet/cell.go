// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the subnet watcher functionality
var Cell = cell.Module(
	"subnet",
	"Subnet watcher and management",

	cell.Config(DefaultConfig),

	cell.Provide(
		newSubnetWatcher,
	),

	cell.Invoke(
		registerSubnetWatcher,
		// Add a fence to ensure that subnet map is ready before starting endpoint regeneration.
		func(fence regeneration.Fence, sw *SubnetWatcher) {
			fence.Add("subnet-map", sw.waitForSync)
		},
	),
)

func registerSubnetWatcher(cfg *option.DaemonConfig, sw *SubnetWatcher) {
	if cfg.RoutingMode != option.RoutingModeHybrid {
		sw.logger.Debug("Routing mode is not hybrid, skipping subnet watcher")
		sw.markSynced()
		return
	}
	sw.jobGroup.Add(job.OneShot("subnet-watcher", func(ctx context.Context, health cell.Health) error {
		sw.logger.Info("Starting subnet topology dynamic config watcher")
		for {
			entry, found, w := dynamicconfig.WatchKey(sw.db.ReadTxn(), sw.dynamicConfigTable, SubnetTopologyConfigKey)
			if found {
				sw.logger.Info("Detected change in subnet-topology dynamic config")
				if err := sw.processSubnetConfigEntry(entry); err != nil {
					sw.logger.Error("Failed to process subnet-topology dynamic config", logfields.Error, err)
					health.Degraded("Failed to process subnet-topology dynamic config", err)
				} else {
					health.OK("subnet-topology dynamic config processed successfully")
				}
			}

			// Initial sync is complete.
			sw.markSynced()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-w:
				continue
			}
		}
	}))
}
