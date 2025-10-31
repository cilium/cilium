// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/time"
)

// Cell initializes and manages the utime offset synchronization.
var Cell = cell.Module(
	"utime",
	"Synchronizes utime offset between userspace and datapath",

	cell.Invoke(initUtimeSync),
)

func initUtimeSync(jobGroup job.Group, configMap configmap.Map, logger *slog.Logger) {
	utimeCtrl := &utimeController{logger: logger, configMap: configMap}

	// use trigger to enforce first execution immediately when the timer job starts
	tr := job.NewTrigger()
	tr.Trigger()

	// Add timer job for keeping clock in sync for NTP time jumps and any difference
	// between monotonic and boottime clocks.
	jobGroup.Add(job.Timer("sync-userspace-and-datapath", utimeCtrl.sync, 1*time.Minute, job.WithTrigger(tr)))
}
