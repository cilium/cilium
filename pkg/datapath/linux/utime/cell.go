// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/time"
)

const (
	syncControllerName     = "sync-utime"
	syncControllerInterval = 1 * time.Minute
)

var syncControllerGroupName = controller.NewGroup("sync-utime")

// Cell initializes and manages the utime offset synchronization.
var Cell = cell.Module(
	"utime",
	"Synchronizes utime offset between userspace and datapath",

	cell.Invoke(initUtimeSync),
)

func initUtimeSync(lifecycle cell.Lifecycle, configMap configmap.Map) {
	controllerManager := controller.NewManager()

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			ctrl := &utimeController{configMap: configMap}

			// Add controller for keeping clock in sync for NTP time jumps and any difference
			// between monotonic and boottime clocks.
			controllerManager.UpdateController(syncControllerName,
				controller.ControllerParams{
					Group: syncControllerGroupName,
					DoFunc: func(ctx context.Context) error {
						return ctrl.sync()
					},
					RunInterval: syncControllerInterval,
				},
			)
			return nil
		},
		OnStop: func(stopCtx cell.HookContext) error {
			if err := controllerManager.RemoveController(syncControllerName); err != nil {
				return fmt.Errorf("failed to remove controller: %w", err)
			}
			return nil
		},
	})
}
