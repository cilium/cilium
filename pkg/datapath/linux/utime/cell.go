// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/configmap"
)

const (
	syncControllerName     = "sync-utime"
	syncControllerInterval = 1 * time.Minute
)

// Cell initializes and manages the utime offset synchronization.
var Cell = cell.Module(
	"utime",
	"Synchronizes utime offset between userspace and datapath",

	cell.Invoke(initUtimeSync),
)

func initUtimeSync(lifecycle hive.Lifecycle, configMap configmap.Map) {
	controllerManager := controller.NewManager()

	lifecycle.Append(hive.Hook{
		OnStart: func(startCtx hive.HookContext) error {
			ctrl := &utimeController{configMap: configMap}

			// Add controller for keeping clock in sync for NTP time jumps and any difference
			// between monotonic and boottime clocks.
			controllerManager.UpdateController(syncControllerName,
				controller.ControllerParams{
					DoFunc: func(ctx context.Context) error {
						return ctrl.sync()
					},
					RunInterval: syncControllerInterval,
				},
			)
			return nil
		},
		OnStop: func(stopCtx hive.HookContext) error {
			if err := controllerManager.RemoveController(syncControllerName); err != nil {
				return fmt.Errorf("failed to remove controller: %w", err)
			}
			return nil
		},
	})
}
