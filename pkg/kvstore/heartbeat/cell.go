// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/kvstore"
)

type Config struct {
	EnableHeartBeat bool
}

// Cell creates a cell responsible for periodically updating the heartbeat key
// in the kvstore.
var Cell = cell.Module(
	"kvstore-heartbeat-updater",
	"KVStore Heartbeat Updater",

	cell.Invoke(func(config Config, logger *slog.Logger, lc cell.Lifecycle, backend kvstore.Client) {
		if !backend.IsEnabled() || !config.EnableHeartBeat {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup

		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				wg.Add(1)
				go func() {
					defer wg.Done()

					Heartbeat(ctx, logger, backend)
				}()
				return nil
			},

			OnStop: func(ctx cell.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})
	}),
)
