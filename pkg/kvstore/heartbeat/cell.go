// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type Config struct {
	EnableHeartBeat bool
}

// Cell creates a cell responsible for periodically updating the heartbeat key
// in the kvstore.
var Cell = cell.Module(
	"kvstore-heartbeat-updater",
	"KVStore Heartbeat Updater",

	cell.Invoke(func(config Config, logger *slog.Logger, jg job.Group, client kvstore.Client) {
		if !client.IsEnabled() || !config.EnableHeartBeat {
			return
		}

		jg.Add(job.Timer("kvstore-heartbeat", func(ctx context.Context) error {
			tctx, cancel := context.WithTimeout(ctx, defaults.LockLeaseTTL)
			defer cancel()

			err := client.Update(tctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
			if err != nil {
				logger.Warn("Unable to update heartbeat key", logfields.Error, err)
				return fmt.Errorf("unable to update heartbeat key: %w", err)
			}

			return nil
		}, kvstore.HeartbeatWriteInterval))
	}),
)

// Enabled unconditionally enables the heartbeat updater logic.
var Enabled = cell.Provide(func() Config {
	return Config{
		EnableHeartBeat: true,
	}
})
