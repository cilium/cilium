// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// Heartbeat periodically updates the heatbeat path through the given client,
// blocking until the context is canceled.
func Heartbeat(ctx context.Context, logger *slog.Logger, backend kvstore.BackendOperations) {
	logger.Info("Starting to update heartbeat key", logfields.Interval, kvstore.HeartbeatWriteInterval)
	for {
		logger.Debug("Updating heartbeat key")
		tctx, cancel := context.WithTimeout(ctx, defaults.LockLeaseTTL)
		err := backend.Update(tctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
		if err != nil {
			logger.Warn("Unable to update heartbeat key", logfields.Error, err)
		}
		cancel()

		select {
		case <-time.After(kvstore.HeartbeatWriteInterval):
		case <-ctx.Done():
			logger.Info("Stopping to update heartbeat key")
			return
		}
	}
}
