// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, "kvstore-heartbeat"))

// Heartbeat periodically updates the heatbeat path through the given client,
// blocking until the context is canceled.
func Heartbeat(ctx context.Context, backend kvstore.BackendOperations) {
	log.Info("Starting to update heartbeat key", slog.Any(logfields.Interval, kvstore.HeartbeatWriteInterval))
	for {
		log.Debug("Updating heartbeat key")
		tctx, cancel := context.WithTimeout(ctx, defaults.LockLeaseTTL)
		err := backend.Update(tctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
		if err != nil {
			log.Warn("Unable to update heartbeat key", slog.Any(logfields.Error, err))
		}
		cancel()

		select {
		case <-time.After(kvstore.HeartbeatWriteInterval):
		case <-ctx.Done():
			log.Info("Stopping to update heartbeat key")
			return
		}
	}
}
