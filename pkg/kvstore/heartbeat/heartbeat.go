// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package heartbeat

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstore-heartbeat")

// Heartbeat periodically updates the heatbeat path through the given client,
// blocking until the context is canceled.
func Heartbeat(ctx context.Context, backend kvstore.BackendOperations) {
	log.WithField(logfields.Interval, kvstore.HeartbeatWriteInterval).Info("Starting to update heartbeat key")
	timer, timerDone := inctimer.New()
	defer timerDone()
	for {
		log.Debug("Updating heartbeat key")
		tctx, cancel := context.WithTimeout(ctx, defaults.LockLeaseTTL)
		err := backend.Update(tctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
		if err != nil {
			log.WithError(err).Warning("Unable to update heartbeat key")
		}
		cancel()

		select {
		case <-timer.After(kvstore.HeartbeatWriteInterval):
		case <-ctx.Done():
			log.Info("Stopping to update heartbeat key")
			return
		}
	}
}
