// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// awaitEndpointPolicyRestoration waits for the endpoint restorer, and then for
// the restored endpoints to have computed their initial policy, so that the
// first resources served to Envoy are a complete state of the world.
//
// Serving early is not a lesser evil. At that point the cilium-http listeners do
// not exist yet, because endpoint regeneration creates them when it builds the
// proxy redirect, and no endpoint has a network policy. A cilium-envoy that
// survived the agent restart is still serving traffic with the configuration it
// already has, and it applies whatever it is sent as authoritative, so an early
// snapshot makes it drop the listeners and every policy it was using.
//
// reportInterval therefore bounds how often this reports that it is still
// waiting, not how long it is prepared to wait. It returns an error only when
// the caller should stop, that is when its context was cancelled.
func awaitEndpointPolicyRestoration(ctx context.Context, health cell.Health, logger *slog.Logger,
	restorerPromise promise.Promise[endpointstate.Restorer], reportInterval time.Duration,
) error {
	if restorerPromise == nil {
		return nil
	}

	logger.Info("Envoy: Waiting for endpoint restorer before serving xDS resources...")

	restorer, err := awaitWithReports(ctx, health, logger, reportInterval,
		func(ctx context.Context) (endpointstate.Restorer, error) {
			return restorerPromise.Await(ctx)
		})
	if err != nil {
		return err
	}
	if restorer == nil {
		return nil
	}

	logger.Info("Envoy: Waiting for endpoint restoration before serving xDS resources...")

	_, err = awaitWithReports(ctx, health, logger, reportInterval,
		func(ctx context.Context) (struct{}, error) {
			return struct{}{}, restorer.WaitForInitialPolicy(ctx)
		})
	return err
}

// awaitWithReports calls await with a deadline of reportInterval, and on expiry
// reports that it is still waiting and calls it again. It only returns when
// await succeeds or ctx is done.
func awaitWithReports[T any](ctx context.Context, health cell.Health, logger *slog.Logger,
	reportInterval time.Duration, await func(context.Context) (T, error),
) (T, error) {
	var zero T

	for waited := time.Duration(0); ; waited += reportInterval {
		attemptCtx, cancel := context.WithTimeout(ctx, reportInterval)
		started := time.Now()
		res, err := await(attemptCtx)
		cancel()

		if !errors.Is(err, context.DeadlineExceeded) {
			if err != nil {
				return zero, err
			}
			return res, nil
		}

		// The parent context being done is reported as DeadlineExceeded by the
		// child, so distinguish the two before deciding to keep waiting.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return zero, ctxErr
		}

		// An implementation that reports the deadline without having waited for
		// it would otherwise spin here.
		if remaining := reportInterval - time.Since(started); remaining > 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(remaining):
			}
		}

		reason := "Envoy: Endpoint policy restoration has not completed yet, still waiting before serving resources to Envoy"
		logger.Warn(reason, logfields.Duration, waited+reportInterval)
		health.Degraded(reason, err)
	}
}
