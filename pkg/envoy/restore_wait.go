// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// awaitEndpointPolicyRestoration waits for the endpoint restorer, and then for
// the restored endpoints to have computed their initial policy, bounded by
// timeout. It returns an error only when the caller should stop, that is when
// its context was cancelled.
func awaitEndpointPolicyRestoration(ctx context.Context, logger *slog.Logger,
	restorerPromise promise.Promise[endpointstate.Restorer], timeout time.Duration,
) error {
	if restorerPromise == nil {
		return nil
	}

	restoreCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logger.Info("Envoy: Waiting for endpoint restorer before serving xDS resources...")

	restorer, err := restorerPromise.Await(restoreCtx)
	if err == nil && restorer != nil {
		logger.Info("Envoy: Waiting for endpoint restoration before serving xDS resources...")
		err = restorer.WaitForInitialPolicy(restoreCtx)
	}

	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("Envoy: Endpoint policy restoration took longer than configured restore timeout, starting serving resources to Envoy",
			logfields.Duration, timeout,
		)
	}

	return nil
}
