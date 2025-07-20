// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// APILimiter allows to rate limit API calls
type APILimiter struct {
	metrics MetricsAPI
	limiter *rate.Limiter
}

// MetricsAPI represents the metrics maintained by the API limiter
type MetricsAPI interface {
	ObserveRateLimit(operation string, duration time.Duration)
}

// NewAPILimiter returns a new API limiter with the specific rate limit and
// burst configuration. The MetricsAPI interface is called to allow for metrics
// accounting.
func NewAPILimiter(metrics MetricsAPI, rateLimit float64, burst int) *APILimiter {
	return &APILimiter{
		metrics: metrics,
		limiter: rate.NewLimiter(rate.Limit(rateLimit), burst),
	}
}

// Limit applies the rate limiting configuration for the given operation
func (l *APILimiter) Limit(ctx context.Context, operation string) {
	r := l.limiter.Reserve()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		l.metrics.ObserveRateLimit(operation, delay)
		// Wait for the required time. We cannot call r.limiter.Wait here, as it
		// would request a second reservation, effectively doubling the wait time.
		// Instead, the following logic is similar to what r.limiter.Wait(ctx)
		// does internally after it successfully obtained/ a reservation.
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-t.C:
			// proceed with the operation
		case <-ctx.Done():
			// cancel the reservation to allow other operations to go through
			r.Cancel()
		}
	}
}
