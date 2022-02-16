// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// ApiLimiter allows to rate limit API calls
type ApiLimiter struct {
	metrics MetricsAPI
	limiter *rate.Limiter
}

// MetricsAPI represents the metrics maintained by the API limiter
type MetricsAPI interface {
	ObserveRateLimit(operation string, duration time.Duration)
}

// NewApiLimiter returns a new API limiter with the specific rate limit and
// burst configuration. The MetricsAPI interface is called to allow for metrics
// accounting.
func NewApiLimiter(metrics MetricsAPI, rateLimit float64, burst int) *ApiLimiter {
	return &ApiLimiter{
		metrics: metrics,
		limiter: rate.NewLimiter(rate.Limit(rateLimit), burst),
	}
}

// Limit applies the rate limiting configuration for the given operation
func (l *ApiLimiter) Limit(ctx context.Context, operation string) {
	r := l.limiter.Reserve()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		l.metrics.ObserveRateLimit(operation, delay)
		l.limiter.Wait(ctx)
	}
}
