// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// RetryFunc tracks resiliency retry calls.
type RetryFunc func(ctx context.Context, retries int) (bool, error)

// Retry retries the provided call using exponential retries given an initial duration for up to max retries count.
func Retry(ctx context.Context, duration time.Duration, maxRetries int, fn RetryFunc) error {
	bo := wait.Backoff{
		Duration: duration,
		Factor:   1,
		Jitter:   0.1,
		Steps:    maxRetries,
	}

	var retries int
	f := func(ctx context.Context) (bool, error) {
		retries++
		return fn(ctx, retries)
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, f)
}
