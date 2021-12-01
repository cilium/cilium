// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package logging

import (
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a wrapper around rate.Limiter that does not panic when
// the limiter is uninitialized. The wrapping also allows more logging
// specific functionality to be added later without changing all the call
// sites.
type Limiter struct {
	bucket *rate.Limiter
}

// NewLimiter returns a new Limiter allowing log messages to be
// emitted on average once every 'interval' and upto 'burst' messages
// during any 'interval'.
func NewLimiter(interval time.Duration, burst int) Limiter {
	return Limiter{
		bucket: rate.NewLimiter(rate.Every(interval), burst),
	}
}

// Allow returns true if the log message is allowed under the
// configured rate limit.
func (ll Limiter) Allow() bool {
	if ll.bucket == nil {
		return true // limiter not initialized => no limit
	}
	return ll.bucket.Allow()
}
