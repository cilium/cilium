// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
