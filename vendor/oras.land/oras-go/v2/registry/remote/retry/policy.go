/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package retry

import (
	"hash/maphash"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// headerRetryAfter is the header key for Retry-After.
const headerRetryAfter = "Retry-After"

// DefaultPolicy is a policy with fine-tuned retry parameters.
// It uses an exponential backoff with jitter.
var DefaultPolicy Policy = &GenericPolicy{
	Retryable: DefaultPredicate,
	Backoff:   DefaultBackoff,
	MinWait:   200 * time.Millisecond,
	MaxWait:   3 * time.Second,
	MaxRetry:  5,
}

// DefaultPredicate is a predicate that retries on 5xx errors, 429 Too Many
// Requests, 408 Request Timeout and on network dial timeout.
var DefaultPredicate Predicate = func(resp *http.Response, err error) (bool, error) {
	if err != nil {
		// retry on Dial timeout
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return true, nil
		}
		return false, err
	}

	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests {
		return true, nil
	}

	if resp.StatusCode == 0 || resp.StatusCode >= 500 {
		return true, nil
	}

	return false, nil
}

// DefaultBackoff is a backoff that uses an exponential backoff with jitter.
// It uses a base of 250ms, a factor of 2 and a jitter of 10%.
var DefaultBackoff Backoff = ExponentialBackoff(250*time.Millisecond, 2, 0.1)

// Policy is a retry policy.
type Policy interface {
	// Retry returns the duration to wait before retrying the request.
	// It returns a negative value if the request should not be retried.
	// The attempt is used to:
	//  - calculate the backoff duration, the default backoff is an exponential backoff.
	//  - determine if the request should be retried.
	// The attempt starts at 0 and should be less than MaxRetry for the request to
	// be retried.
	Retry(attempt int, resp *http.Response, err error) (time.Duration, error)
}

// Predicate is a function that returns true if the request should be retried.
type Predicate func(resp *http.Response, err error) (bool, error)

// Backoff is a function that returns the duration to wait before retrying the
// request. The attempt, is the next attempt number. The response is the
// response from the previous request.
type Backoff func(attempt int, resp *http.Response) time.Duration

// ExponentialBackoff returns a Backoff that uses an exponential backoff with
// jitter. The backoff is calculated as:
//
//	temp = backoff * factor ^ attempt
//	interval = temp * (1 - jitter) + rand.Int64N(2 * jitter * temp)
//
// The HTTP response is checked for a Retry-After header. If it is present, the
// value is used as the backoff duration.
func ExponentialBackoff(backoff time.Duration, factor, jitter float64) Backoff {
	return func(attempt int, resp *http.Response) time.Duration {
		var h maphash.Hash
		h.SetSeed(maphash.MakeSeed())
		rand := rand.New(rand.NewPCG(0, h.Sum64()))

		// check Retry-After
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			if v := resp.Header.Get(headerRetryAfter); v != "" {
				if retryAfter, _ := strconv.ParseInt(v, 10, 64); retryAfter > 0 {
					return time.Duration(retryAfter) * time.Second
				}
			}
		}

		// do exponential backoff with jitter
		temp := float64(backoff) * math.Pow(factor, float64(attempt))
		return time.Duration(temp*(1-jitter)) + time.Duration(rand.Int64N(int64(2*jitter*temp)))
	}
}

// GenericPolicy is a generic retry policy.
type GenericPolicy struct {
	// Retryable is a predicate that returns true if the request should be
	// retried.
	Retryable Predicate

	// Backoff is a function that returns the duration to wait before retrying.
	Backoff Backoff

	// MinWait is the minimum duration to wait before retrying.
	MinWait time.Duration

	// MaxWait is the maximum duration to wait before retrying.
	MaxWait time.Duration

	// MaxRetry is the maximum number of retries.
	MaxRetry int
}

// Retry returns the duration to wait before retrying the request.
// It returns -1 if the request should not be retried.
func (p *GenericPolicy) Retry(attempt int, resp *http.Response, err error) (time.Duration, error) {
	if attempt >= p.MaxRetry {
		return -1, nil
	}
	if ok, err := p.Retryable(resp, err); err != nil {
		return -1, err
	} else if !ok {
		return -1, nil
	}
	backoff := p.Backoff(attempt, resp)
	if backoff < p.MinWait {
		backoff = p.MinWait
	}
	if backoff > p.MaxWait {
		backoff = p.MaxWait
	}
	return backoff, nil
}
