package aws

import (
	"math"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

// DefaultRetryer implements basic retry logic using exponential backoff for
// most services. You can implement your own custom retryer by implementing
// retryer interface.
type DefaultRetryer struct {
	NumMaxRetries    int
	MinRetryDelay    time.Duration
	MinThrottleDelay time.Duration
	MaxRetryDelay    time.Duration
	MaxThrottleDelay time.Duration
}

const (
	// DefaultRetryerMaxNumRetries sets maximum number of retries
	DefaultRetryerMaxNumRetries = 3

	// DefaultRetryerMinRetryDelay sets minimum retry delay
	DefaultRetryerMinRetryDelay = 30 * time.Millisecond

	// DefaultRetryerMinThrottleDelay sets minimum delay when throttled
	DefaultRetryerMinThrottleDelay = 500 * time.Millisecond

	// DefaultRetryerMaxRetryDelay sets maximum retry delay
	DefaultRetryerMaxRetryDelay = 300 * time.Second

	// DefaultRetryerMaxThrottleDelay sets maximum delay when throttled
	DefaultRetryerMaxThrottleDelay = 300 * time.Second
)

// MaxRetries returns the number of maximum returns the service will use to make
// an individual API
func (d DefaultRetryer) MaxRetries() int {
	return d.NumMaxRetries
}

var seededRand = rand.New(&lockedSource{src: rand.NewSource(time.Now().UnixNano())})

// NewDefaultRetryer returns a retryer initialized with default values and optionally takes function
// to override values for default retryer.
func NewDefaultRetryer(opts ...func(d *DefaultRetryer)) DefaultRetryer {
	d := DefaultRetryer{
		NumMaxRetries:    DefaultRetryerMaxNumRetries,
		MinRetryDelay:    DefaultRetryerMinRetryDelay,
		MinThrottleDelay: DefaultRetryerMinThrottleDelay,
		MaxRetryDelay:    DefaultRetryerMaxRetryDelay,
		MaxThrottleDelay: DefaultRetryerMaxThrottleDelay,
	}

	for _, opt := range opts {
		opt(&d)
	}
	return d
}

// RetryRules returns the delay duration before retrying this request again
//
// Note: RetryRules method must be a value receiver so that the
// defaultRetryer is safe.
func (d DefaultRetryer) RetryRules(r *Request) time.Duration {

	minDelay := d.MinRetryDelay
	maxDelay := d.MaxRetryDelay

	var initialDelay time.Duration
	isThrottle := r.IsErrorThrottle()
	if isThrottle {
		if delay, ok := getRetryAfterDelay(r); ok {
			initialDelay = delay
		}
		minDelay = d.MinThrottleDelay
		maxDelay = d.MaxThrottleDelay
	}

	retryCount := r.RetryCount
	var delay time.Duration

	// Logic to cap the retry count based on the minDelay provided
	actualRetryCount := int(math.Log2(float64(minDelay))) + 1
	if actualRetryCount < 63-retryCount {
		delay = time.Duration(1<<uint64(retryCount)) * getJitterDelay(minDelay)
		if delay > maxDelay {
			delay = getJitterDelay(maxDelay / 2)
		}
	} else {
		delay = getJitterDelay(maxDelay / 2)
	}
	return delay + initialDelay
}

// getJitterDelay returns a jittered delay for retry
func getJitterDelay(duration time.Duration) time.Duration {
	return time.Duration(seededRand.Int63n(int64(duration)) + int64(duration))
}

// ShouldRetry returns true if the request should be retried.
func (d DefaultRetryer) ShouldRetry(r *Request) bool {
	// If one of the other handlers already set the retry state
	// we don't want to override it based on the service's state
	if r.Retryable != nil {
		return *r.Retryable
	}

	return r.IsErrorRetryable() || r.IsErrorThrottle()
}

// This will look in the Retry-After header, RFC 7231, for how long
// it will wait before attempting another request
func getRetryAfterDelay(r *Request) (time.Duration, bool) {
	if !canUseRetryAfterHeader(r) {
		return 0, false
	}

	delayStr := r.HTTPResponse.Header.Get("Retry-After")
	if len(delayStr) == 0 {
		return 0, false
	}

	delay, err := strconv.Atoi(delayStr)
	if err != nil {
		return 0, false
	}

	return time.Duration(delay) * time.Second, true
}

// Will look at the status code to see if the retry header pertains to
// the status code.
func canUseRetryAfterHeader(r *Request) bool {
	switch r.HTTPResponse.StatusCode {
	case 429:
	case 503:
	default:
		return false
	}

	return true
}

// lockedSource is a thread-safe implementation of rand.Source
type lockedSource struct {
	lk  sync.Mutex
	src rand.Source
}

func (r *lockedSource) Int63() (n int64) {
	r.lk.Lock()
	n = r.src.Int63()
	r.lk.Unlock()
	return
}

func (r *lockedSource) Seed(seed int64) {
	r.lk.Lock()
	r.src.Seed(seed)
	r.lk.Unlock()
}
