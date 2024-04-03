// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/lock"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type metrics struct {
	MetricsValues
	numSuccess int
	numError   int
}

type mockMetrics struct {
	metrics map[string]*metrics
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		metrics: map[string]*metrics{},
	}
}

func (m *mockMetrics) ProcessedRequest(name string, v MetricsValues) {
	me, ok := m.metrics[name]
	if !ok {
		me = &metrics{}
		m.metrics[name] = me
	}

	if v.Error != nil {
		me.numError++
	} else {
		me.numSuccess++
	}

	me.WaitDuration += v.WaitDuration
	me.MaxWaitDuration = v.MaxWaitDuration
	me.MeanProcessingDuration = v.MeanProcessingDuration
	me.MeanWaitDuration = v.MeanWaitDuration
	me.EstimatedProcessingDuration = v.EstimatedProcessingDuration
	me.ParallelRequests = v.ParallelRequests
	me.Limit = v.Limit
	me.Burst = v.Burst
	me.CurrentRequestsInFlight = v.CurrentRequestsInFlight
	me.AdjustmentFactor = v.AdjustmentFactor
}

func TestNewAPILimiter(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{}, nil)

	req, err := a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req)
	req.Done()
}

func TestCancelContext(t *testing.T) {
	// Validate that error is returned when context is cancelled while
	// request is in flight
	a := NewAPILimiter("foo", APILimiterParameters{Log: true}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := a.Wait(ctx)
	require.ErrorIs(t, err, ErrWaitCancelled)
	require.Nil(t, req)
}

func TestAutoAdjust(t *testing.T) {
	// Test automatic adjustment of rate limiting parameters
	initialParallelRequests := 10
	initialRateLimit := rate.Limit(4.0)
	initialRateBurst := 2

	a := NewAPILimiter("foo", APILimiterParameters{
		AutoAdjust:                  true,
		ParallelRequests:            initialParallelRequests,
		EstimatedProcessingDuration: 10 * time.Millisecond,
		RateLimit:                   initialRateLimit,
		RateBurst:                   initialRateBurst,
	}, nil)

	req, err := a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req)

	time.Sleep(10 * time.Millisecond)
	req.Done()

	req, err = a.Wait(context.Background())
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	req.Done()

	req, err = a.Wait(context.Background())
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	req.Done()

	require.NotEqual(t, initialParallelRequests, a.parallelRequests, "Parallel requests should have been adjusted")
	require.NotEqual(t, initialRateLimit, a.limiter.Limit(), "Rate limit should have been adjusted")

	require.Equal(t, initialRateBurst, a.limiter.Burst(), "Burst should not have been adjusted")
	require.Equal(t, int64(3), a.requestsProcessed, "Expected 3 requests to be processed")
}

func TestMeanProcessingDuration(t *testing.T) {
	// Simulate several requests and calculate the mean processing duration
	// over fewer requests. Verify calculation of mean processing duration
	iterations := int64(10)
	a := NewAPILimiter("foo", APILimiterParameters{
		MeanOver:                    int(iterations) - 1,
		EstimatedProcessingDuration: 10 * time.Millisecond,
		ParallelRequests:            2,
	}, nil)

	for i := int64(0); i < iterations; i++ {
		req, err := a.Wait(context.Background())
		require.NoError(t, err)
		require.NotNil(t, req)
		go func(r LimitedRequest) {
			time.Sleep(time.Millisecond)
			r.Done()
		}(req)
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		assert.Equal(c, iterations, a.requestsProcessed)
	}, timeout, tick, "Limiter should have processed all requests")
	require.NotEqual(t, 0, a.meanProcessingDuration)
}

func TestMinParallelRequests(t *testing.T) {
	// Run a limiter with an initial 10 max parallel requests with a lower
	// limit of 2 parallel requests. Auto adjust and feed it with requests
	// that take 10ms with an estimated processing time of 1ms.
	//
	// The max parallel window should shrink to the minimum
	maxParallelReqs := 10
	minParallelReqs := 2
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: time.Nanosecond,
		AutoAdjust:                  true,
		ParallelRequests:            maxParallelReqs,
		MinParallelRequests:         minParallelReqs,
		DelayedAdjustmentFactor:     1.0,
		Log:                         true,
	}, nil)

	for i := 0; i < maxParallelReqs; i++ {
		req, err := a.Wait(context.Background())
		require.NoError(t, err)
		require.NotNil(t, req)
		go func(r LimitedRequest) {
			time.Sleep(10 * time.Millisecond)
			r.Done()
		}(req)
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		assert.Equal(c, int64(maxParallelReqs), a.requestsProcessed)
	}, timeout, tick, "Requests processed should reach maximum parallel requests")

	require.Equalf(t, minParallelReqs, a.parallelRequests, "Parallel requests window should shrink to minimum")
}

func TestMaxWaitDurationExceeded(t *testing.T) {
	// Test parallel request limiting when the maximum waiting duration is
	// exceeded. A set of requests must fail.
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: 5 * time.Millisecond,
		AutoAdjust:                  true,
		ParallelRequests:            2,
		MinParallelRequests:         2,
		MaxWaitDuration:             10 * time.Millisecond,
		Log:                         true,
	}, nil)

	var mutex lock.Mutex
	failedRequests := 0

	for i := 0; i < 10; i++ {
		go func() {
			req, err := a.Wait(context.Background())
			if err != nil {
				mutex.Lock()
				failedRequests++
				mutex.Unlock()
			} else {
				require.NotNil(t, req)
				time.Sleep(10 * time.Millisecond)
				req.Done()
			}
		}()
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mutex.Lock()
		defer mutex.Unlock()
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		assert.Equal(c, 10, int(a.requestsProcessed)+failedRequests)
	}, timeout, tick, "Expected requests to fail when exceeding max wait duration")

	require.NotEqual(t, 0, failedRequests, "Expected some requests to fail")
}

func TestLimitCancelContext(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		MinWaitDuration: time.Minute,
		RateLimit:       1.0 / 60.0, // 1 request/minute
		RateBurst:       1,
		Log:             true,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	req, err := a.Wait(ctx)
	require.ErrorIs(t, err, ErrWaitCancelled)
	require.Nil(t, req)
}

func TestLimitWaitDurationExceeded(t *testing.T) {
	// Test when rate limiting waiting duration exceeded the maximum wait
	// duration. A set of requests must fail.
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:       1.0 / 60.0, // 1 request/minute
		RateBurst:       2,
		MaxWaitDuration: time.Millisecond,
		Log:             true,
	}, nil)

	var mutex lock.Mutex
	failedRequests := 0

	for i := 0; i < 10; i++ {
		go func() {
			req, err := a.Wait(context.Background())
			if err != nil {
				require.ErrorContains(t, err, "request would have to wait")
				mutex.Lock()
				failedRequests++
				mutex.Unlock()
			} else {
				require.NotNil(t, req)
				time.Sleep(10 * time.Millisecond)
				req.Done()
			}
		}()
	}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mutex.Lock()
		defer mutex.Unlock()
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		assert.Equal(c, 10, int(a.requestsProcessed)+failedRequests)
	}, timeout, tick, "Expected requests to fail when exceeding max wait duration")

	require.NotEqual(t, 0, failedRequests, "Expected some requests to fail")
}

func TestMaxParallelRequests(t *testing.T) {
	// Test blocking of max-parallel-requests by allowing two parallel
	// requests and having a third request fail due to a very short
	// MaxWaitDuration
	a := NewAPILimiter("foo", APILimiterParameters{
		ParallelRequests: 2,
		MaxWaitDuration:  time.Millisecond,
		AutoAdjust:       true,
	}, nil)

	// Process request 1 without completing it
	req1, err := a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req1)

	// Process request 2 without completing it
	req2, err := a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req2)

	// request 3 will fail due to MaxWaitDuration=1ms
	req3, err := a.Wait(context.Background())
	require.Error(t, err, "Request should have failed due to exceeding MaxWaitDuration")
	require.Nil(t, req3)

	// Finish request 1 to unblock another attempt to process request 3
	req1.Done()

	// request 3 will succeed now
	req3, err = a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req3)

	req2.Done()
	req3.Done()
}

func TestParseRate(t *testing.T) {
	l, err := parseRate("foo")
	require.Error(t, err)
	require.Equal(t, rate.Limit(0), l)

	l, err = parseRate("1/foo")
	require.Error(t, err)
	require.Equal(t, rate.Limit(0), l)

	l, err = parseRate("/1s")
	require.Error(t, err)
	require.Equal(t, rate.Limit(0), l)

	l, err = parseRate("foo/1s")
	require.Error(t, err)
	require.Equal(t, rate.Limit(0), l)

	l, err = parseRate("1/1s")
	require.NoError(t, err)
	require.Equal(t, rate.Limit(1.0), l)

	l, err = parseRate("1/5m")
	require.NoError(t, err)
	require.Equal(t, rate.Limit(1.0/(5*60)), l)

	l, err = parseRate("10/m")
	require.NoError(t, err)
	require.Equal(t, rate.Limit(10.0/60), l)

	l, err = parseRate("1/10")
	require.Error(t, err)
	require.Equal(t, rate.Limit(0), l)
}

func TestNewAPILimiterFromConfig(t *testing.T) {
	l, err := NewAPILimiterFromConfig("foo", "foo", nil)
	require.Error(t, err)
	require.Nil(t, l)

	l, err = NewAPILimiterFromConfig("foo", "rate-limit:5/m", nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, rate.Limit(5.0/60.0), l.params.RateLimit)

	l, err = NewAPILimiterFromConfig("foo", "estimated-processing-duration:100ms", nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, time.Millisecond*100, l.params.EstimatedProcessingDuration)

	l, err = NewAPILimiterFromConfig("foo", "rate-limit:5/m,rate-burst:2", nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, rate.Limit(5.0/60.0), l.params.RateLimit)
	require.Equal(t, 2, l.params.RateBurst)

	l, err = NewAPILimiterFromConfig("foo", "auto-adjust:true,parallel-requests:2,max-parallel-requests:3,min-parallel-requests:2,skip-initial:5", nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, true, l.params.AutoAdjust)
	require.Equal(t, 2, l.params.ParallelRequests)
	require.Equal(t, 3, l.params.MaxParallelRequests)
	require.Equal(t, 2, l.params.MinParallelRequests)
	require.Equal(t, 5, l.params.SkipInitial)

	l, err = NewAPILimiterFromConfig("foo", "delayed-adjustment-factor:0.5,log:true,max-wait-duration:2s,min-wait-duration:100ms,max-adjustment-factor:50.0", nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, 0.5, l.params.DelayedAdjustmentFactor)
	require.Equal(t, true, l.params.Log)
	require.Equal(t, 2*time.Second, l.params.MaxWaitDuration)
	require.Equal(t, 100*time.Millisecond, l.params.MinWaitDuration)
	require.Equal(t, 50.0, l.params.MaxAdjustmentFactor)
}

func TestNewAPILimiterSet(t *testing.T) {
	// Empty configuration
	l, err := NewAPILimiterSet(nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, l)

	// Invalid user config
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "foo",
	}, nil, nil)
	require.Error(t, err)
	require.Nil(t, l)

	// Default value only
	l, err = NewAPILimiterSet(nil, map[string]APILimiterParameters{
		"foo": {
			RateLimit: rate.Limit(1.0 / 60.0),
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.NotNil(t, l.Limiter("foo"))
	require.Nil(t, l.Limiter("foo2"))

	// User config only
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "rate-limit:2/m,rate-burst:2",
	}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, rate.Limit(1.0/30.0), l.Limiter("foo").params.RateLimit)
	require.Equal(t, 2, l.Limiter("foo").params.RateBurst)

	// Overwrite default and combine with new user config while also
	// preserving some default values
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "rate-limit:2/m,rate-burst:2",
	}, map[string]APILimiterParameters{
		"foo": {
			RateLimit:  rate.Limit(1.0 / 60.0),
			AutoAdjust: true,
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, rate.Limit(1.0/30.0), l.Limiter("foo").params.RateLimit)
	require.Equal(t, 2, l.Limiter("foo").params.RateBurst)
	require.Equal(t, true, l.Limiter("foo").params.AutoAdjust)

	// Overwrite default with an invalid value
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "rate-limit:foo,rate-burst:2",
	}, map[string]APILimiterParameters{
		"foo": {
			RateLimit: rate.Limit(1.0 / 60.0),
		},
	}, nil)
	require.Error(t, err)
	require.Nil(t, l)
}

func TestAPILimiterMetrics(t *testing.T) {
	// Validate setting of metrics via interface
	metrics := newMockMetrics()

	l, err := NewAPILimiterSet(nil, map[string]APILimiterParameters{
		"foo": {
			EstimatedProcessingDuration: 10 * time.Millisecond,
			MaxWaitDuration:             200 * time.Millisecond,
			ParallelRequests:            2,
			RateLimit:                   rate.Limit(1.0 * 10.0),
			RateBurst:                   2,
			Log:                         true,
		},
	}, metrics)
	require.NoError(t, err)
	require.NotNil(t, l)

	req0, err := l.Wait(context.Background(), "unknown-call")
	require.NoError(t, err)
	require.NotNil(t, req0)
	req0.Done()
	require.Equal(t, time.Duration(0), req0.WaitDuration())

	req1, err := l.Wait(context.Background(), "foo")
	require.NoError(t, err)
	require.NotNil(t, req1)
	time.Sleep(5 * time.Millisecond)
	req1.Done()

	req2, err := l.Wait(context.Background(), "foo")
	require.NoError(t, err)
	require.NotNil(t, req2)
	time.Sleep(5 * time.Millisecond)
	req2.Done()

	req3, err := l.Wait(context.Background(), "foo")
	require.NoError(t, err)
	require.NotNil(t, req3)
	time.Sleep(5 * time.Millisecond)
	req3.Error(fmt.Errorf("error"))
	req3.Done()

	a := l.Limiter("foo")

	require.Equal(t, req1.WaitDuration()+req2.WaitDuration()+req3.WaitDuration(), metrics.metrics["foo"].WaitDuration)
	require.Equal(t, 2, metrics.metrics["foo"].numSuccess)
	require.Equal(t, 1, metrics.metrics["foo"].numError)
	require.Equal(t, a.params.RateLimit, metrics.metrics["foo"].Limit)
	require.Equal(t, a.params.RateBurst, metrics.metrics["foo"].Burst)
	require.Equal(t, a.params.ParallelRequests, metrics.metrics["foo"].ParallelRequests)
	require.Equal(t, a.params.EstimatedProcessingDuration.Seconds(), metrics.metrics["foo"].EstimatedProcessingDuration)
	require.Equal(t, a.meanProcessingDuration, metrics.metrics["foo"].MeanProcessingDuration)
	require.Equal(t, a.meanWaitDuration, metrics.metrics["foo"].MeanWaitDuration)
	require.Equal(t, a.adjustmentFactor, metrics.metrics["foo"].AdjustmentFactor)
}

func TestAPILimiterMergeUserConfig(t *testing.T) {
	// Merge empty configuration into empty configuration. Nothing should change
	o := APILimiterParameters{}
	n, err := o.MergeUserConfig("")
	require.NoError(t, err)
	require.EqualValues(t, o, n, "Expected no changes when merging empty configs")

	// Overwrite defaults with user configuration, check updated values
	o = APILimiterParameters{
		AutoAdjust:          false,
		MaxParallelRequests: 4,
	}

	n, err = o.MergeUserConfig("auto-adjust:true,max-parallel-requests:3,min-parallel-requests:2")
	require.NoError(t, err)

	// these values should be the same
	expectSame := "Value should not have changed"
	expectedChange := "Value should have been overwritten"
	require.Equal(t, o.EstimatedProcessingDuration, n.EstimatedProcessingDuration, expectSame)
	require.Equal(t, o.MeanOver, n.MeanOver, expectSame)
	require.Equal(t, o.RateLimit, n.RateLimit, expectSame)
	require.Equal(t, o.RateBurst, n.RateBurst, expectSame)
	require.Equal(t, o.MaxWaitDuration, n.MaxWaitDuration, expectSame)
	require.Equal(t, o.Log, n.Log, expectSame)

	// these values should be updated
	require.Equal(t, true, n.AutoAdjust, expectedChange)
	require.Equal(t, 3, n.MaxParallelRequests, expectedChange)
	require.Equal(t, 2, n.MinParallelRequests, expectedChange)

	// Merge invalid configuration, must fail
	_, err = o.MergeUserConfig("foo")
	require.Error(t, err)
}

func TestParseUserConfigKeyValue(t *testing.T) {
	p := &APILimiterParameters{}

	tests := []struct {
		key      string
		value    string
		expected assert.ErrorAssertionFunc
	}{
		{"", "", assert.Error},
		{"foo", "", assert.Error},
		{"rate-limit", "10", assert.Error},
		{"rate-limit", "10/m", assert.NoError},
		{"rate-burst", "foo", assert.Error},
		{"rate-burst", "10", assert.NoError},
		{"max-wait-duration", "100sm", assert.Error},
		{"max-wait-duration", "100ms", assert.NoError},
		{"min-wait-duration", "100sm", assert.Error},
		{"min-wait-duration", "100ms", assert.NoError},
		{"estimated-processing-duration", "100sm", assert.Error},
		{"estimated-processing-duration", "100ms", assert.NoError},
		{"auto-adjust", "not-true", assert.Error},
		{"auto-adjust", "true", assert.NoError},
		{"auto-adjust", "false", assert.NoError},
		{"max-parallel-requests", "ss", assert.Error},
		{"max-parallel-requests", "10", assert.NoError},
		{"parallel-requests", "ss", assert.Error},
		{"parallel-requests", "10", assert.NoError},
		{"min-parallel-requests", "ss", assert.Error},
		{"min-parallel-requests", "10", assert.NoError},
		{"mean-over", "foo", assert.Error},
		{"mean-over", "10", assert.NoError},
		{"log", "not-true", assert.Error},
		{"log", "true", assert.NoError},
		{"log", "false", assert.NoError},
		{"delayed-adjustment-factor", "0.25", assert.NoError},
		{"delayed-adjustment-factor", "foo", assert.Error},
		{"max-adjustment-factor", "0.25", assert.NoError},
		{"max-adjustment-factor", "foo", assert.Error},
		{"skip-initial", "2", assert.NoError},
		{"skip-initial", "foo", assert.Error},
	}

	for _, test := range tests {
		test.expected(t, p.mergeUserConfigKeyValue(test.key, test.value))
	}
}

func TestParseUserConfig(t *testing.T) {
	p := &APILimiterParameters{}

	require.NoError(t, p.mergeUserConfig("auto-adjust:true,"))
	require.Equal(t, true, p.AutoAdjust)
	require.NoError(t, p.mergeUserConfig("auto-adjust:false,rate-limit:10/s,"))
	require.Equal(t, false, p.AutoAdjust)
	require.Equal(t, rate.Limit(10.0), p.RateLimit)
	require.Error(t, p.mergeUserConfig("auto-adjust"))
	require.Error(t, p.mergeUserConfig("1:2:3"))
}

func TestCalcMeanDuration(t *testing.T) {
	require.Equal(t, time.Duration(10).Seconds(), calcMeanDuration([]time.Duration{10, 10, 10, 10}))
	require.Equal(t, time.Duration(2).Seconds(), calcMeanDuration([]time.Duration{1, 2, 3}))
}

func TestDelayedAdjustment(t *testing.T) {
	l := APILimiter{
		adjustmentFactor: 1.5,
		params:           APILimiterParameters{DelayedAdjustmentFactor: 0.5},
	}
	require.Equal(t, 1.25, l.delayedAdjustment(1.0, 0.0, 0.0))
	require.Equal(t, 2.0, l.delayedAdjustment(1.0, 2.0, 0.0))
	require.Equal(t, 1.1, l.delayedAdjustment(1.0, 0.0, 1.1))
}

func TestSkipInitial(t *testing.T) {
	// Validate that SkipInitial skips all waiting duration
	iterations := 10
	a := NewAPILimiter("foo", APILimiterParameters{
		SkipInitial:      iterations,
		RateLimit:        1.0,
		ParallelRequests: 2,
	}, nil)

	for i := 0; i < iterations; i++ {
		req, err := a.Wait(context.Background())
		require.NoError(t, err)
		require.NotNil(t, req)
		go func(r LimitedRequest) {
			time.Sleep(20 * time.Millisecond)
			r.Done()
		}(req)
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		assert.Equal(c, int64(iterations), a.requestsProcessed)
	}, timeout, tick, "All requests should have been processed")

	require.Equal(t, 0.0, a.meanWaitDuration, "All requests should have skipped waiting duration")
}

func TestCalculateAdjustmentFactor(t *testing.T) {
	estimatedProcessingDuration := time.Second
	maxAdjustmentFactor := 20.0
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: estimatedProcessingDuration,
		MaxAdjustmentFactor:         maxAdjustmentFactor,
	}, nil)

	a.meanProcessingDuration = estimatedProcessingDuration.Seconds()
	require.Equal(t, 1.0, a.calculateAdjustmentFactor())

	a.meanProcessingDuration = estimatedProcessingDuration.Seconds() / 2
	require.Equal(t, 2.0, a.calculateAdjustmentFactor())

	a.meanProcessingDuration = (time.Second * 1000).Seconds()
	require.Equal(t, 1.0/maxAdjustmentFactor, a.calculateAdjustmentFactor())

	a.meanProcessingDuration = (time.Second / 1000).Seconds()
	require.Equal(t, 1.0*maxAdjustmentFactor, a.calculateAdjustmentFactor())
}

func TestAdjustmentLimit(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{MaxAdjustmentFactor: 2.0}, nil)
	require.Equal(t, 4.0, a.adjustmentLimit(10.0, 2.0))
	require.Equal(t, 1.5, a.adjustmentLimit(1.5, 2.0))
	require.Equal(t, 1.0, a.adjustmentLimit(0.9, 2.0))
}

func TestAdjustedBurst(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:               1.0,
		RateBurst:               1,
		DelayedAdjustmentFactor: 0.5,
		MaxAdjustmentFactor:     2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	require.Equal(t, 2, a.adjustedBurst())
}

func TestAdjustedLimit(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:           1.0,
		MaxAdjustmentFactor: 2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	require.Equal(t, rate.Limit(2.0), a.adjustedLimit())
	a.adjustmentFactor = 0.25
	require.Equal(t, rate.Limit(0.5), a.adjustedLimit())
	a.adjustmentFactor = 1.0
	require.Equal(t, rate.Limit(1.0), a.adjustedLimit())
}

func TestAdjustedParallelRequests(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		ParallelRequests:        2,
		DelayedAdjustmentFactor: 0.5,
		MaxAdjustmentFactor:     2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	require.Equal(t, 4, a.adjustedParallelRequests())
	a.adjustmentFactor = 0.25
	require.Equal(t, 1, a.adjustedParallelRequests())
	a.adjustmentFactor = 1.0
	require.Equal(t, 2, a.adjustedParallelRequests())
}

func testStressRateLimiter(t *testing.T, nGoRoutines int) {
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: 5 * time.Millisecond,
		RateLimit:                   1000.0,
		ParallelRequests:            50,
		RateBurst:                   1,
		MaxWaitDuration:             10 * time.Millisecond,
		AutoAdjust:                  true,
	}, nil)

	var (
		sem                = semaphore.NewWeighted(100)
		completed, retries atomic.Uint32
	)

	go func() {
		for i := 0; i < nGoRoutines; i++ {
			sem.Acquire(context.Background(), 1)
			go func() {
				var (
					err error
					req LimitedRequest
				)
				for req == nil {
					req, err = a.Wait(context.Background())
					if err == nil {
						time.Sleep(5 * time.Millisecond)
						req.Done()
						completed.Add(1)
						sem.Release(1)
						return
					}
					retries.Add(1)
				}
			}()
		}
	}()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, uint32(nGoRoutines), completed.Load())
	}, timeout, tick, "Expected all requests to complete")

	log.Infof("%+v", a)
	log.Infof("Total retries: %v", retries.Load())
}

func TestReservationCancel(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:           50.0,
		RateBurst:           10,
		ParallelRequests:    1,
		MaxParallelRequests: 1,
		MaxWaitDuration:     500 * time.Millisecond,
		Log:                 true,
	}, nil)

	// Process a request but don't complete it, this will occupy the
	// parallel request slot
	req, err := a.Wait(context.Background())
	require.NoError(t, err)
	require.NotNil(t, req)

	var completed atomic.Uint32

	// All of these requests must fail due to having to wait too long as
	// the only parallel request slot is occupied. The rate limiter should
	// not get occupied with these requests though.
	for i := 0; i < 20; i++ {
		go func() {
			_, err := a.Wait(context.Background())
			require.Error(t, err)
			completed.Add(1)
		}()
	}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, uint32(20), completed.Load())
	}, timeout, tick, "Expected all requests to fail")

	req.Done()

	// All of these requests should now succeed
	for i := 0; i < 10; i++ {
		req2, err := a.Wait(context.Background())
		require.NoError(t, err)
		req2.Done()
	}
}

func TestSetRateLimit(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit: 50.0,
	}, nil)
	require.Equal(t, rate.Limit(50.0), a.limiter.Limit())

	a.SetRateLimit(100.0)
	require.Equal(t, rate.Limit(100.0), a.limiter.Limit())
}

func TestSetRateBurst(t *testing.T) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit: 50.0,
		RateBurst: 50,
	}, nil)
	require.Equal(t, 50, a.limiter.Burst())

	a.SetRateBurst(100)
	require.Equal(t, 100, a.limiter.Burst())
}
