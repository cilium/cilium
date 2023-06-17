// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rate

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	check "github.com/cilium/checkmate"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
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

func (b *ControllerSuite) TestNewAPILimiter(c *check.C) {
	a := NewAPILimiter("foo", APILimiterParameters{}, nil)

	req, err := a.Wait(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(req, check.Not(check.IsNil))
	req.Done()
}

func (b *ControllerSuite) TestCancelContext(c *check.C) {
	// Validate that error is returned when context is cancelled while
	// request is in flight
	a := NewAPILimiter("foo", APILimiterParameters{Log: true}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := a.Wait(ctx)
	c.Assert(err, check.ErrorMatches, "request cancelled while waiting for rate limiting slot.*")
	c.Assert(req, check.IsNil)
}

func (b *ControllerSuite) TestAutoAdjust(c *check.C) {
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
	c.Assert(err, check.IsNil)
	c.Assert(req, check.Not(check.IsNil))

	time.Sleep(10 * time.Millisecond)
	req.Done()

	req, err = a.Wait(context.Background())
	c.Assert(err, check.IsNil)
	time.Sleep(10 * time.Millisecond)
	req.Done()

	req, err = a.Wait(context.Background())
	c.Assert(err, check.IsNil)
	time.Sleep(10 * time.Millisecond)
	req.Done()

	c.Assert(a.parallelRequests, check.Not(check.Equals), initialParallelRequests)
	c.Assert(a.limiter.Limit(), check.Not(check.Equals), initialRateLimit)
	// burst should not adjust this quickly
	c.Assert(a.limiter.Burst(), check.Equals, initialRateBurst)
	c.Assert(a.requestsProcessed, check.Equals, int64(3))
}

func (b *ControllerSuite) TestMeanProcessingDuration(c *check.C) {
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
		c.Assert(err, check.IsNil)
		c.Assert(req, check.Not(check.IsNil))
		go func(r LimitedRequest) {
			time.Sleep(time.Millisecond)
			r.Done()
		}(req)
	}

	c.Assert(testutils.WaitUntil(func() bool {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		return a.requestsProcessed == iterations
	}, 5*time.Second), check.IsNil)

	c.Assert(a.requestsProcessed, check.Equals, iterations)
	c.Assert(a.meanProcessingDuration, check.Not(check.Equals), 0)
}

func (b *ControllerSuite) TestMinParallelRequests(c *check.C) {
	// Run a limiter with an initial 10 max parallel requests with a lower
	// limit of 2 parallel requests. Auto adjust and feed it with requests
	// that take 10ms with an estimated processing time of 1ms.
	//
	// The max parallel window should shrink to the minimum
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: time.Nanosecond,
		AutoAdjust:                  true,
		ParallelRequests:            10,
		MinParallelRequests:         2,
		DelayedAdjustmentFactor:     1.0,
		Log:                         true,
	}, nil)

	for i := 0; i < 10; i++ {
		req, err := a.Wait(context.Background())
		c.Assert(err, check.IsNil)
		c.Assert(req, check.Not(check.IsNil))
		go func(r LimitedRequest) {
			time.Sleep(10 * time.Millisecond)
			r.Done()
		}(req)
	}

	c.Assert(testutils.WaitUntil(func() bool {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		return a.requestsProcessed == 10
	}, 5*time.Second), check.IsNil)

	c.Assert(a.requestsProcessed, check.Equals, int64(10))
	c.Assert(a.parallelRequests, check.Equals, 2)
}

func (b *ControllerSuite) TestMaxWaitDurationExceeded(c *check.C) {
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
				c.Assert(req, check.Not(check.IsNil))
				time.Sleep(10 * time.Millisecond)
				req.Done()
			}
		}()
	}

	c.Assert(testutils.WaitUntil(func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		return (int(a.requestsProcessed) + failedRequests) == 10
	}, 5*time.Second), check.IsNil)

	c.Assert(int(a.requestsProcessed)+failedRequests, check.Equals, 10)
	c.Assert(failedRequests, check.Not(check.Equals), 0)
}

func (b *ControllerSuite) TestLimitCancelContext(c *check.C) {
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
	c.Assert(err, check.ErrorMatches, "request cancelled while waiting for rate limiting slot.*")
	c.Assert(req, check.IsNil)
}

func (b *ControllerSuite) TestLimitWaitDurationExceeded(c *check.C) {
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
				c.Assert(err, check.ErrorMatches, "request would have to wait.*")
				mutex.Lock()
				failedRequests++
				mutex.Unlock()
			} else {
				c.Assert(req, check.Not(check.IsNil))
				time.Sleep(10 * time.Millisecond)
				req.Done()
			}
		}()
	}

	c.Assert(testutils.WaitUntil(func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		return (int(a.requestsProcessed) + failedRequests) == 10
	}, 5*time.Second), check.IsNil)

	c.Assert(int(a.requestsProcessed)+failedRequests, check.Equals, 10)
	c.Assert(failedRequests, check.Not(check.Equals), 0)
}

func (b *ControllerSuite) TestMaxParallelRequests(c *check.C) {
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
	c.Assert(err, check.IsNil)
	c.Assert(req1, check.Not(check.IsNil))

	// Process request 2 without completing it
	req2, err := a.Wait(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(req2, check.Not(check.IsNil))

	// request 3 will fail due to MaxWaitDuration=1ms
	req3, err := a.Wait(context.Background())
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(req3, check.IsNil)

	// Finish request 1 to unblock another attempt to process request 3
	req1.Done()

	// request 3 will succeed now
	req3, err = a.Wait(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(req3, check.Not(check.IsNil))

	req2.Done()
	req3.Done()
}

func (b *ControllerSuite) TestParseRate(c *check.C) {
	l, err := parseRate("foo")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.Equals, rate.Limit(0))

	l, err = parseRate("1/foo")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.Equals, rate.Limit(0))

	l, err = parseRate("/1s")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.Equals, rate.Limit(0))

	l, err = parseRate("foo/1s")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.Equals, rate.Limit(0))

	l, err = parseRate("1/1s")
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Equals, rate.Limit(1.0))

	l, err = parseRate("1/5m")
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Equals, rate.Limit(1.0/(5*60)))

	l, err = parseRate("10/m")
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Equals, rate.Limit(10.0/60))

	l, err = parseRate("1/10")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.Equals, rate.Limit(0))
}

func (b *ControllerSuite) TestNewAPILimiterFromConfig(c *check.C) {
	l, err := NewAPILimiterFromConfig("foo", "foo", nil)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.IsNil)

	l, err = NewAPILimiterFromConfig("foo", "rate-limit:5/m", nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.params.RateLimit, check.Equals, rate.Limit(5.0/60.0))

	l, err = NewAPILimiterFromConfig("foo", "estimated-processing-duration:100ms", nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.params.EstimatedProcessingDuration, check.Equals, time.Millisecond*100)

	l, err = NewAPILimiterFromConfig("foo", "rate-limit:5/m,rate-burst:2", nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.params.RateLimit, check.Equals, rate.Limit(5.0/60.0))
	c.Assert(l.params.RateBurst, check.Equals, 2)

	l, err = NewAPILimiterFromConfig("foo", "auto-adjust:true,parallel-requests:2,max-parallel-requests:3,min-parallel-requests:2,skip-initial:5", nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.params.AutoAdjust, check.Equals, true)
	c.Assert(l.params.ParallelRequests, check.Equals, 2)
	c.Assert(l.params.MaxParallelRequests, check.Equals, 3)
	c.Assert(l.params.MinParallelRequests, check.Equals, 2)
	c.Assert(l.params.SkipInitial, check.Equals, 5)

	l, err = NewAPILimiterFromConfig("foo", "delayed-adjustment-factor:0.5,log:true,max-wait-duration:2s,min-wait-duration:100ms,max-adjustment-factor:50.0", nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.params.DelayedAdjustmentFactor, check.Equals, 0.5)
	c.Assert(l.params.Log, check.Equals, true)
	c.Assert(l.params.MaxWaitDuration, check.Equals, 2*time.Second)
	c.Assert(l.params.MinWaitDuration, check.Equals, 100*time.Millisecond)
	c.Assert(l.params.MaxAdjustmentFactor, check.Equals, 50.0)
}

func (b *ControllerSuite) TestNewAPILimiterSet(c *check.C) {
	// Empty configuration
	l, err := NewAPILimiterSet(nil, nil, nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))

	// Invalid user config
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "foo",
	}, nil, nil)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.IsNil)

	// Default value only
	l, err = NewAPILimiterSet(nil, map[string]APILimiterParameters{
		"foo": {
			RateLimit: rate.Limit(1.0 / 60.0),
		},
	}, nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.Limiter("foo"), check.Not(check.IsNil))
	c.Assert(l.Limiter("foo2"), check.IsNil)

	// User config only
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "rate-limit:2/m,rate-burst:2",
	}, nil, nil)
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.Limiter("foo").params.RateLimit, check.Equals, rate.Limit(1.0/30.0))
	c.Assert(l.Limiter("foo").params.RateBurst, check.Equals, 2)

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
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))
	c.Assert(l.Limiter("foo").params.RateLimit, check.Equals, rate.Limit(1.0/30.0))
	c.Assert(l.Limiter("foo").params.RateBurst, check.Equals, 2)
	c.Assert(l.Limiter("foo").params.AutoAdjust, check.Equals, true)

	// Overwrite default with an invalid value
	l, err = NewAPILimiterSet(map[string]string{
		"foo": "rate-limit:foo,rate-burst:2",
	}, map[string]APILimiterParameters{
		"foo": {
			RateLimit: rate.Limit(1.0 / 60.0),
		},
	}, nil)
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(l, check.IsNil)
}

func (b *ControllerSuite) TestAPILimiterMetrics(c *check.C) {
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
	c.Assert(err, check.IsNil)
	c.Assert(l, check.Not(check.IsNil))

	req0, err := l.Wait(context.Background(), "unknown-call")
	c.Assert(err, check.IsNil)
	c.Assert(req0, check.Not(check.IsNil))
	req0.Done()
	c.Assert(req0.WaitDuration(), check.Equals, time.Duration(0))

	req1, err := l.Wait(context.Background(), "foo")
	c.Assert(err, check.IsNil)
	c.Assert(req1, check.Not(check.IsNil))
	time.Sleep(5 * time.Millisecond)
	req1.Done()

	req2, err := l.Wait(context.Background(), "foo")
	c.Assert(err, check.IsNil)
	c.Assert(req2, check.Not(check.IsNil))
	time.Sleep(5 * time.Millisecond)
	req2.Done()

	req3, err := l.Wait(context.Background(), "foo")
	c.Assert(err, check.IsNil)
	c.Assert(req2, check.Not(check.IsNil))
	time.Sleep(5 * time.Millisecond)
	req3.Error(fmt.Errorf("error"))
	req3.Done()

	a := l.Limiter("foo")

	c.Assert(metrics.metrics["foo"].WaitDuration, check.Equals, req1.WaitDuration()+req2.WaitDuration()+req3.WaitDuration())
	c.Assert(metrics.metrics["foo"].numSuccess, check.Equals, 2)
	c.Assert(metrics.metrics["foo"].numError, check.Equals, 1)
	c.Assert(metrics.metrics["foo"].Limit, check.Equals, a.params.RateLimit)
	c.Assert(metrics.metrics["foo"].Burst, check.Equals, a.params.RateBurst)
	c.Assert(metrics.metrics["foo"].ParallelRequests, check.Equals, a.params.ParallelRequests)
	c.Assert(metrics.metrics["foo"].EstimatedProcessingDuration, check.Equals, a.params.EstimatedProcessingDuration.Seconds())
	c.Assert(metrics.metrics["foo"].MeanProcessingDuration, check.Equals, a.meanProcessingDuration)
	c.Assert(metrics.metrics["foo"].MeanWaitDuration, check.Equals, a.meanWaitDuration)
	c.Assert(metrics.metrics["foo"].AdjustmentFactor, check.Equals, a.adjustmentFactor)
}

func (b *ControllerSuite) TestAPILimiterMergeUserConfig(c *check.C) {
	// Merge empty configuration into empty configuration. Nothing should change
	o := APILimiterParameters{}
	n, err := o.MergeUserConfig("")
	c.Assert(err, check.IsNil)
	c.Assert(o.EstimatedProcessingDuration, check.Equals, n.EstimatedProcessingDuration)
	c.Assert(o.AutoAdjust, check.Equals, n.AutoAdjust)
	c.Assert(o.MeanOver, check.Equals, n.MeanOver)
	c.Assert(o.MaxParallelRequests, check.Equals, n.MaxParallelRequests)
	c.Assert(o.MinParallelRequests, check.Equals, n.MinParallelRequests)
	c.Assert(o.RateLimit, check.Equals, n.RateLimit)
	c.Assert(o.RateBurst, check.Equals, n.RateBurst)
	c.Assert(o.MaxWaitDuration, check.Equals, n.MaxWaitDuration)
	c.Assert(o.Log, check.Equals, n.Log)

	// Overwrite defaults with user configuration, check updated values
	o = APILimiterParameters{
		AutoAdjust:          false,
		MaxParallelRequests: 4,
	}
	n, err = o.MergeUserConfig("auto-adjust:true,max-parallel-requests:3,min-parallel-requests:2")
	c.Assert(err, check.IsNil)
	c.Assert(o.EstimatedProcessingDuration, check.Equals, n.EstimatedProcessingDuration)
	c.Assert(n.AutoAdjust, check.Equals, true)
	c.Assert(o.MeanOver, check.Equals, n.MeanOver)
	c.Assert(n.MaxParallelRequests, check.Equals, 3)
	c.Assert(n.MinParallelRequests, check.Equals, 2)
	c.Assert(o.RateLimit, check.Equals, n.RateLimit)
	c.Assert(o.RateBurst, check.Equals, n.RateBurst)
	c.Assert(o.MaxWaitDuration, check.Equals, n.MaxWaitDuration)
	c.Assert(o.Log, check.Equals, n.Log)

	// Merge invalid configuration, must fail
	_, err = o.MergeUserConfig("foo")
	c.Assert(err, check.Not(check.IsNil))
}

func (b *ControllerSuite) TestParseUserConfigKeyValue(c *check.C) {
	p := &APILimiterParameters{}

	c.Assert(p.mergeUserConfigKeyValue("", ""), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("foo", ""), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("rate-limit", "10"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("rate-limit", "10/m"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("rate-burst", "foo"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("rate-burst", "10"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("max-wait-duration", "100sm"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("max-wait-duration", "100ms"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("min-wait-duration", "100sm"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("min-wait-duration", "100ms"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("estimated-processing-duration", "100sm"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("estimated-processing-duration", "100ms"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("auto-adjust", "not-true"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("auto-adjust", "true"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("auto-adjust", "false"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("max-parallel-requests", "ss"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("max-parallel-requests", "10"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("parallel-requests", "ss"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("parallel-requests", "10"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("min-parallel-requests", "ss"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("min-parallel-requests", "10"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("mean-over", "foo"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("mean-over", "10"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("log", "not-true"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("log", "true"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("log", "false"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("delayed-adjustment-factor", "0.25"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("delayed-adjustment-factor", "foo"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("max-adjustment-factor", "0.25"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("max-adjustment-factor", "foo"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfigKeyValue("skip-initial", "2"), check.IsNil)
	c.Assert(p.mergeUserConfigKeyValue("skip-initial", "foo"), check.Not(check.IsNil))
}

func (b *ControllerSuite) TestParseUserConfig(c *check.C) {
	p := &APILimiterParameters{}
	c.Assert(p.mergeUserConfig("auto-adjust:true,"), check.IsNil)
	c.Assert(p.AutoAdjust, check.Equals, true)
	c.Assert(p.mergeUserConfig("auto-adjust:false,rate-limit:10/s,"), check.IsNil)
	c.Assert(p.AutoAdjust, check.Equals, false)
	c.Assert(p.RateLimit, check.Equals, rate.Limit(10.0))
	c.Assert(p.mergeUserConfig("auto-adjust"), check.Not(check.IsNil))
	c.Assert(p.mergeUserConfig("1:2:3"), check.Not(check.IsNil))
}

func (b *ControllerSuite) TestCalcMeanDuration(c *check.C) {
	c.Assert(calcMeanDuration([]time.Duration{10, 10, 10, 10}), check.Equals, time.Duration(10).Seconds())
	c.Assert(calcMeanDuration([]time.Duration{1, 2, 3}), check.Equals, time.Duration(2).Seconds())
}

func (b *ControllerSuite) TestDelayedAdjustment(c *check.C) {
	l := APILimiter{
		adjustmentFactor: 1.5,
		params:           APILimiterParameters{DelayedAdjustmentFactor: 0.5},
	}
	c.Assert(l.delayedAdjustment(1.0, 0.0, 0.0), check.Equals, 1.25)
	c.Assert(l.delayedAdjustment(1.0, 2.0, 0.0), check.Equals, 2.0)
	c.Assert(l.delayedAdjustment(1.0, 0.0, 1.1), check.Equals, 1.1)
}

func (b *ControllerSuite) TestSkipInitial(c *check.C) {
	// Validate that SkipInitial skips all waiting duration
	iterations := 10
	a := NewAPILimiter("foo", APILimiterParameters{
		SkipInitial:      iterations,
		RateLimit:        1.0,
		ParallelRequests: 2,
	}, nil)

	for i := 0; i < iterations; i++ {
		req, err := a.Wait(context.Background())
		c.Assert(err, check.IsNil)
		c.Assert(req, check.Not(check.IsNil))
		go func(r LimitedRequest) {
			time.Sleep(20 * time.Millisecond)
			r.Done()
		}(req)
	}

	c.Assert(testutils.WaitUntil(func() bool {
		a.mutex.RLock()
		defer a.mutex.RUnlock()
		return a.requestsProcessed == int64(iterations)
	}, 5*time.Second), check.IsNil)

	c.Assert(a.requestsProcessed, check.Equals, int64(iterations))
	c.Assert(a.meanWaitDuration, check.Equals, 0.0)
}

func (b *ControllerSuite) TestCalculateAdjustmentFactor(c *check.C) {
	estimatedProcessingDuration := time.Second
	maxAdjustmentFactor := 20.0
	a := NewAPILimiter("foo", APILimiterParameters{
		EstimatedProcessingDuration: estimatedProcessingDuration,
		MaxAdjustmentFactor:         maxAdjustmentFactor,
	}, nil)

	a.meanProcessingDuration = estimatedProcessingDuration.Seconds()
	c.Assert(a.calculateAdjustmentFactor(), check.Equals, 1.0)

	a.meanProcessingDuration = estimatedProcessingDuration.Seconds() / 2
	c.Assert(a.calculateAdjustmentFactor(), check.Equals, 2.0)

	a.meanProcessingDuration = (time.Second * 1000).Seconds()
	c.Assert(a.calculateAdjustmentFactor(), check.Equals, 1.0/maxAdjustmentFactor)

	a.meanProcessingDuration = (time.Second / 1000).Seconds()
	c.Assert(a.calculateAdjustmentFactor(), check.Equals, 1.0*maxAdjustmentFactor)
}

func (b *ControllerSuite) TestAdjustmentLimit(c *check.C) {
	a := NewAPILimiter("foo", APILimiterParameters{MaxAdjustmentFactor: 2.0}, nil)
	c.Assert(a.adjustmentLimit(10.0, 2.0), check.Equals, 4.0)
	c.Assert(a.adjustmentLimit(1.5, 2.0), check.Equals, 1.5)
	c.Assert(a.adjustmentLimit(0.9, 2.0), check.Equals, 1.0)
}

func (b *ControllerSuite) TestAdjustedBurst(c *check.C) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:               1.0,
		RateBurst:               1,
		DelayedAdjustmentFactor: 0.5,
		MaxAdjustmentFactor:     2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	c.Assert(a.adjustedBurst(), check.Equals, 2)
}

func (b *ControllerSuite) TestAdjustedLimit(c *check.C) {
	a := NewAPILimiter("foo", APILimiterParameters{
		RateLimit:           1.0,
		MaxAdjustmentFactor: 2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	c.Assert(a.adjustedLimit(), check.Equals, rate.Limit(2.0))
	a.adjustmentFactor = 0.25
	c.Assert(a.adjustedLimit(), check.Equals, rate.Limit(0.5))
	a.adjustmentFactor = 1.0
	c.Assert(a.adjustedLimit(), check.Equals, rate.Limit(1.0))
}

func (b *ControllerSuite) TestAdjustedParallelRequests(c *check.C) {
	a := NewAPILimiter("foo", APILimiterParameters{
		ParallelRequests:        2,
		DelayedAdjustmentFactor: 0.5,
		MaxAdjustmentFactor:     2.0,
	}, nil)
	a.adjustmentFactor = 4.0
	c.Assert(a.adjustedParallelRequests(), check.Equals, 4)
	a.adjustmentFactor = 0.25
	c.Assert(a.adjustedParallelRequests(), check.Equals, 1)
	a.adjustmentFactor = 1.0
	c.Assert(a.adjustedParallelRequests(), check.Equals, 2)
}

func (b *ControllerSuite) testStressRateLimiter(c *check.C, nGoRoutines int) {
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
		completed, retries int32
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
						atomic.AddInt32(&completed, 1)
						sem.Release(1)
						return
					}
					atomic.AddInt32(&retries, 1)
				}
			}()
		}
	}()

	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadInt32(&completed) == int32(nGoRoutines)
	}, 5*time.Second), check.IsNil)

	log.Infof("%+v", a)
	log.Infof("Total retries: %v", atomic.LoadInt32(&retries))
}

func (b *ControllerSuite) TestReservationCancel(c *check.C) {
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
	c.Assert(err, check.IsNil)

	var completed int32

	// All of these requests must fail due to having to wait too long as
	// the only parallel request slot is occupied. The rate limiter should
	// not get occupied with these requests though.
	for i := 0; i < 20; i++ {
		go func() {
			_, err := a.Wait(context.Background())
			c.Assert(err, check.Not(check.IsNil))
			atomic.AddInt32(&completed, 1)
		}()
	}

	c.Assert(testutils.WaitUntil(func() bool {
		return atomic.LoadInt32(&completed) == 20
	}, time.Second), check.IsNil)

	req.Done()

	// All of these requests should now succeed
	for i := 0; i < 10; i++ {
		req2, err := a.Wait(context.Background())
		c.Assert(err, check.IsNil)
		req2.Done()
	}
}
