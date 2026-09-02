/*
Copyright 2018 The Kubernetes Authors.

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

package metrics

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientmetrics "k8s.io/client-go/tools/metrics"
)

// this file contains setup logic to initialize the myriad of places
// that client-go registers metrics.  We copy the names and formats
// from Kubernetes so that we match the core controllers.

const (
	hostLabel = "host"
	verbLabel = "verb"
)

// defaultRESTClientDurationBuckets matches Kubernetes core controller REST client metrics.
// They start at 5ms; override via RESTClientMetricsOptions.DurationBuckets if a scrape
// pipeline still consumes classic buckets and needs sub-5ms resolution.
var defaultRESTClientDurationBuckets = []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0}

func restClientDurationHistogram(name, help string, labels []string, buckets []float64) *prometheus.HistogramVec {
	if len(buckets) == 0 {
		buckets = defaultRESTClientDurationBuckets
	}
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:                            name,
		Help:                            help,
		Buckets:                         buckets,
		NativeHistogramBucketFactor:     1.1,
		NativeHistogramMaxBucketNumber:  100,
		NativeHistogramMinResetDuration: 1 * time.Hour,
	}, labels)
}

func newRequestLatency(buckets []float64) *prometheus.HistogramVec {
	return restClientDurationHistogram(
		"rest_client_request_duration_seconds",
		"Request latency in seconds. Broken down by verb and host.",
		[]string{verbLabel, hostLabel},
		buckets,
	)
}

func newResolverLatency(buckets []float64) *prometheus.HistogramVec {
	return restClientDurationHistogram(
		"rest_client_dns_resolution_duration_seconds",
		"DNS resolver latency in seconds. Broken down by host.",
		[]string{hostLabel},
		buckets,
	)
}

func newRateLimiterLatency(buckets []float64) *prometheus.HistogramVec {
	return restClientDurationHistogram(
		"rest_client_rate_limiter_duration_seconds",
		"Client side rate limiter latency in seconds. Broken down by verb, and host.",
		[]string{verbLabel, hostLabel},
		buckets,
	)
}

func newRequestSize() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rest_client_request_size_bytes",
			Help: "Request size in bytes. Broken down by verb and host.",
			// 64 bytes to 16MB
			Buckets:                         []float64{64, 256, 512, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216},
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: 1 * time.Hour,
		},
		[]string{verbLabel, hostLabel},
	)
}

func newResponseSize() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rest_client_response_size_bytes",
			Help: "Response size in bytes. Broken down by verb and host.",
			// 64 bytes to 16MB
			Buckets:                         []float64{64, 256, 512, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216},
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: 1 * time.Hour,
		},
		[]string{verbLabel, hostLabel},
	)
}

func newRequestRetry() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rest_client_request_retries_total",
			Help: "Number of request retries, partitioned by status code, verb, and host.",
		},
		[]string{"code", verbLabel, hostLabel},
	)
}

var (
	// requestResult is registered by default. The other client metrics are
	// opt-in: adapters start with a nil collector and RegisterRESTClientMetrics*
	// stores the HistogramVec / CounterVec.
	requestResult = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rest_client_requests_total",
			Help: "Number of HTTP requests, partitioned by status code, method, and host.",
		},
		[]string{"code", "method", hostLabel},
	)

	requestLatency     = &latencyAdapter{}
	resolverLatency    = &resolverLatencyAdapter{}
	requestSize        = &sizeAdapter{}
	responseSize       = &sizeAdapter{}
	rateLimiterLatency = &latencyAdapter{}
	requestRetry       = &retryAdapter{}
)

// RESTClientMetric identifies an opt-in client-go REST client metric.
// Pass values to RegisterRESTClientMetrics to enable a subset.
type RESTClientMetric int

const (
	// MetricRequestLatency enables the rest_client_request_duration_seconds metric.
	MetricRequestLatency = iota + 1
	// MetricDNSResolutionLatency enables the rest_client_dns_resolution_duration_seconds metric.
	MetricDNSResolutionLatency
	// MetricRequestSize enables the rest_client_request_size_bytes metric.
	MetricRequestSize
	// MetricResponseSize enables the rest_client_response_size_bytes metric.
	MetricResponseSize
	// MetricRateLimiterLatency enables the rest_client_rate_limiter_duration_seconds metric.
	MetricRateLimiterLatency
	// MetricRequestRetry enables the rest_client_request_retries_total metric.
	MetricRequestRetry
)

func init() {
	registerClientMetrics()
}

// registerClientMetrics sets up the client latency metrics from client-go.
func registerClientMetrics() {
	// register the metrics with our registry
	Registry.MustRegister(requestResult)

	// register the metrics with client-go
	clientmetrics.Register(clientmetrics.RegisterOpts{
		RequestResult:      &resultAdapter{metric: requestResult},
		RequestLatency:     requestLatency,
		ResolverLatency:    resolverLatency,
		RequestSize:        requestSize,
		ResponseSize:       responseSize,
		RateLimiterLatency: rateLimiterLatency,
		RequestRetry:       requestRetry,
	})
}

// RESTClientMetricsOptions configures RegisterRESTClientMetricsWithOptions.
type RESTClientMetricsOptions struct {
	// DurationBuckets overrides the classic Prometheus histogram buckets used by
	// rest_client_request_duration_seconds, rest_client_dns_resolution_duration_seconds,
	// and rest_client_rate_limiter_duration_seconds.
	//
	// If nil or empty, the Kubernetes-default buckets are kept (starting at 5ms).
	// Native histogram settings are not changed.
	//
	// DurationBuckets is read when each duration metric is first registered.
	// Later calls for the same metric are ignored so already-registered collectors
	// are not replaced.
	DurationBuckets []float64
}

// RegisterRESTClientMetrics enables the given client metrics using default buckets
// that match Kubernetes core controllers.
func RegisterRESTClientMetrics(metrics ...RESTClientMetric) {
	RegisterRESTClientMetricsWithOptions(RESTClientMetricsOptions{}, metrics...)
}

// RegisterRESTClientMetricsWithOptions enables the given client metrics.
// See RESTClientMetricsOptions for knobs such as custom duration buckets.
func RegisterRESTClientMetricsWithOptions(opts RESTClientMetricsOptions, metrics ...RESTClientMetric) {
	for _, m := range metrics {
		switch m {
		case MetricRequestLatency:
			requestLatency.enable(func() *prometheus.HistogramVec {
				return newRequestLatency(opts.DurationBuckets)
			})
		case MetricDNSResolutionLatency:
			resolverLatency.enable(func() *prometheus.HistogramVec {
				return newResolverLatency(opts.DurationBuckets)
			})
		case MetricRequestSize:
			requestSize.enable(newRequestSize)
		case MetricResponseSize:
			responseSize.enable(newResponseSize)
		case MetricRateLimiterLatency:
			rateLimiterLatency.enable(func() *prometheus.HistogramVec {
				return newRateLimiterLatency(opts.DurationBuckets)
			})
		case MetricRequestRetry:
			requestRetry.enable(newRequestRetry)
		default:
			// unknown metric, ignore
		}
	}
}

// this section contains adapters, implementations, and other sundry organic, artisanally
// hand-crafted syntax trees required to convince client-go that it actually wants to let
// someone use its metrics.

// Client metrics adapters (method #1 for client-go metrics),
// copied (more-or-less directly) from k8s.io/kubernetes setup code
// (which isn't anywhere in an easily-importable place).

type resultAdapter struct {
	metric *prometheus.CounterVec
}

func (r *resultAdapter) Increment(_ context.Context, code, method, host string) {
	r.metric.WithLabelValues(code, method, host).Inc()
}

type latencyAdapter struct {
	once   sync.Once
	metric atomic.Pointer[prometheus.HistogramVec]
}

func (l *latencyAdapter) enable(newMetric func() *prometheus.HistogramVec) {
	l.once.Do(func() {
		h := newMetric()
		l.metric.Store(h)
		Registry.MustRegister(h)
	})
}

func (l *latencyAdapter) Observe(_ context.Context, verb string, u url.URL, duration time.Duration) {
	h := l.metric.Load()
	if h == nil {
		return
	}
	h.WithLabelValues(verb, u.Host).Observe(duration.Seconds())
}

type resolverLatencyAdapter struct {
	once   sync.Once
	metric atomic.Pointer[prometheus.HistogramVec]
}

func (r *resolverLatencyAdapter) enable(newMetric func() *prometheus.HistogramVec) {
	r.once.Do(func() {
		h := newMetric()
		r.metric.Store(h)
		Registry.MustRegister(h)
	})
}

func (r *resolverLatencyAdapter) Observe(_ context.Context, host string, duration time.Duration) {
	h := r.metric.Load()
	if h == nil {
		return
	}
	h.WithLabelValues(host).Observe(duration.Seconds())
}

type sizeAdapter struct {
	once   sync.Once
	metric atomic.Pointer[prometheus.HistogramVec]
}

func (r *sizeAdapter) enable(newMetric func() *prometheus.HistogramVec) {
	r.once.Do(func() {
		h := newMetric()
		r.metric.Store(h)
		Registry.MustRegister(h)
	})
}

func (r *sizeAdapter) Observe(_ context.Context, verb string, host string, size float64) {
	h := r.metric.Load()
	if h == nil {
		return
	}
	h.WithLabelValues(verb, host).Observe(size)
}

type retryAdapter struct {
	once   sync.Once
	metric atomic.Pointer[prometheus.CounterVec]
}

func (r *retryAdapter) enable(newMetric func() *prometheus.CounterVec) {
	r.once.Do(func() {
		c := newMetric()
		r.metric.Store(c)
		Registry.MustRegister(c)
	})
}

func (r *retryAdapter) IncrementRetry(_ context.Context, code, verb, host string) {
	c := r.metric.Load()
	if c == nil {
		return
	}
	c.WithLabelValues(code, verb, host).Inc()
}
