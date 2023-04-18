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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	clientmetrics "k8s.io/client-go/tools/metrics"
)

// this file contains setup logic to initialize the myriad of places
// that client-go registers metrics.  We copy the names and formats
// from Kubernetes so that we match the core controllers.

// Metrics subsystem and all of the keys used by the rest client.
const (
	RestClientSubsystem = "rest_client"
	LatencyKey          = "request_latency_seconds"
	ResultKey           = "requests_total"
)

var (
	// client metrics.

	// RequestLatency reports the request latency in seconds per verb/URL.
	// Deprecated: This metric is deprecated for removal in a future release: using the URL as a
	// dimension results in cardinality explosion for some consumers. It was deprecated upstream
	// in k8s v1.14 and hidden in v1.17 via https://github.com/kubernetes/kubernetes/pull/83836.
	// It is not registered by default. To register:
	//	import (
	//		clientmetrics "k8s.io/client-go/tools/metrics"
	//		clmetrics "sigs.k8s.io/controller-runtime/metrics"
	//	)
	//
	//	func init() {
	//		clmetrics.Registry.MustRegister(clmetrics.RequestLatency)
	//		clientmetrics.Register(clientmetrics.RegisterOpts{
	//			RequestLatency: clmetrics.LatencyAdapter
	//		})
	//	}
	RequestLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: RestClientSubsystem,
		Name:      LatencyKey,
		Help:      "Request latency in seconds. Broken down by verb and URL.",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10),
	}, []string{"verb", "url"})

	// requestLatency is a Prometheus Histogram metric type partitioned by
	// "verb", and "host" labels. It is used for the rest client latency metrics.
	requestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rest_client_request_duration_seconds",
			Help:    "Request latency in seconds. Broken down by verb, and host.",
			Buckets: []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0},
		},
		[]string{"verb", "host"},
	)

	requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rest_client_request_size_bytes",
			Help: "Request size in bytes. Broken down by verb and host.",
			// 64 bytes to 16MB
			Buckets: []float64{64, 256, 512, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216},
		},
		[]string{"verb", "host"},
	)

	responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "rest_client_response_size_bytes",
			Help: "Response size in bytes. Broken down by verb and host.",
			// 64 bytes to 16MB
			Buckets: []float64{64, 256, 512, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216},
		},
		[]string{"verb", "host"},
	)

	requestResult = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rest_client_requests_total",
			Help: "Number of HTTP requests, partitioned by status code, method, and host.",
		},
		[]string{"code", "method", "host"},
	)
)

func init() {
	registerClientMetrics()
}

// registerClientMetrics sets up the client latency metrics from client-go.
func registerClientMetrics() {
	// register the metrics with our registry
	Registry.MustRegister(requestLatency)
	Registry.MustRegister(requestSize)
	Registry.MustRegister(responseSize)
	Registry.MustRegister(requestResult)

	// register the metrics with client-go
	clientmetrics.Register(clientmetrics.RegisterOpts{
		RequestLatency: &LatencyAdapter{metric: requestLatency},
		RequestSize:    &sizeAdapter{metric: requestSize},
		ResponseSize:   &sizeAdapter{metric: responseSize},
		RequestResult:  &resultAdapter{metric: requestResult},
	})
}

// this section contains adapters, implementations, and other sundry organic, artisanally
// hand-crafted syntax trees required to convince client-go that it actually wants to let
// someone use its metrics.

// Client metrics adapters (method #1 for client-go metrics),
// copied (more-or-less directly) from k8s.io/kubernetes setup code
// (which isn't anywhere in an easily-importable place).

// LatencyAdapter implements LatencyMetric.
type LatencyAdapter struct {
	metric *prometheus.HistogramVec
}

// Observe increments the request latency metric for the given verb/URL.
func (l *LatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	l.metric.WithLabelValues(verb, u.String()).Observe(latency.Seconds())
}

type sizeAdapter struct {
	metric *prometheus.HistogramVec
}

func (s *sizeAdapter) Observe(ctx context.Context, verb string, host string, size float64) {
	s.metric.WithLabelValues(verb, host).Observe(size)
}

type resultAdapter struct {
	metric *prometheus.CounterVec
}

func (r *resultAdapter) Increment(_ context.Context, code, method, host string) {
	r.metric.WithLabelValues(code, method, host).Inc()
}
