<<<<<<< HEAD
package metrics

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpMethodCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubble_http_method_requests_total",
			Help: "Total number of HTTP requests by method and path.",
		},
		[]string{"method", "path"},
	)

	httpStatusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubble_http_status_requests_total",
			Help: "Total number of HTTP requests by status code and path.",
		},
		[]string{"status", "path"},
	)

	httpDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "hubble_http_duration_seconds",
			Help:    "Duration of HTTP requests by method and path.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		},
		[]string{"method", "path"},
	)
=======
package metrics

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpMethodCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubble_http_method_requests_total",
			Help: "Total number of HTTP requests by method and path.",
		},
		[]string{"method", "path"},
	)

	httpStatusCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubble_http_status_requests_total",
			Help: "Total number of HTTP requests by status code and path.",
		},
		[]string{"status", "path"},
	)

	httpDurationHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "hubble_http_duration_seconds",
			Help:    "Duration of HTTP requests by method and path.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		},
		[]string{"method", "path"},
	)
>>>>>>> fix-bug-expose-url-path-in-http-metrics