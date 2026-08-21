// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cel

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Metrics holds Prometheus metrics for the CEL module.
type Metrics struct {
	// CompilationDuration is a histogram of CEL expression compilation
	// durations, labelled by environment type and outcome ("success" or "error").
	CompilationDuration metric.Vec[metric.Observer]

	// EvaluationDuration is a histogram of CEL expression evaluation
	// durations, labelled by environment type and outcome ("success" or "error").
	// Only successful compilations that reach the evaluation step are counted.
	EvaluationDuration metric.Vec[metric.Observer]
}

func NewCELMetrics() *Metrics {
	return &Metrics{
		CompilationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "cel",
			Name:      "program_compilation_duration_seconds",
			Help:      "Duration in seconds of CEL expression compilation",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, []string{metrics.LabelType, metrics.LabelOutcome}),

		EvaluationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "cel",
			Name:      "program_evaluation_duration_seconds",
			Help:      "Duration in seconds of CEL expression evaluation",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, []string{metrics.LabelType, metrics.LabelOutcome}),
	}
}
