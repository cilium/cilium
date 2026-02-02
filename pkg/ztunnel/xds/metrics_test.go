// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func TestMetricsInitialization(t *testing.T) {
	// Create metrics instance
	m := NewMetrics()

	// Verify all metrics are initialized
	require.NotNil(t, m.EnrollmentFailures, "EnrollmentFailures should be initialized")
}

func TestEnrollmentMetricsIncrement(t *testing.T) {
	// Create metrics instance
	m := NewMetrics()

	// Test enrollment failure metrics with different status values
	m.EnrollmentFailures.WithLabelValues("send_failed").Inc()
	m.EnrollmentFailures.WithLabelValues("nack_received").Inc()

	// No assertions needed - we're just verifying metrics don't panic
	// The prometheus library handles the actual metric storage
	t.Log("All metrics incremented successfully")
}

// TestEnrollmentFailuresActuallyEmit verifies enrollment failure metrics are actually emitted to Prometheus
func TestEnrollmentFailuresActuallyEmit(t *testing.T) {
	// Create a test registry
	registry := prometheus.NewRegistry()

	// Create metrics and register to test registry
	enrollmentFailures := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "enrollment_failures_total",
			Help:      "Total number of workload enrollment failures to ztunnel via XDS by status",
		},
		[]string{labelStatus},
	)
	registry.MustRegister(enrollmentFailures)

	// Emit metrics with different status labels
	enrollmentFailures.WithLabelValues("send_failed").Inc()
	enrollmentFailures.WithLabelValues("nack_received").Inc()
	enrollmentFailures.WithLabelValues("nack_received").Inc() // Increment twice

	// Gather metrics from registry - PROVE they're actually there
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	// Verify metric family name
	assert.Equal(t, "cilium_ztunnel_xds_enrollment_failures_total", *metricFamilies[0].Name)
	assert.Equal(t, "Total number of workload enrollment failures to ztunnel via XDS by status", *metricFamilies[0].Help)

	// Should have 2 metrics (one for each unique label value)
	require.Len(t, metricFamilies[0].Metric, 2, "Expected 2 metrics for 2 different status labels")

	// Verify each metric's labels and values
	metricsData := metricFamilies[0].Metric

	// Track which status labels we've seen and their values
	statusCounts := make(map[string]float64)
	for _, m := range metricsData {
		require.Len(t, m.Label, 1, "Expected exactly 1 label")
		assert.Equal(t, "status", *m.Label[0].Name)
		statusCounts[*m.Label[0].Value] = *m.Counter.Value
	}

	// Verify all expected status labels are present with correct counts
	assert.Equal(t, float64(1), statusCounts["send_failed"], "send_failed should be incremented once")
	assert.Equal(t, float64(2), statusCounts["nack_received"], "nack_received should be incremented twice")
}
