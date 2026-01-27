// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

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
	require.NotNil(t, m.ConnectionActive, "ConnectionActive should be initialized")
}

func TestEnrollmentMetricsIncrement(t *testing.T) {
	// Create metrics instance
	m := NewMetrics()

	// Test enrollment failure metrics with different status values
	m.EnrollmentFailures.WithLabelValues("netns_failed").Inc()
	m.EnrollmentFailures.WithLabelValues("iptables_failed").Inc()
	m.EnrollmentFailures.WithLabelValues("send_failed").Inc()

	// Test connection metrics
	m.ConnectionActive.Set(1)
	m.ConnectionActive.Set(0)

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
			Help:      "Total number of endpoint enrollment failures to ztunnel by status",
		},
		[]string{labelStatus},
	)
	registry.MustRegister(enrollmentFailures)

	// Emit metrics with different status labels
	enrollmentFailures.WithLabelValues("netns_failed").Inc()
	enrollmentFailures.WithLabelValues("iptables_failed").Inc()
	enrollmentFailures.WithLabelValues("iptables_failed").Inc() // Increment twice
	enrollmentFailures.WithLabelValues("send_failed").Inc()

	// Gather metrics from registry - PROVE they're actually there
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	// Verify metric family name
	assert.Equal(t, "cilium_ztunnel_enrollment_failures_total", *metricFamilies[0].Name)
	assert.Equal(t, "Total number of endpoint enrollment failures to ztunnel by status", *metricFamilies[0].Help)

	// Should have 3 metrics (one for each unique label value)
	require.Len(t, metricFamilies[0].Metric, 3, "Expected 3 metrics for 3 different status labels")

	// Verify each metric's labels and values
	metrics := metricFamilies[0].Metric

	// Track which status labels we've seen and their values
	statusCounts := make(map[string]float64)
	for _, m := range metrics {
		require.Len(t, m.Label, 1, "Expected exactly 1 label")
		assert.Equal(t, "status", *m.Label[0].Name)
		statusCounts[*m.Label[0].Value] = *m.Counter.Value
	}

	// Verify all expected status labels are present with correct counts
	assert.Equal(t, float64(1), statusCounts["netns_failed"], "netns_failed should be incremented once")
	assert.Equal(t, float64(2), statusCounts["iptables_failed"], "iptables_failed should be incremented twice")
	assert.Equal(t, float64(1), statusCounts["send_failed"], "send_failed should be incremented once")
}

// TestConnectionActiveActuallyEmit verifies connection active gauge is actually emitted to Prometheus
func TestConnectionActiveActuallyEmit(t *testing.T) {
	// Create a test registry
	registry := prometheus.NewRegistry()

	// Create connection active gauge and register to test registry
	connectionActive := metric.NewGauge(
		metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "connection_active",
			Help:      "Whether ztunnel connection is active (1) or not (0)",
		},
	)
	registry.MustRegister(connectionActive)

	// Set gauge to 1 (connected)
	connectionActive.Set(1)

	// Gather and verify
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	// Verify metric family
	assert.Equal(t, "cilium_ztunnel_connection_active", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 1, "Expected exactly 1 metric")

	// Verify gauge value is 1
	metric := metricFamilies[0].Metric[0]
	assert.Equal(t, float64(1), *metric.Gauge.Value, "Connection should be active (1)")

	// Change to disconnected
	connectionActive.Set(0)

	// Gather again and verify it changed
	metricFamilies, err = registry.Gather()
	require.NoError(t, err)
	metric = metricFamilies[0].Metric[0]
	assert.Equal(t, float64(0), *metric.Gauge.Value, "Connection should be inactive (0)")
}

// TestAllMetricsEmitTogether verifies both metrics can coexist in the same registry
func TestAllMetricsEmitTogether(t *testing.T) {
	// Create a test registry
	registry := prometheus.NewRegistry()

	// Create both metrics
	enrollmentFailures := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "enrollment_failures_total",
			Help:      "Total number of endpoint enrollment failures to ztunnel by status",
		},
		[]string{labelStatus},
	)
	connectionActive := metric.NewGauge(
		metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "connection_active",
			Help:      "Whether ztunnel connection is active (1) or not (0)",
		},
	)

	// Register both
	registry.MustRegister(enrollmentFailures)
	registry.MustRegister(connectionActive)

	// Emit some values
	enrollmentFailures.WithLabelValues("netns_failed").Inc()
	enrollmentFailures.WithLabelValues("send_failed").Inc()
	connectionActive.Set(1)

	// Gather and verify both metrics exist
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 2, "Expected 2 metric families")

	// Verify both metrics are present (order may vary)
	metricNames := map[string]bool{
		*metricFamilies[0].Name: true,
		*metricFamilies[1].Name: true,
	}
	assert.True(t, metricNames["cilium_ztunnel_connection_active"], "connection_active metric should be present")
	assert.True(t, metricNames["cilium_ztunnel_enrollment_failures_total"], "enrollment_failures_total metric should be present")
}

func TestGetNamespace(t *testing.T) {
	// Test with nil endpoint
	result := getNamespace(nil)
	assert.Equal(t, "unknown", result)
}
