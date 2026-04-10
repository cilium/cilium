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

func TestMetricsDisabledByDefault(t *testing.T) {
	m := NewMetrics()

	// Verify all metrics are initialized but disabled
	require.NotNil(t, m.EnrollmentTotal, "EnrollmentTotal should be initialized")
	require.NotNil(t, m.EnrollmentFailures, "EnrollmentFailures should be initialized")
	require.NotNil(t, m.ConnectionActive, "ConnectionActive should be initialized")

	assert.False(t, m.EnrollmentTotal.IsEnabled(), "EnrollmentTotal should be disabled by default")
	assert.False(t, m.ConnectionActive.IsEnabled(), "ConnectionActive should be disabled by default")

	// Verify operations on disabled metrics don't panic
	m.EnrollmentTotal.Inc()
	m.EnrollmentFailures.WithLabelValues("netns_failed").Inc()
	m.ConnectionActive.Inc()
	m.ConnectionActive.Dec()
}

func TestMetricsEnabled(t *testing.T) {
	m := NewMetrics()
	m.Enable()

	assert.True(t, m.EnrollmentTotal.IsEnabled(), "EnrollmentTotal should be enabled after Enable()")
	assert.True(t, m.ConnectionActive.IsEnabled(), "ConnectionActive should be enabled after Enable()")
}

// TestEnrollmentFailuresActuallyEmit verifies enrollment failure metrics are actually emitted to Prometheus
func TestEnrollmentFailuresActuallyEmit(t *testing.T) {
	registry := prometheus.NewRegistry()

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

	enrollmentFailures.WithLabelValues("netns_failed").Inc()
	enrollmentFailures.WithLabelValues("iptables_failed").Inc()
	enrollmentFailures.WithLabelValues("iptables_failed").Inc()
	enrollmentFailures.WithLabelValues("send_failed").Inc()

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	assert.Equal(t, "cilium_ztunnel_zds_enrollment_failures_total", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 3, "Expected 3 metrics for 3 different status labels")

	statusCounts := make(map[string]float64)
	for _, m := range metricFamilies[0].Metric {
		require.Len(t, m.Label, 1, "Expected exactly 1 label")
		assert.Equal(t, "status", *m.Label[0].Name)
		statusCounts[*m.Label[0].Value] = *m.Counter.Value
	}

	assert.Equal(t, float64(1), statusCounts["netns_failed"], "netns_failed should be incremented once")
	assert.Equal(t, float64(2), statusCounts["iptables_failed"], "iptables_failed should be incremented twice")
	assert.Equal(t, float64(1), statusCounts["send_failed"], "send_failed should be incremented once")
}

// TestConnectionActiveActuallyEmit verifies connection active gauge is actually emitted to Prometheus
func TestConnectionActiveActuallyEmit(t *testing.T) {
	registry := prometheus.NewRegistry()

	connectionActive := metric.NewGauge(
		metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "connection_active",
			Help:      "Whether ztunnel connection is active (1) or not (0)",
		},
	)
	registry.MustRegister(connectionActive)

	connectionActive.Set(1)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	assert.Equal(t, "cilium_ztunnel_zds_connection_active", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 1, "Expected exactly 1 metric")
	assert.Equal(t, float64(1), *metricFamilies[0].Metric[0].Gauge.Value, "Connection should be active (1)")

	connectionActive.Set(0)

	metricFamilies, err = registry.Gather()
	require.NoError(t, err)
	assert.Equal(t, float64(0), *metricFamilies[0].Metric[0].Gauge.Value, "Connection should be inactive (0)")
}

// TestAllMetricsEmitTogether verifies all metrics can coexist in the same registry
func TestAllMetricsEmitTogether(t *testing.T) {
	registry := prometheus.NewRegistry()

	enrollmentTotal := metric.NewCounter(
		metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "enrollment_total",
			Help:      "Total number of endpoint enrollment attempts to ztunnel",
		},
	)
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

	registry.MustRegister(enrollmentTotal)
	registry.MustRegister(enrollmentFailures)
	registry.MustRegister(connectionActive)

	enrollmentTotal.Inc()
	enrollmentTotal.Inc()
	enrollmentFailures.WithLabelValues("netns_failed").Inc()
	enrollmentFailures.WithLabelValues("send_failed").Inc()
	connectionActive.Set(1)

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 3, "Expected 3 metric families")

	metricNames := make(map[string]bool)
	for _, mf := range metricFamilies {
		metricNames[*mf.Name] = true
	}
	assert.True(t, metricNames["cilium_ztunnel_zds_connection_active"], "connection_active metric should be present")
	assert.True(t, metricNames["cilium_ztunnel_zds_enrollment_total"], "enrollment_total metric should be present")
	assert.True(t, metricNames["cilium_ztunnel_zds_enrollment_failures_total"], "enrollment_failures_total metric should be present")
}
