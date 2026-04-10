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

func TestMetricsDisabledByDefault(t *testing.T) {
	m := NewMetrics()

	require.NotNil(t, m.EnrollmentFailures, "EnrollmentFailures should be initialized")

	// Verify operations on disabled metrics don't panic
	m.EnrollmentFailures.WithLabelValues("send_failed").Inc()
	m.EnrollmentFailures.WithLabelValues("nack_received").Inc()
}

func TestMetricsEnabled(t *testing.T) {
	m := NewMetrics()
	m.Enable()

	// Verify operations on enabled metrics don't panic
	m.EnrollmentFailures.WithLabelValues("send_failed").Inc()
	m.EnrollmentFailures.WithLabelValues("nack_received").Inc()
}

// TestEnrollmentFailuresActuallyEmit verifies enrollment failure metrics are actually emitted to Prometheus
func TestEnrollmentFailuresActuallyEmit(t *testing.T) {
	registry := prometheus.NewRegistry()

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

	enrollmentFailures.WithLabelValues("send_failed").Inc()
	enrollmentFailures.WithLabelValues("nack_received").Inc()
	enrollmentFailures.WithLabelValues("nack_received").Inc()

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	assert.Equal(t, "cilium_ztunnel_xds_enrollment_failures_total", *metricFamilies[0].Name)
	require.Len(t, metricFamilies[0].Metric, 2, "Expected 2 metrics for 2 different status labels")

	statusCounts := make(map[string]float64)
	for _, m := range metricFamilies[0].Metric {
		require.Len(t, m.Label, 1, "Expected exactly 1 label")
		assert.Equal(t, "status", *m.Label[0].Name)
		statusCounts[*m.Label[0].Value] = *m.Counter.Value
	}

	assert.Equal(t, float64(1), statusCounts["send_failed"], "send_failed should be incremented once")
	assert.Equal(t, float64(2), statusCounts["nack_received"], "nack_received should be incremented twice")
}
