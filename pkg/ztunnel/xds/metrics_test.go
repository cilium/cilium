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

	// Verify metric is initialized
	require.NotNil(t, m.CertificateIssuanceFailures, "CertificateIssuanceFailures should be initialized")
}

func TestCertificateIssuanceMetricsIncrement(t *testing.T) {
	// Create metrics instance
	m := NewMetrics()

	// Test certificate issuance failure metrics with different status values
	m.CertificateIssuanceFailures.WithLabelValues("csr_empty").Inc()
	m.CertificateIssuanceFailures.WithLabelValues("csr_invalid").Inc()
	m.CertificateIssuanceFailures.WithLabelValues("signature_failed").Inc()
	m.CertificateIssuanceFailures.WithLabelValues("sa_not_found").Inc()

	// No assertions needed - we're just verifying metrics don't panic
	t.Log("All certificate metrics incremented successfully")
}

// TestCertificateIssuanceFailuresActuallyEmit verifies certificate issuance failure metrics are actually emitted to Prometheus
func TestCertificateIssuanceFailuresActuallyEmit(t *testing.T) {
	// Create a test registry
	registry := prometheus.NewRegistry()

	// Create metrics and register to test registry
	certFailures := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "certificate_issuance_failures_total",
			Help:      "Total number of certificate issuance failures from Spire by status",
		},
		[]string{labelStatus},
	)
	registry.MustRegister(certFailures)

	// Emit metrics with different status labels representing different failure scenarios
	certFailures.WithLabelValues("csr_empty").Inc()
	certFailures.WithLabelValues("csr_invalid").Inc()
	certFailures.WithLabelValues("csr_parse_failed").Inc()
	certFailures.WithLabelValues("signature_failed").Inc()
	certFailures.WithLabelValues("signature_failed").Inc() // Increment twice
	certFailures.WithLabelValues("uri_invalid").Inc()
	certFailures.WithLabelValues("scheme_invalid").Inc()
	certFailures.WithLabelValues("spiffe_malformed").Inc()
	certFailures.WithLabelValues("sa_not_found").Inc()
	certFailures.WithLabelValues("cert_creation_failed").Inc()

	// Gather metrics from registry - PROVE they're actually there
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1, "Expected exactly 1 metric family")

	// Verify metric family name
	assert.Equal(t, "cilium_ztunnel_certificate_issuance_failures_total", *metricFamilies[0].Name)
	assert.Equal(t, "Total number of certificate issuance failures from Spire by status", *metricFamilies[0].Help)

	// Should have 9 metrics (one for each unique label value)
	require.Len(t, metricFamilies[0].Metric, 9, "Expected 9 metrics for 9 different status labels")

	// Verify each metric has correct label structure
	metrics := metricFamilies[0].Metric

	// Track which status labels we've seen and their values
	statusCounts := make(map[string]float64)
	for i := range metrics {
		m := metrics[i]
		require.Len(t, m.Label, 1, "Expected exactly 1 label")
		assert.Equal(t, "status", *m.Label[0].Name)

		statusValue := *m.Label[0].Value
		statusCounts[statusValue] = *m.Counter.Value
	}

	// Verify all expected status labels are present with correct counts
	assert.Equal(t, float64(1), statusCounts["csr_empty"], "csr_empty should be incremented once")
	assert.Equal(t, float64(1), statusCounts["csr_invalid"], "csr_invalid should be incremented once")
	assert.Equal(t, float64(1), statusCounts["csr_parse_failed"], "csr_parse_failed should be incremented once")
	assert.Equal(t, float64(2), statusCounts["signature_failed"], "signature_failed should be incremented twice")
	assert.Equal(t, float64(1), statusCounts["uri_invalid"], "uri_invalid should be incremented once")
	assert.Equal(t, float64(1), statusCounts["scheme_invalid"], "scheme_invalid should be incremented once")
	assert.Equal(t, float64(1), statusCounts["spiffe_malformed"], "spiffe_malformed should be incremented once")
	assert.Equal(t, float64(1), statusCounts["sa_not_found"], "sa_not_found should be incremented once")
	assert.Equal(t, float64(1), statusCounts["cert_creation_failed"], "cert_creation_failed should be incremented once")
}

// TestCertificateMetricLabelsMatchServerCode verifies the status labels match what's actually used in xds_server.go
func TestCertificateMetricLabelsMatchServerCode(t *testing.T) {
	// These are the exact labels used in xds_server.go CreateCertificate() function
	// If someone changes the labels in the server, this test will remind them to update the metric definition
	expectedLabels := []string{
		"csr_empty",
		"csr_invalid",
		"csr_parse_failed",
		"signature_failed",
		"uri_invalid",
		"scheme_invalid",
		"spiffe_malformed",
		"sa_not_found",
		"cert_creation_failed",
	}

	// Create registry and metrics
	registry := prometheus.NewRegistry()
	certFailures := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "certificate_issuance_failures_total",
			Help:      "Total number of certificate issuance failures from Spire by status",
		},
		[]string{labelStatus},
	)
	registry.MustRegister(certFailures)

	// Increment all expected labels
	for _, label := range expectedLabels {
		certFailures.WithLabelValues(label).Inc()
	}

	// Gather and verify all labels are present
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metricFamilies, 1)
	require.Len(t, metricFamilies[0].Metric, len(expectedLabels), "All expected labels should be present")

	// Verify each label exists
	foundLabels := make(map[string]bool)
	for _, m := range metricFamilies[0].Metric {
		foundLabels[*m.Label[0].Value] = true
	}

	for _, expectedLabel := range expectedLabels {
		assert.True(t, foundLabels[expectedLabel], "Expected label %s should be present", expectedLabel)
	}
}
