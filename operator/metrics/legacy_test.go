// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/metrics"
)

func newTestRegistry(t *testing.T) *metrics.Registry {
	t.Helper()
	reg := metrics.NewRegistry(metrics.RegistryParams{
		Logger: slog.Default(),
	})
	return reg
}

func TestDumpMetrics_NilRegistry(t *testing.T) {
	result, err := DumpMetrics(nil)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestDumpMetrics_Counter(t *testing.T) {
	reg := newTestRegistry(t)
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counter_total"})
	c.Add(42)
	require.NoError(t, reg.Register(c))

	result, err := DumpMetrics(reg)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "test_counter_total", result[0].Name)
	assert.InDelta(t, 42.0, result[0].Value, 1e-9)
}

func TestDumpMetrics_Histogram(t *testing.T) {
	reg := newTestRegistry(t)
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "test_histogram_seconds",
		Buckets: prometheus.DefBuckets,
	})
	// Observe values that should place p50 < p90 < p99
	for range 50 {
		h.Observe(0.01) // 50 fast samples
	}
	for range 40 {
		h.Observe(0.1) // 40 medium samples
	}
	for range 10 {
		h.Observe(1.0) // 10 slow samples
	}
	require.NoError(t, reg.Register(h))

	result, err := DumpMetrics(reg)
	require.NoError(t, err)

	// One entry per quantile: p50, p90, p99
	require.Len(t, result, 3)

	quantiles := make(map[string]float64)
	for _, m := range result {
		assert.Equal(t, "test_histogram_seconds", m.Name)
		q, ok := m.Labels["quantile"]
		require.True(t, ok, "expected 'quantile' label")
		quantiles[q] = m.Value
	}

	assert.Contains(t, quantiles, "0.5")
	assert.Contains(t, quantiles, "0.9")
	assert.Contains(t, quantiles, "0.99")

	// p50 should be around 0.01, p90 around 0.1, p99 around 1.0
	assert.Less(t, quantiles["0.5"], quantiles["0.9"])
	assert.Less(t, quantiles["0.9"], quantiles["0.99"])
}

func TestDumpMetrics_Histogram_PreservesExistingLabels(t *testing.T) {
	reg := newTestRegistry(t)
	hv := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_hist_labeled",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})
	hv.WithLabelValues("GET").Observe(0.05)
	require.NoError(t, reg.Register(hv))

	result, err := DumpMetrics(reg)
	require.NoError(t, err)
	require.Len(t, result, 3)

	for _, m := range result {
		assert.Equal(t, "GET", m.Labels["method"], "existing labels must be preserved")
		_, ok := m.Labels["quantile"]
		assert.True(t, ok, "quantile label must be present")
	}
}

func TestDumpMetrics_Summary(t *testing.T) {
	reg := newTestRegistry(t)
	s := prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "test_summary_seconds",
		Objectives: map[float64]float64{
			0.5:  0.05,
			0.9:  0.01,
			0.99: 0.001,
		},
	})
	for i := range 100 {
		s.Observe(float64(i) * 0.01)
	}
	require.NoError(t, reg.Register(s))

	result, err := DumpMetrics(reg)
	require.NoError(t, err)

	// One entry per predefined quantile
	require.Len(t, result, 3)

	quantiles := make(map[string]float64)
	for _, m := range result {
		assert.Equal(t, "test_summary_seconds", m.Name)
		q, ok := m.Labels["quantile"]
		require.True(t, ok, "expected 'quantile' label")
		quantiles[q] = m.Value
	}

	assert.Contains(t, quantiles, "0.5")
	assert.Contains(t, quantiles, "0.9")
	assert.Contains(t, quantiles, "0.99")

	// p50 < p90 < p99 for an ascending distribution
	assert.Less(t, quantiles["0.5"], quantiles["0.9"])
	assert.Less(t, quantiles["0.9"], quantiles["0.99"])
}
