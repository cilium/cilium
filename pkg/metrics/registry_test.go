// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	metricpkg "github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

// testAutoMetric implements metricpkg.WithMetadata for testing
type testAutoMetric struct {
	name    string
	enabled bool
	opts    metricpkg.Opts
}

func (m *testAutoMetric) Opts() metricpkg.Opts {
	return m.opts
}

func (m *testAutoMetric) SetEnabled(enabled bool) {
	m.enabled = enabled
}

func (m *testAutoMetric) IsEnabled() bool {
	return m.enabled
}

func (m *testAutoMetric) Describe(ch chan<- *prometheus.Desc) {}
func (m *testAutoMetric) Collect(ch chan<- prometheus.Metric) {}

// TestMetricsCoreOnly_DefaultBehavior verifies that existing behavior remains unchanged
// when metrics-core-only is disabled (default).
func TestMetricsCoreOnly_DefaultBehavior(t *testing.T) {
	metric1 := &testAutoMetric{
		name:    "test_metric_1",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_1",
		},
	}
	metric2 := &testAutoMetric{
		name:    "test_metric_2",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_2",
		},
	}

	params := RegistryParams{
		DaemonConfig: &option.DaemonConfig{
			MetricsCoreOnly: false,
		},
		Config: RegistryConfig{
			PrometheusServeAddr: "",
			Metrics:             []string{},
		},
		AutoMetrics: []metricpkg.WithMetadata{metric1, metric2},
	}

	reg := NewRegistry(params)
	require.NotNil(t, reg)
	reg.registerMetrics()

	require.True(t, metric1.IsEnabled(), "metric1 should remain enabled when MetricsCoreOnly is false")
	require.True(t, metric2.IsEnabled(), "metric2 should remain enabled when MetricsCoreOnly is false")
}

// TestMetricsCoreOnly_DisablesAllAutoMetrics verifies that all auto metrics are disabled
// when metrics-core-only is enabled.
func TestMetricsCoreOnly_DisablesAllAutoMetrics(t *testing.T) {
	metric1 := &testAutoMetric{
		name:    "test_metric_1",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_1",
		},
	}
	metric2 := &testAutoMetric{
		name:    "test_metric_2",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_2",
		},
	}
	metric3 := &testAutoMetric{
		name:    "test_metric_3",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_3",
		},
	}

	params := RegistryParams{
		DaemonConfig: &option.DaemonConfig{
			MetricsCoreOnly: true,
		},
		Config: RegistryConfig{
			PrometheusServeAddr: "",
			Metrics:             []string{},
		},
		AutoMetrics: []metricpkg.WithMetadata{metric1, metric2, metric3},
	}

	reg := NewRegistry(params)
	require.NotNil(t, reg)
	reg.registerMetrics()

	require.False(t, metric1.IsEnabled(), "metric1 should be disabled when MetricsCoreOnly is true")
	require.False(t, metric2.IsEnabled(), "metric2 should be disabled when MetricsCoreOnly is true")
	require.False(t, metric3.IsEnabled(), "metric3 should be disabled when MetricsCoreOnly is true")
}

// TestMetricsCoreOnly_WithExplicitEnable verifies that explicitly enabled metrics
// continue to be registered even when metrics-core-only is enabled.
func TestMetricsCoreOnly_WithExplicitEnable(t *testing.T) {
	metric1 := &testAutoMetric{
		name:    "test_metric_1",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_1",
		},
	}
	metric2 := &testAutoMetric{
		name:    "test_metric_2",
		enabled: true,
		opts: metricpkg.Opts{
			ConfigName: "cilium_test_metric_2",
		},
	}

	params := RegistryParams{
		DaemonConfig: &option.DaemonConfig{
			MetricsCoreOnly: true,
		},
		Config: RegistryConfig{
			PrometheusServeAddr: "",
			Metrics: []string{
				"+cilium_test_metric_1",
			},
		},
		AutoMetrics: []metricpkg.WithMetadata{metric1, metric2},
	}

	reg := NewRegistry(params)
	require.NotNil(t, reg)
	reg.registerMetrics()

	require.True(t, metric1.IsEnabled(), "metric1 should be enabled due to explicit +cilium_test_metric_1")
	require.False(t, metric2.IsEnabled(), "metric2 should remain disabled when MetricsCoreOnly is true")
}

