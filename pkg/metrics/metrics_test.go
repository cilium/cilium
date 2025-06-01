// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

func TestGaugeWithThreshold(t *testing.T) {
	logger := hivetest.Logger(t)
	threshold := 1.0
	underThreshold := threshold - 0.5
	overThreshold := threshold + 0.5
	reg := NewRegistry(RegistryParams{
		Logger:       logger,
		DaemonConfig: &option.DaemonConfig{},
	})

	gauge := reg.NewGaugeWithThreshold(
		"test_metric",
		"test_subsystem",
		"test_metric",
		map[string]string{
			"test_label": "test_value",
		},
		threshold,
	)

	metrics, err := reg.inner.Gather()
	require.NoError(t, err)
	initMetricLen := len(metrics)

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, underThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen+1)
	require.Equal(t, overThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(threshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, threshold, GetGaugeValue(gauge.gauge))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen+1)
	require.Equal(t, overThreshold, GetGaugeValue(gauge.gauge))

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, initMetricLen)
	require.Equal(t, underThreshold, GetGaugeValue(gauge.gauge))
}
