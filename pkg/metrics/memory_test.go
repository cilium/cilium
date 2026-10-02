// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"runtime"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestGoRuntimeInUseBytes(t *testing.T) {
	assert.NotZero(t, goRuntimeInUseBytes())
}

func TestPrivilegedAgentMemoryCollectorCollect(t *testing.T) {
	testutils.PrivilegedTest(t)
	if runtime.GOOS != "linux" {
		t.Skip("requires linux")
	}

	collector := newAgentMemoryCollector(hivetest.Logger(t))
	ch := make(chan prometheus.Metric, len(agentMemoryComponents))
	collector.Collect(ch)
	close(ch)

	got := make(map[string]float64, len(agentMemoryComponents))
	for metric := range ch {
		dm, err := metricToDTO(metric)
		require.NoError(t, err)
		require.Len(t, dm.Label, 1)
		got[dm.Label[0].GetValue()] = dm.GetGauge().GetValue()
	}

	for _, component := range agentMemoryComponents {
		value, ok := got[component]
		require.True(t, ok, "missing component %s", component)
		assert.GreaterOrEqual(t, value, float64(0), "component %s", component)
	}

	assert.Equal(t, got["go"]+got["bpf_maps"]+got["bpf_progs"], got["total"])
}

func metricToDTO(metric prometheus.Metric) (*dto.Metric, error) {
	var dm dto.Metric
	if err := metric.Write(&dm); err != nil {
		return nil, err
	}
	return &dm, nil
}
