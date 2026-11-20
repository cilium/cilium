// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestIsSupportedPressureMapType(t *testing.T) {
	assert.True(t, isSupportedPressureMapType(ebpf.Hash))
	assert.True(t, isSupportedPressureMapType(ebpf.LRUHash))
	assert.False(t, isSupportedPressureMapType(ebpf.LPMTrie))
	assert.False(t, isSupportedPressureMapType(ebpf.HashOfMaps))
	assert.False(t, isSupportedPressureMapType(ebpf.Array))
}

func TestPrivilegedPressureMetrics(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS(hivetest.Logger(t), "")

	sockRevNatMap := NewSockRevNat4Map(10)
	require.NoError(t, sockRevNatMap.CreateUnpinned())
	t.Cleanup(func() { sockRevNatMap.Close() })

	svcMap := NewService4Map(10)
	require.NoError(t, svcMap.CreateUnpinned())
	t.Cleanup(func() { svcMap.Close() })

	srcRangeMap := NewSourceRange4Map(10)
	require.NoError(t, srcRangeMap.CreateUnpinned())
	t.Cleanup(func() { srcRangeMap.Close() })

	bpfMaps := &BPFLBMaps{
		openMaps: []*bpf.Map{sockRevNatMap, svcMap, srcRangeMap},
	}

	reg := metrics.NewAgentRegistry(metrics.RegistryParams{
		Logger:       hivetest.Logger(t),
		DaemonConfig: &option.DaemonConfig{},
	})
	pm := &pressureMetrics{
		pressureMetricsParams: pressureMetricsParams{
			MetricsRegistry: reg,
		},
		bpfMaps: bpfMaps,
		gauges:  map[string]*metrics.GaugeWithThreshold{},
	}

	key := NewSockRevNat4Key(1234, netip.MustParseAddr("10.0.0.1"), 80)
	val := SockRevNat4Value{
		Address:     key.Address,
		Port:        key.Port,
		RevNatIndex: 1,
	}
	require.NoError(t, sockRevNatMap.Update(key, &val))

	require.NoError(t, pm.report(context.Background()))

	require.Contains(t, pm.gauges, "lb4_reverse_sk")
	require.Contains(t, pm.gauges, "lb4_services_v2")
	assert.NotContains(t, pm.gauges, "lb4_source_range")
}
