// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestPolicySharedMapMetrics(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	t.Cleanup(func() {
		cleanup()
		option.Config.EnablePolicySharedMapArena = false
		resetSharedManagerForTest()
	})

	option.Config.EnablePolicySharedMapArena = true
	// Limit shared refs to 1 to force spillover
	option.Config.PolicySharedMapMaxSharedRefs = 1
	option.Config.PolicySharedMapMaxPrivateOverrides = 4

	// Overwrite global metric to ensure it is enabled and fresh
	metrics.PolicySharedMapEntries = metric.NewGaugeVecWithLabels(metric.GaugeOpts{
		Name:     "test_shared_map_entries",
		Disabled: false,
	}, metric.Labels{
		{
			Name: metrics.LabelSharedMapType,
			Values: metric.NewValues(
				metrics.LabelSharedMapSpillover,
				metrics.LabelSharedMapPriv,
				metrics.LabelSharedMapOne,
			),
		},
	})
	metrics.PolicySharedMapEntries.SetEnabled(true)

	// Overwrite Ops metric
	metrics.PolicySharedMapOps = metric.NewCounterVecWithLabels(metric.CounterOpts{
		Name:     "test_shared_map_ops",
		Disabled: false,
	}, metric.Labels{
		{Name: metrics.LabelOperation, Values: metric.NewValues("lookup", "add", "delete")},
		{Name: metrics.LabelOutcome, Values: metric.NewValues(metrics.LabelValueOutcomeSuccess, metrics.LabelValueOutcomeFail)},
	})
	metrics.PolicySharedMapOps.SetEnabled(true)

	// Mock BPF ops
	oldUpdateOverlay := updateOverlayPolicyEntry
	oldDeleteOverlay := deleteOverlayPolicyEntry
	defer func() {
		updateOverlayPolicyEntry = oldUpdateOverlay
		deleteOverlayPolicyEntry = oldDeleteOverlay
	}()
	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }
	deleteOverlayPolicyEntry = func(epID uint16) error { return nil }

	// Get initial metrics
	spilloverGauge := metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapSpillover)
	initialSpillover := spilloverGauge.Get()

	opsAdd := metrics.PolicySharedMapOps.WithLabelValues("add", metrics.LabelValueOutcomeSuccess)
	opsDelete := metrics.PolicySharedMapOps.WithLabelValues("delete", metrics.LabelValueOutcomeSuccess)

	initialAdds := opsAdd.Get()
	initialDeletes := opsDelete.Get()

	// 1. Sync Endpoint with 2 rules. Quota is 1. One should spillover.
	// We need 2 DIFFERENT shared rules.
	seq := func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		// Rule 1: Port 80
		key1 := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, 80)
		key1.Identity = 100
		if !yield(key1, policyTypes.AllowEntry()) {
			return
		}
		// Rule 2: Port 81
		key2 := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, 81)
		key2.Identity = 101
		yield(key2, policyTypes.AllowEntry())
	}

	_, err := SyncEndpointOverlay(999, seq, true, true)
	require.NoError(t, err)

	// Verify Spillover Metric is 0 (Phase 3 aggregates into 1 handle < Limit 1)
	newSpillover := spilloverGauge.Get()
	require.Equal(t, float64(0), newSpillover-initialSpillover, "Spillover metric should be 0 in Phase 3")

	// Verify Ops: 0 Store Ops (Phase 3 bypasses SharedStore)
	require.Equal(t, float64(0), opsAdd.Get()-initialAdds, "Phase 3 bypasses SharedStore Ops")

	// Verify Overlay state
	mgr := getSharedManager()
	require.Equal(t, 0, mgr.spilloverCounts[999], "Spillover count in implementation should be 0")

	// 2. Remove Endpoint
	RemoveEndpointOverlay(999)

	// Verify Spillover Metric unchanged
	finalSpillover := spilloverGauge.Get()
	require.Equal(t, initialSpillover, finalSpillover, "Spillover metric should be unchanged")

	// Verify Ops: 0 Delete
	require.Equal(t, float64(0), opsDelete.Get()-initialDeletes, "Phase 3 bypasses SharedStore Ops")
}
