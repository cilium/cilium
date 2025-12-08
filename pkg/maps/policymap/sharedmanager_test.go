// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/ebpf/rlimit"
)

// resetSharedManagerForTest clears the singleton so each test starts from a
// clean slate.
func resetSharedManagerForTest() {
	sharedMgrOnce = sync.Once{}
	sharedMgr = nil
}

func TestSyncEndpointOverlayStoresOverrides(t *testing.T) {
	// 1. Setup options

	option.Config.PolicySharedMapMaxSharedRefs = 4
	option.Config.PolicySharedMapMaxPrivateOverrides = 4
	option.Config.EnablePolicySharedMapArena = true

	// 2. Initialize Real Arena Map (Requires Root)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("Failed to remove memlock rlimit: %v", err)
	}
	cleanup := setupRestartTestArena(t)
	defer cleanup()
	mgr := getSharedManager()

	seq := func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		key := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, 80)
		key.Identity = 128
		yield(key, policyTypes.AllowEntry())
	}

	// Mock BPF map operations
	oldUpdateOverlay := updateOverlayPolicyEntry
	oldDeleteOverlay := deleteOverlayPolicyEntry
	defer func() {
		updateOverlayPolicyEntry = oldUpdateOverlay
		deleteOverlayPolicyEntry = oldDeleteOverlay
	}()

	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }
	deleteOverlayPolicyEntry = func(epID uint16) error { return nil }

	_, err := SyncEndpointOverlay(10, seq, true, true)
	require.NoError(t, err)

	overlay, ok := OverlaySnapshot(10)
	require.True(t, ok)
	require.Equal(t, uint8(1), overlay.SharedRefCount)
	require.Equal(t, uint8(0), overlay.PrivateCount)

	mgr.allocator.mu.Lock()
	count, exists := mgr.allocator.refcount[overlay.SharedRefs[0]]
	mgr.allocator.mu.Unlock()
	require.True(t, exists)
	require.Equal(t, 1, count)

	RemoveEndpointOverlay(10)
	_, still := OverlaySnapshot(10)
	require.False(t, still)
}
