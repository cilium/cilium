// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

var lastMmapAddr uint64

// setupRestartTestArena creates a test arena and configures the shared manager.
// Returns a cleanup function that must be deferred.
func setupRestartTestArena(t *testing.T) func() {
	option.Config.PolicySharedMapMaxSharedRefs = 16
	option.Config.PolicySharedMapMaxPrivateOverrides = 8
	option.Config.EnablePolicySharedMapArena = true

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("Failed to remove memlock rlimit: %v", err)
	}

	// 1. Create Arena Map
	maxPages := uint32(512)
	innerArena, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Name:       "cilium_test_a",
		Type:       ciliumebpf.MapType(33), // BPF_MAP_TYPE_ARENA
		MaxEntries: maxPages,
		Flags:      1 << 10, // BPF_F_MMAPABLE
	})
	if err != nil {
		t.Fatalf("Failed to create arena map: %v", err)
	}
	arenaMap = &ebpf.Map{Map: innerArena}

	// 2. Create Shared LPM Map
	innerLPM, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Name:       "cilium_test_s",
		Type:       ciliumebpf.LPMTrie,
		KeySize:    16, // sizeof(SharedLPMKey)
		ValueSize:  8,  // sizeof(SharedLPMValue)
		MaxEntries: 1024,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Fatalf("Failed to create shared LPM map: %v", err)
	}
	sharedLPMMap = &ebpf.Map{Map: innerLPM}

	// 3. Mmap the arena
	pageSize := os.Getpagesize()
	size := int(maxPages) * pageSize
	addr := uintptr(0x20000000000) // Different from prod to avoid collision
	r, _, errno := unix.Syscall6(unix.SYS_MMAP,
		addr,
		uintptr(size),
		uintptr(unix.PROT_READ|unix.PROT_WRITE),
		uintptr(unix.MAP_SHARED|unix.MAP_FIXED),
		uintptr(innerArena.FD()),
		0,
	)
	if errno != 0 {
		t.Fatalf("Failed to mmap arena: %v", errno)
	}
	lastMmapAddr = uint64(r)

	// 4. Initialize Arena Allocator and Shared Manager manually
	slogger := logging.DefaultSlogLogger.With("subsys", "policymap-test")
	alloc, err := NewArenaAllocatorForTest(slogger, arenaMap, lastMmapAddr)
	if err != nil {
		t.Fatalf("Failed to create arena allocator: %v", err)
	}

	sharedMgr = &sharedManager{
		overlays:        make(map[uint16]OverlayEntryBPF),
		spilloverCounts: make(map[uint16]int),
		ruleSetIDs:      make(map[uint16]uint32),
		allocator:       NewRuleSetAllocator(1024, alloc),
		maxShared:       16,
		maxPrivate:      8,
	}
	sharedMgrOnce.Do(func() {}) // Mark as initialized

	// Mock BPF map operations
	updateOverlayPolicyEntry = func(epID uint16, overlay OverlayEntryBPF) error { return nil }
	deleteOverlayPolicyEntry = func(epID uint16) error { return nil }

	return func() {
		option.Config.EnablePolicySharedMapArena = false
		sharedMgrOnce = sync.Once{}
		sharedMgr = nil
		if arenaMap != nil {
			arenaMap.Close()
			arenaMap = nil
		}
		if sharedLPMMap != nil {
			sharedLPMMap.Close()
			sharedLPMMap = nil
		}
		unix.Syscall(unix.SYS_MUNMAP, r, uintptr(size), 0)
	}
}

// makeRestartRuleSeq creates a rule sequence from port numbers.
func makeRestartRuleSeq(ports ...uint16) func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
	return func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		for _, port := range ports {
			key := policyTypes.KeyForDirection(trafficdirection.Ingress).WithPortProto(u8proto.TCP, port)
			key.Identity = 100
			if !yield(key, policyTypes.AllowEntry()) {
				return
			}
		}
	}
}

// simulateAgentRestart resets the Go-side state while preserving overlay data.
// This simulates what happens during agent restart when BPF maps are pinned
// but Go state is lost.
func simulateAgentRestart(t *testing.T, overlays map[uint16]OverlayEntryBPF) {
	// Reset Go-side state (simulates agent process restart)
	sharedMgrOnce = sync.Once{}
	sharedMgr = nil

	// Re-initialize shared manager manually to bypass discovery
	slogger := logging.DefaultSlogLogger.With("subsys", "policymap-test-rst")
	alloc, err := NewArenaAllocatorForTest(slogger, arenaMap, lastMmapAddr)
	if err != nil {
		t.Fatalf("Failed to create arena allocator during restart: %v", err)
	}

	sharedMgr = &sharedManager{
		overlays:        make(map[uint16]OverlayEntryBPF),
		spilloverCounts: make(map[uint16]int),
		ruleSetIDs:      make(map[uint16]uint32),
		allocator:       NewRuleSetAllocator(1024, alloc),
		maxShared:       16,
		maxPrivate:      8,
	}
	sharedMgrOnce.Do(func() {})

	// Restore overlays from "pinned" map (simulated by the overlays parameter)
	for epID, overlay := range overlays {
		RestoreEndpointOverlay(epID, overlay)
	}

	t.Logf("Agent restart simulated: restored %d endpoint overlays", len(overlays))
	sharedMgr.allocator.mu.Lock()
	t.Logf("Allocator state: nextRuleSetID=%d, refcount entries=%d",
		sharedMgr.allocator.nextRuleSetID, len(sharedMgr.allocator.refcount))
	sharedMgr.allocator.mu.Unlock()
}

// TestRestart_BasicOverlayRestore tests that overlay state is correctly restored
// after agent restart.
func TestRestart_BasicOverlayRestore(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create initial state (before restart)
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80, 443), true, true)
	require.NoError(t, err)

	overlay, ok := OverlaySnapshot(701)
	require.True(t, ok)
	ruleSetID := overlay.SharedRefs[0]
	require.NotZero(t, ruleSetID)

	// Save overlay data (simulates pinned BPF map)
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay,
	}

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Step 3: Verify state is restored
	restoredOverlay, ok := OverlaySnapshot(701)
	require.True(t, ok, "overlay should be restored after restart")
	require.Equal(t, ruleSetID, restoredOverlay.SharedRefs[0],
		"rule_set_id should be preserved")

	// Verify refcount is restored
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	refcount := mgr.allocator.refcount[ruleSetID]
	mgr.allocator.mu.Unlock()
	require.Equal(t, 1, refcount, "refcount should be restored to 1")
}

// TestRestart_SharedRefcountRestore tests that shared rule sets have correct
// refcounts restored when multiple endpoints share the same policy.
func TestRestart_SharedRefcountRestore(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create two endpoints sharing the same policy
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80, 443), true, true)
	require.NoError(t, err)

	_, err = SyncEndpointOverlay(702, makeRestartRuleSeq(80, 443), true, true)
	require.NoError(t, err)

	overlay1, _ := OverlaySnapshot(701)
	overlay2, _ := OverlaySnapshot(702)
	ruleSetID := overlay1.SharedRefs[0]

	// Verify they share the same rule_set_id
	require.Equal(t, ruleSetID, overlay2.SharedRefs[0])

	// Verify initial refcount is 2
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	initialRefcount := mgr.allocator.refcount[ruleSetID]
	mgr.allocator.mu.Unlock()
	require.Equal(t, 2, initialRefcount)

	// Save overlay data
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay1,
		702: overlay2,
	}

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Step 3: Verify refcount is correctly restored
	mgr = sharedMgr
	mgr.allocator.mu.Lock()
	restoredRefcount := mgr.allocator.refcount[ruleSetID]
	mgr.allocator.mu.Unlock()
	require.Equal(t, 2, restoredRefcount,
		"refcount should be restored to 2 for shared rule_set")
}

// TestRestart_NextRuleSetIDCollision tests that new rule_set_id allocations
// after restart don't collide with restored IDs.
func TestRestart_NextRuleSetIDCollision(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create initial state
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80), true, true)
	require.NoError(t, err)

	overlay, _ := OverlaySnapshot(701)
	restoredID := overlay.SharedRefs[0]

	// Save overlay data
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay,
	}

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Step 3: Add a NEW endpoint with DIFFERENT policy
	_, err = SyncEndpointOverlay(702, makeRestartRuleSeq(8080), true, true)
	require.NoError(t, err)

	newOverlay, _ := OverlaySnapshot(702)
	newID := newOverlay.SharedRefs[0]

	// Verify no collision
	require.NotEqual(t, restoredID, newID,
		"new rule_set_id should not collide with restored ID")

	// Verify nextRuleSetID was advanced correctly
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	nextID := mgr.allocator.nextRuleSetID
	mgr.allocator.mu.Unlock()
	require.Greater(t, nextID, restoredID,
		"nextRuleSetID should be greater than restored IDs")
	require.Greater(t, nextID, newID,
		"nextRuleSetID should be greater than newly allocated ID")
}

// TestRestart_PolicyChangeAfterRestore tests that policy can be changed
// after restart and refcounts update correctly.
func TestRestart_PolicyChangeAfterRestore(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create initial state
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80), true, true)
	require.NoError(t, err)

	overlay, _ := OverlaySnapshot(701)
	oldRuleSetID := overlay.SharedRefs[0]

	// Save overlay data
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay,
	}

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Verify old rule_set_id is tracked
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	require.Equal(t, 1, mgr.allocator.refcount[oldRuleSetID])
	mgr.allocator.mu.Unlock()

	// Step 3: Change policy (different ports)
	_, err = SyncEndpointOverlay(701, makeRestartRuleSeq(443, 8443), true, true)
	require.NoError(t, err)

	// Step 4: Verify old rule_set is released, new one created
	newOverlay, _ := OverlaySnapshot(701)
	newRuleSetID := newOverlay.SharedRefs[0]

	require.NotEqual(t, oldRuleSetID, newRuleSetID,
		"rule_set_id should change after policy change")

	mgr.allocator.mu.Lock()
	oldRefcount := mgr.allocator.refcount[oldRuleSetID]
	newRefcount := mgr.allocator.refcount[newRuleSetID]
	mgr.allocator.mu.Unlock()

	require.Equal(t, 0, oldRefcount, "old rule_set should be released")
	require.Equal(t, 1, newRefcount, "new rule_set should have refcount 1")
}

// TestRestart_RemoveEndpointAfterRestore tests that endpoints can be removed
// after restart and refcounts update correctly.
func TestRestart_RemoveEndpointAfterRestore(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create two endpoints sharing policy
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80), true, true)
	require.NoError(t, err)

	_, err = SyncEndpointOverlay(702, makeRestartRuleSeq(80), true, true)
	require.NoError(t, err)

	overlay1, _ := OverlaySnapshot(701)
	overlay2, _ := OverlaySnapshot(702)
	ruleSetID := overlay1.SharedRefs[0]

	// Save overlay data
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay1,
		702: overlay2,
	}

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Verify refcount is 2
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	require.Equal(t, 2, mgr.allocator.refcount[ruleSetID])
	mgr.allocator.mu.Unlock()

	// Step 3: Remove one endpoint
	RemoveEndpointOverlay(701)

	// Verify refcount decreased
	mgr.allocator.mu.Lock()
	require.Equal(t, 1, mgr.allocator.refcount[ruleSetID],
		"refcount should decrease when endpoint removed")
	mgr.allocator.mu.Unlock()

	// Step 4: Remove remaining endpoint
	RemoveEndpointOverlay(702)

	mgr.allocator.mu.Lock()
	require.Equal(t, 0, mgr.allocator.refcount[ruleSetID],
		"refcount should be 0 when all endpoints removed")
	mgr.allocator.mu.Unlock()
}

// TestRestart_ManyEndpoints tests restart with many endpoints to verify
// scalability of the restore process.
func TestRestart_ManyEndpoints(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	const numEndpoints = 50

	// Step 1: Create many endpoints with various policies
	savedOverlays := make(map[uint16]OverlayEntryBPF)

	for i := 0; i < numEndpoints; i++ {
		epID := uint16(700 + i)
		// Alternate between a few different policies to test deduplication
		port := uint16(80 + (i % 5))
		_, err := SyncEndpointOverlay(epID, makeRestartRuleSeq(port), true, true)
		require.NoError(t, err)

		overlay, ok := OverlaySnapshot(epID)
		require.True(t, ok)
		savedOverlays[epID] = overlay
	}

	// Count unique rule_set_ids before restart
	uniqueIDs := make(map[uint32]int)
	for _, overlay := range savedOverlays {
		if overlay.SharedRefCount > 0 {
			uniqueIDs[overlay.SharedRefs[0]]++
		}
	}
	t.Logf("Before restart: %d endpoints, %d unique rule_sets", numEndpoints, len(uniqueIDs))

	// Step 2: Simulate agent restart
	simulateAgentRestart(t, savedOverlays)

	// Step 3: Verify all overlays are restored
	for epID := range savedOverlays {
		_, ok := OverlaySnapshot(epID)
		require.True(t, ok, "endpoint %d overlay should be restored", epID)
	}

	// Step 4: Verify refcounts match
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	for ruleSetID, expectedCount := range uniqueIDs {
		actualCount := mgr.allocator.refcount[ruleSetID]
		require.Equal(t, expectedCount, actualCount,
			"refcount mismatch for rule_set_id %d", ruleSetID)
	}
	mgr.allocator.mu.Unlock()
}

// TestRestart_EmptyOverlay tests restart with an endpoint that has no policies.
func TestRestart_EmptyOverlay(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Create empty overlay (endpoint exists but no policy)
	emptySeq := func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {}

	_, err := SyncEndpointOverlay(701, emptySeq, true, true)
	require.NoError(t, err)

	overlay, ok := OverlaySnapshot(701)
	require.True(t, ok)

	// Save and restart
	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay,
	}

	simulateAgentRestart(t, savedOverlays)

	// Verify empty overlay is restored
	restoredOverlay, ok := OverlaySnapshot(701)
	require.True(t, ok, "empty overlay should be restored")
	require.Equal(t, overlay.SharedRefCount, restoredOverlay.SharedRefCount)
}

// TestRestart_MultipleRestarts tests multiple consecutive agent restarts.
func TestRestart_MultipleRestarts(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Step 1: Create initial state
	_, err := SyncEndpointOverlay(701, makeRestartRuleSeq(80), true, true)
	require.NoError(t, err)

	overlay, _ := OverlaySnapshot(701)
	ruleSetID := overlay.SharedRefs[0]

	// Multiple restart cycles
	for cycle := 1; cycle <= 3; cycle++ {
		savedOverlays := map[uint16]OverlayEntryBPF{
			701: overlay,
		}

		simulateAgentRestart(t, savedOverlays)

		// Verify state after each restart
		restoredOverlay, ok := OverlaySnapshot(701)
		require.True(t, ok, "overlay should be restored after cycle %d", cycle)
		require.Equal(t, ruleSetID, restoredOverlay.SharedRefs[0],
			"rule_set_id should be preserved after cycle %d", cycle)

		mgr := sharedMgr
		mgr.allocator.mu.Lock()
		refcount := mgr.allocator.refcount[ruleSetID]
		mgr.allocator.mu.Unlock()
		require.Equal(t, 1, refcount, "refcount should be 1 after cycle %d", cycle)

		// Update overlay for next cycle
		overlay = restoredOverlay
	}
}

// TestRestart_HighRuleSetID tests restore with a high rule_set_id to verify
// nextRuleSetID is set correctly.
func TestRestart_HighRuleSetID(t *testing.T) {
	cleanup := setupRestartTestArena(t)
	defer cleanup()

	// Create a fake overlay with a high rule_set_id (simulates long-running cluster)
	// Must be less than MaxRuleSets (4096)
	highID := uint32(4000)
	overlay := OverlayEntryBPF{
		SharedRefCount: 1,
	}
	overlay.SharedRefs[0] = highID

	savedOverlays := map[uint16]OverlayEntryBPF{
		701: overlay,
	}

	// Restore with high ID
	simulateAgentRestart(t, savedOverlays)

	// Verify nextRuleSetID is set correctly
	mgr := sharedMgr
	mgr.allocator.mu.Lock()
	nextID := mgr.allocator.nextRuleSetID
	mgr.allocator.mu.Unlock()

	require.GreaterOrEqual(t, nextID, highID+1,
		"nextRuleSetID should be at least highID+1")

	// Allocate a new rule_set and verify no collision
	_, err := SyncEndpointOverlay(702, makeRestartRuleSeq(8080), true, true)
	require.NoError(t, err)

	newOverlay, _ := OverlaySnapshot(702)
	newID := newOverlay.SharedRefs[0]

	require.Greater(t, newID, highID, "new ID should be greater than restored high ID")
}
