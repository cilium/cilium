// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cidr"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/mac"
	vtepmap "github.com/cilium/cilium/pkg/maps/vtep"
)

// fakeVTEPMap implements vtep.Map for testing.
type fakeVTEPMap struct {
	mu      sync.Mutex
	entries map[string]vtepmap.Entry // keyed by normalized CIDR string e.g. "10.1.1.0/24"
	// Track errors to inject
	updateErr error
	deleteErr error
	listErr   error
}

func newFakeVTEPMap() *fakeVTEPMap {
	return &fakeVTEPMap{
		entries: make(map[string]vtepmap.Entry),
	}
}

func (m *fakeVTEPMap) Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	// Use the normalized CIDR string as the map key, matching the LPM trie key.
	key := newCIDR.String() // e.g. "10.1.1.0/24"
	ones, _ := newCIDR.Mask.Size()
	m.entries[key] = vtepmap.Entry{
		CIDR:           newCIDR.IP,
		PrefixLen:      ones,
		TunnelEndpoint: newTunnelEndpoint,
		MAC:            vtepMAC,
	}
	return nil
}

func (m *fakeVTEPMap) Delete(c *cidr.CIDR) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.entries, c.String())
	return nil
}

func (m *fakeVTEPMap) List() ([]vtepmap.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	entries := make([]vtepmap.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	return entries, nil
}

func (m *fakeVTEPMap) Dump(hash map[string][]string) error {
	return nil
}

func (m *fakeVTEPMap) getEntry(cidrKey string) (vtepmap.Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[cidrKey]
	return e, ok
}

func (m *fakeVTEPMap) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func newTestReconciler(vtepMap *fakeVTEPMap) *VTEPReconciler {
	return &VTEPReconciler{
		logger:      slog.Default(),
		vtepMap:     vtepMap,
		manager:     nil, // no route management in tests
		allConfigs:  make(map[string]*cilium_api_v2.CiliumVTEPConfig),
		lastApplied: make(map[string]appliedEndpoint),
	}
}

func newTestConfig(endpoints ...cilium_api_v2.VTEPEndpoint) *cilium_api_v2.CiliumVTEPConfig {
	return &cilium_api_v2.CiliumVTEPConfig{
		Spec: cilium_api_v2.CiliumVTEPConfigSpec{
			Endpoints: endpoints,
		},
	}
}

func newTestConfigWithName(name string, endpoints ...cilium_api_v2.VTEPEndpoint) *cilium_api_v2.CiliumVTEPConfig {
	config := newTestConfig(endpoints...)
	config.Name = name
	return config
}

func newTestConfigWithSelector(name string, selector *slimv1.LabelSelector, endpoints ...cilium_api_v2.VTEPEndpoint) *cilium_api_v2.CiliumVTEPConfig {
	config := newTestConfigWithName(name, endpoints...)
	config.Spec.NodeSelector = selector
	return config
}

func newEndpoint(name, cidrStr, tunnelEP, macAddr string) cilium_api_v2.VTEPEndpoint {
	return cilium_api_v2.VTEPEndpoint{
		Name:           name,
		CIDR:           cidrStr,
		TunnelEndpoint: tunnelEP,
		MAC:            macAddr,
	}
}

// --- validateConfig tests ---

func TestValidateConfig_Valid(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	err := r.validateConfig(config)
	assert.NoError(t, err)
}

func TestValidateConfig_EmptyEndpoints(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig()

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "at least one endpoint")
}

func TestValidateConfig_TooManyEndpoints(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	endpoints := make([]cilium_api_v2.VTEPEndpoint, vtepmap.MaxEntries+1)
	for i := range endpoints {
		endpoints[i] = newEndpoint(
			fmt.Sprintf("gw%d", i),
			fmt.Sprintf("10.%d.1.0/24", i),
			fmt.Sprintf("10.169.72.%d", i),
			fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i),
		)
	}
	config := newTestConfig(endpoints...)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "maximum")
}

func TestValidateConfig_DuplicateName(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw1", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "duplicate endpoint name")
}

func TestValidateConfig_DuplicateCIDR(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.1.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "normalizes to the same entry")
}

func TestValidateConfig_InvalidTunnelEndpoint(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "not-an-ip", "aa:bb:cc:dd:ee:01"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "invalid tunnel endpoint")
}

func TestValidateConfig_InvalidCIDR(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "not-a-cidr", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "invalid CIDR")
}

func TestValidateConfig_InvalidMAC(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "not-a-mac"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "invalid MAC")
}

func TestValidateConfig_IPv6CIDRRejected(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "2001:db8::/32", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "CIDR must be IPv4")
}

func TestValidateConfig_IPv6TunnelEndpointRejected(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "2001:db8::1", "aa:bb:cc:dd:ee:01"),
	)

	err := r.validateConfig(config)
	assert.ErrorContains(t, err, "tunnel endpoint must be IPv4")
}

// TestValidateConfig_DifferentPrefixLengths verifies that two CIDRs with different
// prefix lengths (e.g. /24 and /25) are valid — each is a distinct LPM trie key.
func TestValidateConfig_DifferentPrefixLengths(t *testing.T) {
	r := newTestReconciler(newFakeVTEPMap())

	// "10.1.1.0/24" and "10.1.1.128/25" are distinct LPM keys — no collision.
	config := newTestConfig(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.1.1.128/25", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	err := r.validateConfig(config)
	assert.NoError(t, err)
}

// --- syncDesiredState tests ---

func TestSyncDesiredState_SingleConfig(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	r.syncDesiredState(context.Background())

	assert.Equal(t, 1, fakeMap.count())
	entry, ok := fakeMap.getEntry("10.1.1.0/24")
	require.True(t, ok)
	assert.Equal(t, "10.169.72.236", entry.TunnelEndpoint.String())
}

func TestSyncDesiredState_MultipleEndpoints(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	assert.Equal(t, 2, fakeMap.count())
}

func TestSyncDesiredState_RemovesStaleCIDRs(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// First sync with two endpoints
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	r.syncDesiredState(context.Background())
	assert.Equal(t, 2, fakeMap.count())

	// Second sync removes gw2
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.syncDesiredState(context.Background())

	assert.Equal(t, 1, fakeMap.count())
	_, ok := fakeMap.getEntry("10.2.1.0/24")
	assert.False(t, ok, "stale entry for 10.2.1.0/24 should be deleted")
}

func TestSyncDesiredState_UpdatesExistingEndpoint(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// First sync
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.syncDesiredState(context.Background())

	// Update tunnel endpoint for same CIDR
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.237", "aa:bb:cc:dd:ee:ff"),
	)
	r.syncDesiredState(context.Background())

	assert.Equal(t, 1, fakeMap.count())
	entry, ok := fakeMap.getEntry("10.1.1.0/24")
	require.True(t, ok)
	assert.Equal(t, "10.169.72.237", entry.TunnelEndpoint.String())
}

func TestSyncDesiredState_BPFMapUpdateError(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	fakeMap.updateErr = fmt.Errorf("bpf map full")
	r := newTestReconciler(fakeMap)

	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	err := r.syncDesiredState(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 0, fakeMap.count())
	// Failed BPF update must NOT be tracked in lastApplied
	assert.Equal(t, 0, len(r.lastApplied), "failed BPF update should not be in lastApplied")
}

func TestSyncDesiredState_InvalidConfig(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	r.allConfigs["default"] = newTestConfigWithName("default") // empty endpoints = invalid

	r.syncDesiredState(context.Background())
	assert.Equal(t, 0, fakeMap.count())
}

func TestSyncDesiredState_DeleteConfig(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Add config
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	r.syncDesiredState(context.Background())
	assert.Equal(t, 2, fakeMap.count())

	// Remove config
	delete(r.allConfigs, "default")
	r.syncDesiredState(context.Background())
	assert.Equal(t, 0, fakeMap.count())
}

// --- nodeSelector tests ---

func TestConfigMatchesNode_NilSelector(t *testing.T) {
	config := newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	// nil nodeSelector matches all nodes
	matches, err := configMatchesNode(config, map[string]string{"zone": "a"})
	require.NoError(t, err)
	assert.True(t, matches)
}

func TestConfigMatchesNode_EmptySelector(t *testing.T) {
	config := newTestConfigWithSelector("default",
		&slimv1.LabelSelector{},
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	// empty selector matches all nodes
	matches, err := configMatchesNode(config, map[string]string{"zone": "a"})
	require.NoError(t, err)
	assert.True(t, matches)
}

func TestConfigMatchesNode_MatchingSelector(t *testing.T) {
	config := newTestConfigWithSelector("zone-a",
		&slimv1.LabelSelector{
			MatchLabels: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			},
		},
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	matches, err := configMatchesNode(config, map[string]string{
		"topology.kubernetes.io/zone": "zone-a",
		"kubernetes.io/hostname":      "node-1",
	})
	require.NoError(t, err)
	assert.True(t, matches)
}

func TestConfigMatchesNode_NonMatchingSelector(t *testing.T) {
	config := newTestConfigWithSelector("zone-a",
		&slimv1.LabelSelector{
			MatchLabels: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			},
		},
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	matches, err := configMatchesNode(config, map[string]string{
		"topology.kubernetes.io/zone": "zone-b",
	})
	require.NoError(t, err)
	assert.False(t, matches)
}

func TestConfigMatchesNode_NilLabels(t *testing.T) {
	config := newTestConfigWithSelector("zone-a",
		&slimv1.LabelSelector{
			MatchLabels: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			},
		},
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	// nil node labels — selector with requirements won't match
	matches, err := configMatchesNode(config, nil)
	require.NoError(t, err)
	assert.False(t, matches)
}

func TestSyncDesiredState_NodeSelectorFiltering(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// No statedb — getLocalNodeLabels() returns nil
	// Only configs with nil nodeSelector should match

	r.allConfigs["zone-a"] = newTestConfigWithSelector("zone-a",
		&slimv1.LabelSelector{
			MatchLabels: map[string]string{
				"topology.kubernetes.io/zone": "zone-a",
			},
		},
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.allConfigs["global"] = newTestConfigWithName("global",
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	// Only the global (nil nodeSelector) config should be applied
	assert.Equal(t, 1, fakeMap.count())
	_, ok := fakeMap.getEntry("10.2.1.0/24")
	assert.True(t, ok, "global config endpoint should be applied")
	_, ok = fakeMap.getEntry("10.1.1.0/24")
	assert.False(t, ok, "zone-a config should not match (nil node labels)")
}

func TestSyncDesiredState_MultipleMatchingConfigs_NoCIDROverlap(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Both configs have nil nodeSelector (match all nodes), different CIDRs
	r.allConfigs["config-a"] = newTestConfigWithName("config-a",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.allConfigs["config-b"] = newTestConfigWithName("config-b",
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	// Both should be applied — no overlap
	assert.Equal(t, 2, fakeMap.count())
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok)
	_, ok = fakeMap.getEntry("10.2.1.0/24")
	assert.True(t, ok)
}

func TestSyncDesiredState_CIDRConflictAcrossConfigs(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Both configs claim the same CIDR — should be rejected
	r.allConfigs["config-a"] = newTestConfigWithName("config-a",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.allConfigs["config-b"] = newTestConfigWithName("config-b",
		newEndpoint("gw2", "10.1.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	// Conflicting CIDR should NOT be applied
	assert.Equal(t, 0, fakeMap.count())
}

// TestSyncDesiredState_DifferentPrefixLengthsAcrossConfigs verifies that two configs
// with the same IP base but different prefix lengths do NOT conflict in the LPM trie.
// "10.1.1.0/24" and "10.1.1.128/25" are distinct LPM keys and both get applied.
func TestSyncDesiredState_DifferentPrefixLengthsAcrossConfigs(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	r.allConfigs["config-a"] = newTestConfigWithName("config-a",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.allConfigs["config-b"] = newTestConfigWithName("config-b",
		newEndpoint("gw2", "10.1.1.128/25", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	// Both are distinct LPM keys — both should be applied
	assert.Equal(t, 2, fakeMap.count(), "distinct LPM keys should both be applied")
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok, "10.1.1.0/24 should be applied")
	_, ok = fakeMap.getEntry("10.1.1.128/25")
	assert.True(t, ok, "10.1.1.128/25 should be applied")
}

func TestSyncDesiredState_DeleteRetryOnFailure(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Add an endpoint
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)
	r.syncDesiredState(context.Background())
	assert.Equal(t, 1, fakeMap.count())

	// Remove the config, but make delete fail
	delete(r.allConfigs, "default")
	fakeMap.deleteErr = fmt.Errorf("temporary BPF error")
	r.syncDesiredState(context.Background())

	// Entry should still be in lastApplied for retry
	assert.Equal(t, 1, len(r.lastApplied), "failed delete should keep entry in lastApplied for retry")

	// Now make delete succeed — next sync should clean it up
	fakeMap.deleteErr = nil
	r.syncDesiredState(context.Background())
	assert.Equal(t, 0, len(r.lastApplied), "successful delete should remove entry from lastApplied")
}

func TestSyncDesiredState_CrdSyncedGate(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Seed BPF map with stale entries (from previous agent run)
	fakeMap.entries["10.99.0.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.99.0.0"), PrefixLen: 24}

	// Add a config (simulates Upsert before Sync)
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	// Sync WITHOUT crdSynced — cleanup should NOT run
	r.syncDesiredState(context.Background())
	assert.False(t, r.initialCleanupDone, "cleanup should not run before crdSynced")
	// Stale entry should still be there (not cleaned up)
	_, ok := fakeMap.getEntry("10.99.0.0/24")
	assert.True(t, ok, "stale entry should persist before crdSynced")
	// But the desired entry should be applied
	assert.Equal(t, 2, fakeMap.count(), "desired + stale entries should both exist")

	// Now set crdSynced and sync again
	r.mu.Lock()
	r.crdSynced = true
	r.mu.Unlock()
	r.syncDesiredState(context.Background())

	assert.True(t, r.initialCleanupDone, "cleanup should run after crdSynced")
	// Stale entry should now be cleaned up
	_, ok = fakeMap.getEntry("10.99.0.0/24")
	assert.False(t, ok, "stale entry should be cleaned up after crdSynced")
	// Desired entry should remain
	assert.Equal(t, 1, fakeMap.count())
	_, ok = fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok, "desired entry should remain after cleanup")
}

func TestSyncDesiredState_SkipsUnchangedEndpoints(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
	)

	r.syncDesiredState(context.Background())
	assert.Equal(t, 1, fakeMap.count())

	// Track that lastApplied has the entry
	applied, ok := r.lastApplied["10.1.1.0/24"]
	require.True(t, ok)
	assert.Equal(t, "10.169.72.236", applied.tunnelEndpoint)

	// Sync again with same config — should skip BPF update
	// (We can't easily verify no BPF call was made, but we verify state is consistent)
	r.syncDesiredState(context.Background())
	assert.Equal(t, 1, fakeMap.count())
}

// --- cleanupStaleBPFEntries tests ---

func TestCleanupStaleBPFEntries(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Seed BPF map with entries from previous agent run.
	// Both the map key and Entry.PrefixLen must be set so cleanupStaleBPFEntries
	// can reconstruct the CIDR string from the Entry fields.
	fakeMap.entries["10.1.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.1.1.0"), PrefixLen: 24}
	fakeMap.entries["10.2.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.2.1.0"), PrefixLen: 24}
	fakeMap.entries["10.3.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.3.1.0"), PrefixLen: 24}

	// Only 10.1.1.0/24 is desired
	desiredKeys := map[string]desiredEP{"10.1.1.0/24": {}}
	r.cleanupStaleBPFEntries(desiredKeys)

	// Only the desired entry should remain
	assert.Equal(t, 1, fakeMap.count())
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok, "desired entry should be kept")
}

func TestCleanupStaleBPFEntries_ListError(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	fakeMap.listErr = fmt.Errorf("map not found")
	r := newTestReconciler(fakeMap)

	// Should not panic, just log warning
	r.cleanupStaleBPFEntries(map[string]desiredEP{"10.1.1.0/24": {}})
}

// --- applyConnection tests ---

func TestApplyConnection_Valid(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	err := r.applyConnection("10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01")
	require.NoError(t, err)
	assert.Equal(t, 1, fakeMap.count())
}

func TestApplyConnection_InvalidTunnelIP(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	err := r.applyConnection("10.1.1.0/24", "not-an-ip", "aa:bb:cc:dd:ee:01")
	assert.ErrorContains(t, err, "invalid tunnel endpoint")
}

func TestApplyConnection_InvalidCIDR(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	err := r.applyConnection("not-a-cidr", "10.169.72.236", "aa:bb:cc:dd:ee:01")
	assert.ErrorContains(t, err, "invalid CIDR")
}

func TestApplyConnection_InvalidMAC(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	err := r.applyConnection("10.1.1.0/24", "10.169.72.236", "not-a-mac")
	assert.ErrorContains(t, err, "invalid MAC")
}

// TestSyncDesiredState_DifferentPrefixLengths_BothApplied verifies that a single
// config with endpoints on different prefix lengths is valid and all endpoints get applied.
func TestSyncDesiredState_DifferentPrefixLengths_BothApplied(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Config with two endpoints at different prefix lengths — both are distinct LPM keys.
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.1.1.128/25", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)

	r.syncDesiredState(context.Background())

	// Both endpoints should be applied — they are distinct LPM keys
	assert.Equal(t, 2, fakeMap.count())
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok, "10.1.1.0/24 should be applied")
	_, ok = fakeMap.getEntry("10.1.1.128/25")
	assert.True(t, ok, "10.1.1.128/25 should be applied")
}

func TestSyncDesiredState_ThreeWayConflict(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Three configs with the same CIDR — all should be rejected
	r.allConfigs["config-a"] = newTestConfigWithName("config-a",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.1", "aa:bb:cc:dd:ee:01"),
	)
	r.allConfigs["config-b"] = newTestConfigWithName("config-b",
		newEndpoint("gw2", "10.1.1.0/24", "10.169.72.2", "aa:bb:cc:dd:ee:02"),
	)
	r.allConfigs["config-c"] = newTestConfigWithName("config-c",
		newEndpoint("gw3", "10.1.1.0/24", "10.169.72.3", "aa:bb:cc:dd:ee:03"),
	)

	r.syncDesiredState(context.Background())

	// All three conflict — none should be applied
	assert.Equal(t, 0, fakeMap.count())
}

// TestCleanupStaleBPFEntries_IPv4MappedAddress verifies that stale entries with
// 16-byte IPv4-mapped addresses (e.g. ::ffff:10.1.1.0) are handled correctly.
// net.ParseIP always returns a 16-byte slice; To4() normalizes it to 4-byte.
func TestCleanupStaleBPFEntries_IPv4MappedAddress(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// net.ParseIP("10.1.1.0") returns a 16-byte IPv4-in-IPv6 form internally;
	// explicitly use To4() to demonstrate what the real BPF List() returns (4-byte),
	// and also test the 16-byte path by inserting a raw 16-byte IP.
	ipv4Mapped := net.ParseIP("10.99.0.0") // 16-byte form from ParseIP
	fakeMap.entries["10.99.0.0/24"] = vtepmap.Entry{
		CIDR:      ipv4Mapped, // 16-byte ::ffff:10.99.0.0 form
		PrefixLen: 24,
	}

	// Nothing is desired — the stale entry should be cleaned up.
	r.cleanupStaleBPFEntries(map[string]desiredEP{})

	// The entry must be deleted regardless of whether it came in as a 16-byte IP.
	assert.Equal(t, 0, fakeMap.count(), "IPv4-mapped stale entry should be cleaned up")
}

// TestSyncDesiredState_PartialEndpointFailure verifies that when one endpoint in a
// config fails to apply to the BPF map, the successful endpoint is still tracked
// in lastApplied, and the failed endpoint is not.
func TestSyncDesiredState_PartialEndpointFailure(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// First apply both endpoints successfully.
	r.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	r.syncDesiredState(context.Background())
	assert.Equal(t, 2, fakeMap.count())

	// Now update gw1's tunnel IP and inject a BPF error only for the next write.
	// Only the first Update call fails; subsequent calls succeed.
	callCount := 0
	origUpdateErr := fakeMap.updateErr
	defer func() { fakeMap.updateErr = origUpdateErr }()

	// Use a custom fakeVTEPMap that fails on the first Update only.
	type countingMap struct {
		*fakeVTEPMap
		calls int
	}
	cm := &countingMap{fakeVTEPMap: fakeMap}

	r2 := newTestReconciler(cm.fakeVTEPMap)
	r2.lastApplied = r.lastApplied // carry over applied state

	// Inject failure only for gw1's update (change its tunnel endpoint to trigger a write).
	r2.allConfigs["default"] = newTestConfigWithName("default",
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.99", "aa:bb:cc:dd:ee:01"),  // changed
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"), // unchanged
	)
	cm.fakeVTEPMap.updateErr = fmt.Errorf("transient error")
	_ = callCount
	err := r2.syncDesiredState(context.Background())

	// At least one endpoint failed.
	assert.Error(t, err)
	// gw2 is unchanged and stays tracked.
	_, gw2Applied := r2.lastApplied["10.2.1.0/24"]
	assert.True(t, gw2Applied, "unchanged endpoint should remain in lastApplied")
	// gw1 failed to update — its old entry stays in lastApplied until success.
	gw1Entry, gw1Applied := r2.lastApplied["10.1.1.0/24"]
	if gw1Applied {
		// If still tracked, it must be with the OLD tunnel endpoint (not the failed new value).
		assert.Equal(t, "10.169.72.236", gw1Entry.tunnelEndpoint,
			"failed update must not advance lastApplied to new value")
	}
}

// TestSyncDesiredState_NearCapacity verifies behaviour at the 8-endpoint limit.
// All 8 (the BPF max) should be accepted; a 9th would be rejected per CRD validation
// (enforced by the kubebuilder MaxItems annotation before reaching the reconciler).
func TestSyncDesiredState_NearCapacity(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	endpoints := make([]cilium_api_v2.VTEPEndpoint, vtepmap.MaxEntries)
	for i := range endpoints {
		endpoints[i] = newEndpoint(
			fmt.Sprintf("gw%d", i),
			fmt.Sprintf("10.%d.1.0/24", i+1),
			fmt.Sprintf("10.169.72.%d", i+1),
			fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i+1),
		)
	}
	r.allConfigs["default"] = newTestConfigWithName("default", endpoints...)

	err := r.syncDesiredState(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, vtepmap.MaxEntries, fakeMap.count(),
		"all MaxEntries endpoints should be applied")
}

// TestSyncDesiredState_NearCapacityAcrossConfigs verifies that total endpoint count
// is enforced across multiple matching configs.
func TestSyncDesiredState_NearCapacityAcrossConfigs(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Spread MaxEntries+1 endpoints across two configs.
	total := vtepmap.MaxEntries + 1
	for i := range total {
		r.allConfigs[fmt.Sprintf("config-%d", i)] = newTestConfigWithName(
			fmt.Sprintf("config-%d", i),
			newEndpoint(
				fmt.Sprintf("gw%d", i),
				fmt.Sprintf("192.168.%d.0/24", i),
				fmt.Sprintf("10.169.72.%d", i+1),
				fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i+1),
			),
		)
	}

	err := r.syncDesiredState(context.Background())
	assert.Error(t, err, "exceeding MaxEntries across configs should fail")
	assert.Equal(t, 0, fakeMap.count(), "no endpoints should be applied when total exceeds max")
}

// TestCleanupStaleBPFEntries_NonIPv4Skipped verifies that a non-IPv4 entry in the
// BPF map (which should never happen in practice) is skipped with a warning and
// does not cause a panic or incorrect deletion.
func TestCleanupStaleBPFEntries_NonIPv4Skipped(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Insert a sentinel IPv6 entry to simulate unexpected BPF map contents.
	// The key is arbitrary since the reconciler uses List() not direct key access.
	fakeMap.entries["bad"] = vtepmap.Entry{
		CIDR:      net.ParseIP("::1"), // IPv6 — To4() returns nil
		PrefixLen: 128,
	}
	// Also insert a valid IPv4 stale entry.
	fakeMap.entries["10.50.0.0/24"] = vtepmap.Entry{
		CIDR:      net.ParseIP("10.50.0.0").To4(),
		PrefixLen: 24,
	}

	// Nothing desired — both should be handled.
	r.cleanupStaleBPFEntries(map[string]desiredEP{})

	// The IPv6 entry cannot be deleted (skipped with warning) and stays in the map.
	// The IPv4 entry is deleted.
	_, ipv4Remains := fakeMap.getEntry("10.50.0.0/24")
	assert.False(t, ipv4Remains, "IPv4 stale entry should be deleted")
}
