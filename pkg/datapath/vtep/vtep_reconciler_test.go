// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	vtepmap "github.com/cilium/cilium/pkg/maps/vtep"
)

// fakeVTEPMap implements vtep.Map for testing.
type fakeVTEPMap struct {
	mu      lock.Mutex
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
		lastApplied: make(map[string]appliedEndpoint),
	}
}

func newEndpoint(name, cidrStr, tunnelEP, macAddr string) cilium_api_v2alpha1.VTEPEndpoint {
	return cilium_api_v2alpha1.VTEPEndpoint{
		Name:           name,
		CIDR:           cidrStr,
		TunnelEndpoint: tunnelEP,
		MAC:            macAddr,
	}
}

// reconcileWith sets this node's CiliumVTEPNodeConfig spec to the given endpoints and
// runs a reconcile. crdSynced is set so stale-entry cleanup behaves as in steady state.
func (r *VTEPReconciler) reconcileWith(endpoints ...cilium_api_v2alpha1.VTEPEndpoint) (map[string]error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.crdSynced = true
	r.nodeConfig = &cilium_api_v2alpha1.CiliumVTEPNodeConfig{
		Spec: cilium_api_v2alpha1.CiliumVTEPNodeConfigSpec{VTEPEndpoints: endpoints},
	}
	r.nodeName = "test-node"
	return r.reconcileLocked()
}

// deleteConfig clears this node's config (simulating object deletion) and reconciles.
func (r *VTEPReconciler) deleteConfig() (map[string]error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.crdSynced = true
	r.nodeConfig = nil
	return r.reconcileLocked()
}

// --- reconcile tests ---

func TestReconcile_SingleEndpoint(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	require.NoError(t, err)

	assert.Equal(t, 1, fakeMap.count())
	entry, ok := fakeMap.getEntry("10.1.1.0/24")
	require.True(t, ok)
	assert.Equal(t, "10.169.72.236", entry.TunnelEndpoint.String())
}

func TestReconcile_MultipleEndpoints(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	require.NoError(t, err)
	assert.Equal(t, 2, fakeMap.count())
}

func TestReconcile_RemovesStaleCIDRs(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	require.NoError(t, err)
	assert.Equal(t, 2, fakeMap.count())

	// Reconcile with only gw1 — gw2 must be removed.
	_, err = r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	require.NoError(t, err)
	assert.Equal(t, 1, fakeMap.count())
	_, ok := fakeMap.getEntry("10.2.1.0/24")
	assert.False(t, ok, "stale entry for 10.2.1.0/24 should be deleted")
}

func TestReconcile_UpdatesExistingEndpoint(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	require.NoError(t, err)

	// Update tunnel endpoint for the same CIDR.
	_, err = r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.237", "aa:bb:cc:dd:ee:ff"))
	require.NoError(t, err)

	assert.Equal(t, 1, fakeMap.count())
	entry, ok := fakeMap.getEntry("10.1.1.0/24")
	require.True(t, ok)
	assert.Equal(t, "10.169.72.237", entry.TunnelEndpoint.String())
}

func TestReconcile_BPFMapUpdateError(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	fakeMap.updateErr = fmt.Errorf("bpf map full")
	r := newTestReconciler(fakeMap)

	epErrors, err := r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	assert.Error(t, err)
	assert.Contains(t, epErrors, "gw1")
	assert.Equal(t, 0, fakeMap.count())
	// Failed BPF update must NOT be tracked in lastApplied.
	assert.Empty(t, r.lastApplied, "failed BPF update should not be in lastApplied")
}

func TestReconcile_EmptySpec(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith()
	require.NoError(t, err)
	assert.Equal(t, 0, fakeMap.count())
}

func TestReconcile_DeleteConfig(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	require.NoError(t, err)
	assert.Equal(t, 2, fakeMap.count())

	// Node config deleted — all entries removed.
	_, err = r.deleteConfig()
	require.NoError(t, err)
	assert.Equal(t, 0, fakeMap.count())
}

func TestReconcile_DuplicateCIDRInSpec(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Two endpoints normalize to the same LPM key — the second is flagged.
	epErrors, _ := r.reconcileWith(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.1.1.5/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	assert.Contains(t, epErrors, "gw2")
	assert.Equal(t, 1, fakeMap.count(), "only the first endpoint for the CIDR is applied")
}

func TestReconcile_IPv6CIDRRejected(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	epErrors, _ := r.reconcileWith(newEndpoint("gw1", "2001:db8::/32", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	assert.Contains(t, epErrors, "gw1")
	assert.Equal(t, 0, fakeMap.count())
}

// TestReconcile_DifferentPrefixLengths verifies that two CIDRs with different prefix
// lengths (/24 and /25) are distinct LPM keys and both get applied.
func TestReconcile_DifferentPrefixLengths(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.1.1.128/25", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	require.NoError(t, err)
	assert.Equal(t, 2, fakeMap.count())
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok)
	_, ok = fakeMap.getEntry("10.1.1.128/25")
	assert.True(t, ok)
}

func TestReconcile_DeleteRetryOnFailure(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	_, err := r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	require.NoError(t, err)
	assert.Equal(t, 1, fakeMap.count())

	// Remove the endpoint but make delete fail.
	fakeMap.deleteErr = fmt.Errorf("temporary BPF error")
	_, _ = r.reconcileWith()
	assert.Len(t, r.lastApplied, 1, "failed delete should keep entry in lastApplied for retry")

	// Delete succeeds on the next reconcile.
	fakeMap.deleteErr = nil
	_, err = r.reconcileWith()
	require.NoError(t, err)
	assert.Empty(t, r.lastApplied, "successful delete should remove entry from lastApplied")
}

func TestReconcile_CrdSyncedGate(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	// Seed BPF map with a stale entry from a previous agent run.
	fakeMap.entries["10.99.0.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.99.0.0"), PrefixLen: 24}

	// Reconcile WITHOUT crdSynced — cleanup should NOT run.
	r.mu.Lock()
	r.nodeConfig = &cilium_api_v2alpha1.CiliumVTEPNodeConfig{
		Spec: cilium_api_v2alpha1.CiliumVTEPNodeConfigSpec{
			VTEPEndpoints: []cilium_api_v2alpha1.VTEPEndpoint{
				newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
			},
		},
	}
	_, err := r.reconcileLocked()
	r.mu.Unlock()
	require.NoError(t, err)
	assert.False(t, r.initialCleanupDone, "cleanup should not run before crdSynced")
	_, ok := fakeMap.getEntry("10.99.0.0/24")
	assert.True(t, ok, "stale entry should persist before crdSynced")
	assert.Equal(t, 2, fakeMap.count(), "desired + stale entries should both exist")

	// Now set crdSynced and reconcile again — stale cleanup runs.
	_, err = r.reconcileWith(newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	require.NoError(t, err)
	assert.True(t, r.initialCleanupDone, "cleanup should run after crdSynced")
	_, ok = fakeMap.getEntry("10.99.0.0/24")
	assert.False(t, ok, "stale entry should be cleaned up after crdSynced")
	assert.Equal(t, 1, fakeMap.count())
}

// TestReconcile_NearCapacity verifies all MaxEntries endpoints are accepted.
func TestReconcile_NearCapacity(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	endpoints := make([]cilium_api_v2alpha1.VTEPEndpoint, vtepmap.MaxEntries)
	for i := range endpoints {
		endpoints[i] = newEndpoint(
			fmt.Sprintf("gw%d", i),
			fmt.Sprintf("10.%d.1.0/24", i+1),
			fmt.Sprintf("10.169.72.%d", i+1),
			fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i+1),
		)
	}

	_, err := r.reconcileWith(endpoints...)
	require.NoError(t, err)
	assert.Equal(t, vtepmap.MaxEntries, fakeMap.count(), "all MaxEntries endpoints should be applied")
}

// TestReconcile_OverCapacity verifies that exceeding MaxEntries is rejected and nothing
// is programmed (defence-in-depth; the CRD's MaxItems=8 normally enforces this at admission).
func TestReconcile_OverCapacity(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	endpoints := make([]cilium_api_v2alpha1.VTEPEndpoint, vtepmap.MaxEntries+1)
	for i := range endpoints {
		endpoints[i] = newEndpoint(
			fmt.Sprintf("gw%d", i),
			fmt.Sprintf("10.%d.1.0/24", i+1),
			fmt.Sprintf("10.169.72.%d", i+1),
			fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i+1),
		)
	}

	_, err := r.reconcileWith(endpoints...)
	assert.Error(t, err, "exceeding MaxEntries should fail")
	assert.Equal(t, 0, fakeMap.count(), "no endpoints should be applied when over capacity")
}

// --- cleanupStaleBPFEntries tests ---

func TestCleanupStaleBPFEntries(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	fakeMap.entries["10.1.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.1.1.0"), PrefixLen: 24}
	fakeMap.entries["10.2.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.2.1.0"), PrefixLen: 24}
	fakeMap.entries["10.3.1.0/24"] = vtepmap.Entry{CIDR: net.ParseIP("10.3.1.0"), PrefixLen: 24}

	desiredKeys := map[string]desiredEP{"10.1.1.0/24": {}}
	r.cleanupStaleBPFEntries(desiredKeys)

	assert.Equal(t, 1, fakeMap.count())
	_, ok := fakeMap.getEntry("10.1.1.0/24")
	assert.True(t, ok, "desired entry should be kept")
}

func TestCleanupStaleBPFEntries_ListError(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	fakeMap.listErr = fmt.Errorf("map not found")
	r := newTestReconciler(fakeMap)

	// Should not panic, just log a warning.
	r.cleanupStaleBPFEntries(map[string]desiredEP{"10.1.1.0/24": {}})
}

// TestCleanupStaleBPFEntries_IPv4MappedAddress verifies that stale entries with
// 16-byte IPv4-mapped addresses (e.g. ::ffff:10.1.1.0) are handled correctly.
func TestCleanupStaleBPFEntries_IPv4MappedAddress(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	ipv4Mapped := net.ParseIP("10.99.0.0") // 16-byte form from ParseIP
	fakeMap.entries["10.99.0.0/24"] = vtepmap.Entry{
		CIDR:      ipv4Mapped,
		PrefixLen: 24,
	}

	r.cleanupStaleBPFEntries(map[string]desiredEP{})

	assert.Equal(t, 0, fakeMap.count(), "IPv4-mapped stale entry should be cleaned up")
}

// TestCleanupStaleBPFEntries_NonIPv4Skipped verifies that a non-IPv4 entry is skipped
// (not deleted) while a valid IPv4 entry is cleaned up.
func TestCleanupStaleBPFEntries_NonIPv4Skipped(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	fakeMap.entries["bad"] = vtepmap.Entry{
		CIDR:      net.ParseIP("::1"), // IPv6 — To4() returns nil
		PrefixLen: 128,
	}
	fakeMap.entries["10.50.0.0/24"] = vtepmap.Entry{
		CIDR:      net.ParseIP("10.50.0.0").To4(),
		PrefixLen: 24,
	}

	r.cleanupStaleBPFEntries(map[string]desiredEP{})

	_, ipv4Remains := fakeMap.getEntry("10.50.0.0/24")
	assert.False(t, ipv4Remains, "IPv4 stale entry should be deleted")
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

func TestApplyConnection_IPv6TunnelRejected(t *testing.T) {
	fakeMap := newFakeVTEPMap()
	r := newTestReconciler(fakeMap)

	err := r.applyConnection("10.1.1.0/24", "2001:db8::1", "aa:bb:cc:dd:ee:01")
	assert.ErrorContains(t, err, "must be IPv4")
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

// --- node-config status building tests ---

func fixedTime(sec int64) metav1.Time { return metav1.Unix(sec, 0) }

func nodeCfg(gen int64, eps ...cilium_api_v2alpha1.VTEPEndpoint) *cilium_api_v2alpha1.CiliumVTEPNodeConfig {
	c := &cilium_api_v2alpha1.CiliumVTEPNodeConfig{
		Spec: cilium_api_v2alpha1.CiliumVTEPNodeConfigSpec{VTEPEndpoints: eps},
	}
	c.Generation = gen
	return c
}

func TestBuildNodeConfigStatus_AllSynced(t *testing.T) {
	cfg := nodeCfg(1,
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	now := fixedTime(1000)
	st := buildNodeConfigStatus(cfg, nil, nil, now)

	assert.Equal(t, int32(2), st.EndpointCount)
	require.Len(t, st.VTEPEndpointStatuses, 2)
	for _, es := range st.VTEPEndpointStatuses {
		assert.True(t, es.Synced)
		assert.Empty(t, es.Error)
		require.NotNil(t, es.LastSyncTime)
		assert.Equal(t, int64(1000), es.LastSyncTime.Unix())
	}
	require.Len(t, st.Conditions, 1)
	assert.Equal(t, cilium_api_v2alpha1.VTEPConditionReady, st.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, st.Conditions[0].Status)
	assert.Equal(t, int64(1), st.Conditions[0].ObservedGeneration)
	assert.Equal(t, int64(1000), st.Conditions[0].LastTransitionTime.Unix())
}

func TestBuildNodeConfigStatus_PartialError(t *testing.T) {
	cfg := nodeCfg(2,
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	st := buildNodeConfigStatus(cfg, map[string]error{"gw2": fmt.Errorf("bpf map full")}, nil, fixedTime(1000))

	byName := map[string]cilium_api_v2alpha1.VTEPEndpointStatus{}
	for _, es := range st.VTEPEndpointStatuses {
		byName[es.Name] = es
	}
	assert.True(t, byName["gw1"].Synced)
	assert.False(t, byName["gw2"].Synced)
	assert.Contains(t, byName["gw2"].Error, "bpf map full")
	assert.Nil(t, byName["gw2"].LastSyncTime)
	require.Len(t, st.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, st.Conditions[0].Status)
	assert.Equal(t, "SyncFailed", st.Conditions[0].Reason)
}

func TestBuildNodeConfigStatus_LastSyncTimeStable(t *testing.T) {
	cfg := nodeCfg(1, newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	first := buildNodeConfigStatus(cfg, nil, nil, fixedTime(1000))
	second := buildNodeConfigStatus(cfg, nil, &first, fixedTime(2000))
	require.Len(t, second.VTEPEndpointStatuses, 1)
	require.NotNil(t, second.VTEPEndpointStatuses[0].LastSyncTime)
	assert.Equal(t, int64(1000), second.VTEPEndpointStatuses[0].LastSyncTime.Unix(),
		"LastSyncTime must not advance while the endpoint stays synced")
}

// TestBuildNodeConfigStatus_DedupInvariant verifies that two consecutive builds for an
// unchanged config are DeepEqual, which is what lets the reconciler suppress redundant
// /status writes (the production fix for status write-amplification).
func TestBuildNodeConfigStatus_DedupInvariant(t *testing.T) {
	cfg := nodeCfg(1,
		newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"),
		newEndpoint("gw2", "10.2.1.0/24", "10.169.73.100", "aa:bb:cc:dd:ee:02"),
	)
	first := buildNodeConfigStatus(cfg, nil, nil, fixedTime(1000))
	second := buildNodeConfigStatus(cfg, nil, &first, fixedTime(5000))
	assert.True(t, reflect.DeepEqual(first, second),
		"unchanged config must produce a byte-stable status for no-op dedup")
}

func TestBuildNodeConfigStatus_ConditionTransition(t *testing.T) {
	cfg := nodeCfg(1, newEndpoint("gw1", "10.1.1.0/24", "10.169.72.236", "aa:bb:cc:dd:ee:01"))
	healthy := buildNodeConfigStatus(cfg, nil, nil, fixedTime(1000))
	assert.Equal(t, metav1.ConditionTrue, healthy.Conditions[0].Status)
	stillHealthy := buildNodeConfigStatus(cfg, nil, &healthy, fixedTime(2000))
	assert.Equal(t, int64(1000), stillHealthy.Conditions[0].LastTransitionTime.Unix(),
		"unchanged condition status preserves LastTransitionTime")
	failing := buildNodeConfigStatus(cfg, map[string]error{"gw1": fmt.Errorf("x")}, &stillHealthy, fixedTime(3000))
	assert.Equal(t, metav1.ConditionFalse, failing.Conditions[0].Status)
	assert.Equal(t, int64(3000), failing.Conditions[0].LastTransitionTime.Unix(),
		"changed condition status bumps LastTransitionTime")
}

func TestSetCondition(t *testing.T) {
	var conds []metav1.Condition
	setCondition(&conds, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue}, fixedTime(100))
	require.Len(t, conds, 1)
	assert.Equal(t, int64(100), conds[0].LastTransitionTime.Unix())
	setCondition(&conds, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue}, fixedTime(200))
	assert.Equal(t, int64(100), conds[0].LastTransitionTime.Unix(), "same status preserves LastTransitionTime")
	setCondition(&conds, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse}, fixedTime(300))
	assert.Equal(t, int64(300), conds[0].LastTransitionTime.Unix(), "changed status bumps LastTransitionTime")
}
