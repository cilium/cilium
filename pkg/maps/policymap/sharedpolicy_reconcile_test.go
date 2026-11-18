// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/registry"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// TestReconcileSharedPolicy checks that the reconciliation fixes the changes to the shared
// policy map and the policy overlay map that the agent did not make, and leaves the rest
// alone.
func TestReconcileSharedPolicy(t *testing.T) {
	f, shared, overlay := setupCountingFactory(t)
	for _, epID := range []uint16{1, 2} {
		require.NoError(t, f.SyncEndpointOverlay(epID, entriesOf(rulesForIdentities(100, 101))))
	}
	require.NoError(t, f.SyncEndpointOverlay(3, entriesOf(rulesForIdentities(200))))
	// The agent tracks no rule set for an endpoint in lockdown.
	require.NoError(t, f.LockdownEndpoint(4))
	rsA, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	rsB, _ := overlayRuleSet(t, overlay.fakeBPFMap, 3)

	shared.resetCounts()
	overlay.resetCounts()
	fixed, err := f.reconcileSharedPolicy()
	require.NoError(t, err)
	require.Zero(t, fixed)
	require.Zero(t, shared.updates+shared.deletes+overlay.updates+overlay.deletes, "nothing to fix")

	// A missing entry, a changed entry, and entries the agent did not write: one in a rule set
	// in use, one in an unknown rule set, and one in the lockdown rule set.
	keyA := NewSharedKey(rsA, rulesForIdentities(101)[0].Key)
	require.NoError(t, shared.fakeBPFMap.Delete(&keyA))
	keyB := NewSharedKey(rsB, rulesForIdentities(200)[0].Key)
	deny := NewSharedEntry(keyB, policyTypes.DenyEntry())
	require.NoError(t, shared.fakeBPFMap.Update(&keyB, &deny))
	for _, id := range []uint32{rsA, 77, lockdownRuleSetID} {
		key := NewSharedKey(id, rulesForIdentities(999)[0].Key)
		entry := NewSharedEntry(key, policyTypes.AllowEntry())
		require.NoError(t, shared.fakeBPFMap.Update(&key, &entry))
	}
	// An overlay entry that points to another rule set, a missing one, and one of an
	// endpoint that has no rule set.
	require.NoError(t, overlay.fakeBPFMap.Update(&OverlayKey{EndpointID: 1}, &OverlayValue{RuleSetID: rsB}))
	require.NoError(t, overlay.fakeBPFMap.Delete(&OverlayKey{EndpointID: 3}))
	require.NoError(t, overlay.fakeBPFMap.Update(&OverlayKey{EndpointID: 9}, &OverlayValue{RuleSetID: rsA}))

	fixed, err = f.reconcileSharedPolicy()
	require.NoError(t, err)
	require.Equal(t, 8, fixed)
	for _, epID := range []uint16{1, 2} {
		rs, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rsA, rs)
		require.ElementsMatch(t, []uint32{100, 101}, endpointIdentities(t, f, epID))
	}
	rs, _ := overlayRuleSet(t, overlay.fakeBPFMap, 3)
	require.Equal(t, rsB, rs)
	v, err := shared.fakeBPFMap.Lookup(&keyB)
	require.NoError(t, err)
	require.False(t, v.(*PolicyEntry).IsDeny(), "the changed entry is written again")
	require.Equal(t, 3, totalEntries(t, shared.fakeBPFMap), "the entries the agent did not write are deleted")
	rs, ok := overlayRuleSet(t, overlay.fakeBPFMap, 4)
	require.True(t, ok)
	require.Equal(t, uint32(lockdownRuleSetID), rs, "the endpoint in lockdown is left alone")
	_, ok = overlayRuleSet(t, overlay.fakeBPFMap, 9)
	require.False(t, ok, "the overlay entry the agent did not write is deleted")

	fixed, err = f.reconcileSharedPolicy()
	require.NoError(t, err)
	require.Zero(t, fixed)
}

// TestReconcileSharedPolicyConcurrentUpdates checks that the changes made by policy updates
// after the maps were read are kept.
func TestReconcileSharedPolicyConcurrentUpdates(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory(t)
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100))))
	require.NoError(t, f.SyncEndpointOverlay(2, entriesOf(rulesForIdentities(200))))
	require.NoError(t, f.SyncEndpointOverlay(4, entriesOf(rulesForIdentities(400))))
	s, err := f.snapshotSharedPolicy()
	require.NoError(t, err)

	// Endpoint 1 gets a new rule, endpoint 2 is removed, endpoint 3 is new and reuses the ID
	// of endpoint 2's rule set, and endpoint 4 is locked down.
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100, 101))))
	require.NoError(t, f.removeEndpointOverlay(2))
	require.NoError(t, f.SyncEndpointOverlay(3, entriesOf(rulesForIdentities(300))))
	require.NoError(t, f.LockdownEndpoint(4))

	f.allocator.mu.Lock()
	fixed, err := f.reconcileSharedPolicyLocked(s)
	f.allocator.mu.Unlock()
	require.NoError(t, err)
	require.Zero(t, fixed)
	require.ElementsMatch(t, []uint32{100, 101}, endpointIdentities(t, f, 1))
	require.False(t, f.HasEndpointOverlay(2))
	require.ElementsMatch(t, []uint32{300}, endpointIdentities(t, f, 3))
	rs, ok := overlayRuleSet(t, overlay, 4)
	require.True(t, ok)
	require.Equal(t, uint32(lockdownRuleSetID), rs)
	require.Equal(t, 3, totalEntries(t, shared))
}

func TestReconcileSharedPolicyDumpError(t *testing.T) {
	f, shared, _ := setupSharedPolicyFactory(t)
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100))))
	errDump := errors.New("dump failed")
	shared.dumpErr = errDump
	fixed, err := f.reconcileSharedPolicy()
	require.ErrorIs(t, err, errDump)
	require.Zero(t, fixed)
}

// TestReconcileSharedPolicyJob checks that the periodic job logs the fixes.
func TestReconcileSharedPolicyJob(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory(t)
	var logs bytes.Buffer
	f.logger = slog.New(slog.NewTextHandler(&logs, nil))
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100))))

	require.NoError(t, f.reconcileSharedPolicyJob(t.Context()))
	require.Empty(t, logs.String())

	rs, _ := overlayRuleSet(t, overlay, 1)
	key := NewSharedKey(rs, rulesForIdentities(100)[0].Key)
	require.NoError(t, shared.Delete(&key))
	require.NoError(t, f.reconcileSharedPolicyJob(t.Context()))
	require.Contains(t, logs.String(), "Fixed shared policy map entries")
	require.Contains(t, logs.String(), "count=1")
}

// fakeJobGroup records the jobs added to it.
type fakeJobGroup struct {
	jobs []job.Job
}

func (g *fakeJobGroup) Add(jobs ...job.Job)           { g.jobs = append(g.jobs, jobs...) }
func (g *fakeJobGroup) Scoped(string) job.ScopedGroup { return nil }

// TestRegisterSharedPolicyReconciliation checks that the periodic reconciliation is set up
// only with a job group and a positive interval.
func TestRegisterSharedPolicyReconciliation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		group    bool
		interval time.Duration
		jobs     int
	}{
		{name: "enabled", group: true, interval: time.Minute, jobs: 1},
		{name: "zero interval", group: true, interval: 0, jobs: 0},
		{name: "no job group", group: false, interval: time.Minute, jobs: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &factory{logger: hivetest.Logger(t)}
			g := &fakeJobGroup{}
			var jobs job.Group
			if tc.group {
				jobs = g
			}
			f.registerSharedPolicy(&cell.DefaultLifecycle{}, &registry.MapRegistry{}, jobs, tc.interval)
			require.Len(t, g.jobs, tc.jobs)
		})
	}
}
