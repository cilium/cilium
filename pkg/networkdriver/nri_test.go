// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for RunPodSandbox and StopPodSandbox covering the early-exit paths
// that require no real kernel network namespaces:
//
//   - host-network pod (empty network namespace in the sandbox) → skipped
//   - pod UID not found in driver.allocations → skipped
//   - containerd <2.1 fallback: StopPodSandbox evicts the netns cache entry
//     even when the netns open fails (path doesn't exist on the test host)
//
// Both functions open a real pinned netns once they pass these gates, so the
// tests that exercise the full "move interface" path live in the privileged
// integration test suite (which has a real kernel).

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kubetypes "k8s.io/apimachinery/pkg/types"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// buildNRIDriverWithAlloc returns a Driver that has one pre-wired allocation
// for podUID/claimUID → dummy device, so RunPodSandbox / StopPodSandbox can
// reach the netns-open gate before bailing out on the missing file.
func buildNRIDriverWithAlloc(t *testing.T, podUID kubetypes.UID, claimUID kubetypes.UID) *Driver {
	t.Helper()
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	d := buildPrepDriver(t, cs)
	d.podNetns = make(map[kubetypes.UID]string)
	dev := &dummy.DummyDevice{Name: "dummy0"}
	d.allocations[podUID] = map[kubetypes.UID][]allocation{
		claimUID: {{Device: dev, Config: types.DeviceConfig{}, Manager: types.DeviceManagerTypeDummy}},
	}
	return d
}

// ---------------------------------------------------------------------------
// RunPodSandbox — early exits (no netlink/netns)
// ---------------------------------------------------------------------------

// TestRunPodSandbox_HostNetwork_Skipped verifies that a pod using host
// networking (no network namespace in the sandbox) is silently skipped.
func TestRunPodSandbox_HostNetwork_Skipped(t *testing.T) {
	d := buildNRIDriver(t)
	sb := podSandbox("some-uid", "") // empty netnsPath → host network

	err := d.RunPodSandbox(t.Context(), sb)
	require.NoError(t, err)
	// podNetns must still be empty — nothing was cached.
	assert.Empty(t, d.podNetns)
}

// TestRunPodSandbox_NoAllocation_Skipped verifies that a pod whose UID is not
// in driver.allocations is silently skipped without an error.
func TestRunPodSandbox_NoAllocation_Skipped(t *testing.T) {
	d := buildNRIDriver(t)
	// Give the sandbox a non-empty netns path to pass the host-network gate.
	// Because driver.allocations is empty, the function must return nil early
	// before attempting to open the netns file.
	sb := podSandbox("unknown-pod-uid", "/run/netns/some-netns")

	err := d.RunPodSandbox(t.Context(), sb)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// StopPodSandbox — early exits (no netlink/netns)
// ---------------------------------------------------------------------------

// TestStopPodSandbox_HostNetwork_Skipped verifies that a host-network pod is
// silently skipped and the podNetns cache entry is evicted.
func TestStopPodSandbox_HostNetwork_Skipped(t *testing.T) {
	d := buildNRIDriver(t)
	// Pre-seed a cache entry to verify it is cleaned up even on the fast path.
	d.podNetns["host-pod"] = ""

	sb := podSandbox("host-pod", "")
	err := d.StopPodSandbox(t.Context(), sb)
	require.NoError(t, err)
	assert.NotContains(t, d.podNetns, kubetypes.UID("host-pod"),
		"cache entry must be evicted even for host-network pods")
}

// TestStopPodSandbox_NoAllocation_Skipped verifies that when a pod with a
// real network namespace has no allocation, the call returns nil and its cache
// entry is still evicted.
func TestStopPodSandbox_NoAllocation_Skipped(t *testing.T) {
	d := buildNRIDriver(t)
	d.podNetns["no-alloc-pod"] = "/run/netns/some-ns"

	// getNetworkNamespace falls back to the cache since the sandbox has no
	// Linux namespaces populated (mimics containerd < 2.1 stop event).
	sb := &api.PodSandbox{Uid: "no-alloc-pod", Linux: &api.LinuxPodSandbox{}}

	// allocations is empty → must exit early before trying to open the netns.
	err := d.StopPodSandbox(t.Context(), sb)
	require.NoError(t, err)
	assert.NotContains(t, d.podNetns, kubetypes.UID("no-alloc-pod"),
		"cache entry must be evicted even when no allocation is found")
}

// TestStopPodSandbox_FallbackCacheEvicted verifies that on containerd < 2.1
// (no namespaces in the stop event), the cached namespace path is used and
// then evicted. Because the allocation entry exists, the driver will try to
// open the netns — which will fail because the path doesn't exist on this
// host — but the cache eviction happens before that (deferred), so we only
// check the eviction.
func TestStopPodSandbox_FallbackCacheEvicted(t *testing.T) {
	const podUID = kubetypes.UID("cache-pod-uid")
	d := buildNRIDriverWithAlloc(t, podUID, "claim-uid")
	d.podNetns[podUID] = "/run/netns/cached-ns"

	// No Linux namespaces in the sandbox — forces the cache fallback path.
	sb := &api.PodSandbox{Uid: string(podUID), Linux: &api.LinuxPodSandbox{}}

	// Will fail at netns.OpenPinned because the path doesn't exist — that's fine.
	_ = d.StopPodSandbox(t.Context(), sb)

	// Cache entry must always be evicted (defer runs before the error path).
	assert.NotContains(t, d.podNetns, podUID,
		"cache entry must be evicted after StopPodSandbox regardless of netns errors")
}
