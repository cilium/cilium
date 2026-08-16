// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for RunPodSandbox and StopPodSandbox covering the early-exit paths
// that require no real kernel network namespaces:
//
//   - host-network pod (empty network namespace in the sandbox) → skipped
//   - pod UID not found in the deviceTable statedb table → skipped
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
	dev := &dummy.DummyDevice{Name: "dummy0"}
	// Insert the allocation into the statedb Device table.
	d.commitAllocation(podUID, claimUID, []allocation{
		{Device: dev, Config: types.DeviceConfig{}, Manager: types.DeviceManagerTypeDummy},
	}, nil)
	return d
}

// ---------------------------------------------------------------------------
// RunPodSandbox — early exits (no netlink/netns)
// ---------------------------------------------------------------------------

func TestRunPodSandbox(t *testing.T) {
	// host-network pod (empty network namespace) → silently skipped.
	t.Run("host network skipped", func(t *testing.T) {
		d := buildNRIDriver(t)

		require.NoError(t, d.RunPodSandbox(t.Context(), podSandbox("some-uid", "")))
		// podNetns map must still be empty — nothing was cached.
		require.NotContains(t, d.podNetns, "some-uid")
	})

	// Pod whose UID is not in the deviceTable → silently skipped.
	t.Run("no allocation skipped", func(t *testing.T) {
		d := buildNRIDriver(t)
		// Give the sandbox a non-empty netns path to pass the host-network gate.
		// Because deviceTable has no allocation, the function must return nil early
		// before attempting to open the netns file.
		require.NoError(t, d.RunPodSandbox(t.Context(), podSandbox("unknown-pod-uid", "/run/netns/some-netns")))
	})
}

// ---------------------------------------------------------------------------
// StopPodSandbox — early exits (no netlink/netns)
// ---------------------------------------------------------------------------

func TestStopPodSandbox(t *testing.T) {
	// Host-network pod → silently skipped; podNetns map entry is evicted.
	t.Run("host network skipped", func(t *testing.T) {
		d := buildNRIDriver(t)
		// Pre-seed a map entry to verify it is cleaned up even on the fast path.
		d.podNetns[kubetypes.UID("host-pod")] = ""

		require.NoError(t, d.StopPodSandbox(t.Context(), podSandbox("host-pod", "")))
		require.NotContains(t, d.podNetns, "host-pod",
			"map entry must be evicted even for host-network pods")
	})

	// Pod with a real netns but no allocation → nil return; map entry evicted.
	t.Run("no allocation skipped", func(t *testing.T) {
		d := buildNRIDriver(t)
		d.podNetns[kubetypes.UID("no-alloc-pod")] = "/run/netns/some-ns"

		// getNetworkNamespace falls back to the map since the sandbox has no
		// Linux namespaces populated (mimics containerd < 2.1 stop event).
		require.NoError(t, d.StopPodSandbox(t.Context(), &api.PodSandbox{Uid: "no-alloc-pod", Linux: &api.LinuxPodSandbox{}}))
		require.NotContains(t, d.podNetns, "no-alloc-pod",
			"map entry must be evicted even when no allocation is found")
	})

	// containerd < 2.1: stop event carries no namespaces; cached path is used
	// then evicted. Because the allocation entry exists the driver will try to
	// open the netns — which fails (path absent on test host) — but the cache
	// eviction happens in a defer before that, so we only check the eviction.
	t.Run("fallback cache evicted", func(t *testing.T) {
		const podUID = kubetypes.UID("cache-pod-uid")
		d := buildNRIDriverWithAlloc(t, podUID, "claim-uid")

		d.podNetns[podUID] = "/run/netns/cached-ns"

		// No Linux namespaces in the sandbox — forces the map fallback path.
		// Will fail at netns.OpenPinned because the path doesn't exist — that's fine.
		_ = d.StopPodSandbox(t.Context(), &api.PodSandbox{Uid: string(podUID), Linux: &api.LinuxPodSandbox{}})

		// Map entry must always be evicted (defer runs before the error path).
		require.NotContains(t, d.podNetns, podUID,
			"map entry must be evicted after StopPodSandbox regardless of netns errors")
	})
}
