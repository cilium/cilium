// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Integration tests that verify statedb table writes happen correctly from
// the Driver's operation methods:
//
//   commitAllocation       → Device table (PodUID/ClaimUID set)
//   unprepareResourceClaim → Device table (allocation fields cleared)
//   restoreDevicesFromClaim→ Device table
//   getDevicePools         → Device table (upsert discovered devices)
//   rememberNetworkNamespace → driver.podNetns map
//   getNetworkNamespace    → driver.podNetns map (fallback read)
//   StopPodSandbox         → driver.podNetns map (delete on success)
//
// Every test wires a real statedb.DB + Device table into the Driver so no
// Hive or fake cluster is required.

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// buildDriverWithTables constructs a *Driver with a real in-process statedb.DB
// and the Device table wired in. The caller can inject devices or allocations
// before calling the method under test.
func buildDriverWithTables(t *testing.T) (*Driver, *statedb.DB, statedb.RWTable[*Device]) {
	t.Helper()

	db := statedb.New()

	devTbl, err := NewDeviceTable(db)
	require.NoError(t, err)

	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	d := buildPrepDriver(t, cs)
	d.db = db
	d.deviceTable = devTbl
	d.podNetns = make(map[kubetypes.UID]string)

	return d, db, devTbl
}

// listingDeviceManager is a DeviceManager stub whose ListDevices returns a
// configurable slice, allowing the test to change it between calls.
type listingDeviceManager struct {
	devices []types.Device
}

func (m *listingDeviceManager) Type() types.DeviceManagerType { return types.DeviceManagerTypeMock }
func (m *listingDeviceManager) ListDevices() ([]types.Device, error) {
	return m.devices, nil
}
func (m *listingDeviceManager) RestoreDevice([]byte) (types.Device, error) { return nil, nil }

func TestStateDBTables(t *testing.T) {
	t.Run("write device table via commitAllocation", func(t *testing.T) {
		d, db, devTbl := buildDriverWithTables(t)

		podUID := kubetypes.UID("pod-commit-1")
		claimUID := kubetypes.UID("claim-commit-1")

		dev := &trackedDevice{name: "eth0"}
		allocs := []allocation{
			{Device: dev, Config: types.DeviceConfig{PodIfName: "eth-pod"}, Manager: types.DeviceManagerTypeMock},
		}

		d.commitAllocation(podUID, claimUID, allocs, nil)

		rtxn := db.ReadTxn()
		row, _, ok := devTbl.Get(rtxn, DeviceByName("eth0"))
		require.True(t, ok)
		require.Equal(t, podUID, row.PodUID)
		require.Equal(t, claimUID, row.ClaimUID)
		require.Equal(t, "eth-pod", row.Config.PodIfName)
		require.Equal(t, types.DeviceManagerTypeMock, row.Manager)
	})

	t.Run("multiple claims", func(t *testing.T) {
		d, db, devTbl := buildDriverWithTables(t)

		podUID := kubetypes.UID("pod-multi")
		claimUID1 := kubetypes.UID("claim-multi-1")
		claimUID2 := kubetypes.UID("claim-multi-2")

		d.commitAllocation(podUID, claimUID1, []allocation{
			{Device: &trackedDevice{name: "eth0"}, Manager: types.DeviceManagerTypeMock},
		}, nil)
		d.commitAllocation(podUID, claimUID2, []allocation{
			{Device: &trackedDevice{name: "eth1"}, Manager: types.DeviceManagerTypeMock},
		}, nil)

		rtxn := db.ReadTxn()
		var found []string
		for row := range devTbl.List(rtxn, DeviceByPodUID(podUID)) {
			found = append(found, row.Name)
		}
		require.ElementsMatch(t, []string{"eth0", "eth1"}, found)
	})

	t.Run("unprepare resource claim clears allocation fields", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(hivetest.Logger(t))

		d, db, devTbl := buildDriverWithTables(t)
		d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: prepTestDriverName}

		dev := &trackedDevice{name: prepTestDev0}
		// Insert the device into the table so unprepare can look it up.
		txn := db.WriteTxn(devTbl)
		devTbl.Insert(txn, &Device{
			Name:     prepTestDev0,
			Manager:  types.DeviceManagerTypeMock,
			Dev:      dev,
			PodUID:   prepTestPodUID,
			ClaimUID: prepTestClaimUID,
		})
		txn.Commit()

		// Confirm it is allocated.
		rtxn := db.ReadTxn()
		row, _, ok := devTbl.Get(rtxn, DeviceByName(prepTestDev0))
		require.True(t, ok)
		require.True(t, row.IsAllocated())

		// Unprepare.
		claim := buildPrepClaim(prepTestDev0)
		createPrepClaim(t, cs, claim)
		err := d.unprepareResourceClaim(t.Context(), kubeletplugin.NamespacedObject{
			NamespacedName: kubetypes.NamespacedName{Namespace: prepTestClaimNS, Name: prepTestClaimName},
			UID:            prepTestClaimUID,
		})

		require.NoError(t, err)

		// Allocation fields must be cleared; row still exists.
		rtxn2 := db.ReadTxn()
		row2, _, ok := devTbl.Get(rtxn2, DeviceByName(prepTestDev0))
		require.True(t, ok, "Device row must still exist after unprepare")
		require.False(t, row2.IsAllocated(), "Device must be unallocated after unprepare")
	})

	t.Run("restore devices from claim populates table", func(t *testing.T) {
		d, db, devTbl := buildDriverWithTables(t)
		d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: prepTestDriverName}
		d.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
			types.DeviceManagerTypeMock: &mockDeviceManager{},
		}

		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)
		require.NoError(t, d.restoreDevicesFromClaim(claim))

		rtxn := db.ReadTxn()
		row, _, ok := devTbl.Get(rtxn, DeviceByName(prepTestDev0))
		require.True(t, ok)
		require.Equal(t, prepTestPodUID, row.PodUID)
		require.Equal(t, prepTestClaimUID, row.ClaimUID)
		require.Equal(t, prepTestDev0, row.Name)
	})

	t.Run("get device pools writes Device table", func(t *testing.T) {
		d, db, devTbl := buildDriverWithTables(t)

		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}

		d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-x", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
		}

		d.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
			types.DeviceManagerTypeMock: &listingDeviceManager{devices: []types.Device{dev0, dev1}},
		}

		_, err := d.getDevicePools(t.Context())
		require.NoError(t, err)

		rtxn := db.ReadTxn()

		got0, _, ok := devTbl.Get(rtxn, DeviceByName("eth0"))
		require.True(t, ok)
		require.Equal(t, "pool-x", got0.Pool)

		got1, _, ok := devTbl.Get(rtxn, DeviceByName("eth1"))
		require.True(t, ok)
		require.Equal(t, "pool-x", got1.Pool)
	})

	t.Run("get device pools prunes stale unallocated devices from table", func(t *testing.T) {
		d, db, devTbl := buildDriverWithTables(t)

		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}

		d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
			Pools: []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-y", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
		}

		lm := &listingDeviceManager{devices: []types.Device{dev0, dev1}}
		d.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
			types.DeviceManagerTypeMock: lm,
		}

		// First call: both devices present.
		_, err := d.getDevicePools(t.Context())
		require.NoError(t, err)

		rtxn := db.ReadTxn()
		_, _, ok := devTbl.Get(rtxn, DeviceByName("eth1"))
		require.True(t, ok)

		// Second call: eth1 removed.
		lm.devices = []types.Device{dev0}

		_, err = d.getDevicePools(t.Context())
		require.NoError(t, err)

		rtxn2 := db.ReadTxn()
		_, _, ok = devTbl.Get(rtxn2, DeviceByName("eth1"))
		require.False(t, ok, "stale unallocated device must be pruned from Device table")

		_, _, ok = devTbl.Get(rtxn2, DeviceByName("eth0"))
		require.True(t, ok, "eth0 must still be present")
	})

	t.Run("test remember network namespace map", func(t *testing.T) {
		d, _, _ := buildDriverWithTables(t)

		require.Equal(t, "/run/netns/abc", d.rememberNetworkNamespace(podSandbox("pod-ns-1", "/run/netns/abc")))

		// Map must have the entry.
		require.Equal(t, "/run/netns/abc", d.podNetns[kubetypes.UID("pod-ns-1")])
	})

	t.Run("test remember network namespace host ns not cached", func(t *testing.T) {
		d, _, _ := buildDriverWithTables(t)
		require.Empty(t, d.rememberNetworkNamespace(podSandbox("pod-hostnet", "")))
		_, ok := d.podNetns[kubetypes.UID("pod-hostnet")]
		require.False(t, ok)
	})

	t.Run("get network namespace falls back to the map", func(t *testing.T) {
		d, _, _ := buildDriverWithTables(t)

		// Pre-populate the map (simulating what rememberNetworkNamespace wrote).
		d.podNetns[kubetypes.UID("pod-fallback")] = "/run/netns/fallback"

		// Pod sandbox with no namespaces (containerd < 2.1 scenario).
		require.Equal(t, "/run/netns/fallback", d.getNetworkNamespace(podSandbox("pod-fallback", "")))
	})

	t.Run("get network namespace prefers sandbox namespace over map", func(t *testing.T) {
		d, _, _ := buildDriverWithTables(t)

		// Map has a stale value.
		d.podNetns[kubetypes.UID("pod-prefer")] = "/run/netns/stale"

		// Sandbox carries the real namespace.
		require.Equal(t, "/run/netns/real", d.getNetworkNamespace(podSandbox("pod-prefer", "/run/netns/real")), "sandbox namespace must take precedence over map")
	})

	t.Run("test stoppodsandbox deletes pod netns map entry on success", func(t *testing.T) {
		d, _, _ := buildDriverWithTables(t)

		// RunPodSandbox: populate map.
		sbRun := podSandbox("pod-stop-1", "/run/netns/xyz")
		_ = d.rememberNetworkNamespace(sbRun)

		require.Equal(t, "/run/netns/xyz", d.podNetns[kubetypes.UID("pod-stop-1")])

		// StopPodSandbox: no namespaces (containerd < 2.1), no allocation → no-op except cleanup.
		require.NoError(t, d.StopPodSandbox(context.Background(), podSandbox("pod-stop-1", "")))

		// Map entry must be deleted.
		_, ok := d.podNetns[kubetypes.UID("pod-stop-1")]
		require.False(t, ok, "podNetns map entry must be deleted after StopPodSandbox")
	})
}

func TestContainerd21Bug_EndToEnd(t *testing.T) {
	// Full sequence:
	//   1. Synchronize is called with a live pod (namespaces populated) → map written
	//   2. StopPodSandbox is called with empty namespaces (containerd < 2.1 scenario)
	//      → getNetworkNamespace falls back to map → returns correct path → entry cleaned up
	d, _, _ := buildDriverWithTables(t)

	const podUID = "pod-ct21-bug"
	const netnsPath = "/run/netns/cni-ct21"

	// Step 1: Synchronize populates map via rememberNetworkNamespace.
	_, err := d.Synchronize(context.Background(), []*api.PodSandbox{
		podSandbox(podUID, netnsPath),
	}, nil)
	require.NoError(t, err)

	require.Equal(t, netnsPath, d.podNetns[kubetypes.UID(podUID)])

	// Step 2: StopPodSandbox arrives with no namespaces.
	sbStop := podSandbox(podUID, "")
	// No allocation for this pod → StopPodSandbox exits early but still cleans up.
	err = d.StopPodSandbox(context.Background(), sbStop)
	require.NoError(t, err)

	// Verify entry is cleaned up.
	_, ok := d.podNetns[kubetypes.UID(podUID)]
	require.False(t, ok, "podNetns map entry must be evicted after StopPodSandbox")
}
