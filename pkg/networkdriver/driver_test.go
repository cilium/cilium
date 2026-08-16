// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for pure logic in driver.go and nri.go that requires no real kernel or
// cluster:
//
//   driver.go
//   - filterDevices        — filter a device slice by a match predicate
//   - resolvePoolAssignments — device→pool resolution with tie-break and stability
//   - buildPools           — pool map construction from resolved assignments
//   - restoreDevicesFromClaim — rebuild in-memory allocations from claim status
//
//   nri.go
//   - getNetworkNamespace  — prefer NRI namespace over cached fallback
//   - rememberNetworkNamespace — cache population
//   - Synchronize          — lock + bulk cache population

import (
	"encoding/json"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// newTestAllocDB creates a minimal in-process statedb.DB with the Device table
// wired in, for use in unit tests that need to populate device state without a
// full Driver or Hive.
func newTestAllocDB(t *testing.T) (*statedb.DB, statedb.RWTable[*Device]) {
	t.Helper()
	db := statedb.New()
	devTbl, err := NewDeviceTable(db)
	require.NoError(t, err)
	return db, devTbl
}

// ---------------------------------------------------------------------------
// Minimal mock device manager (for restoreDevicesFromClaim)
// ---------------------------------------------------------------------------

// mockDeviceManager implements types.DeviceManager using trackedDevice.
type mockDeviceManager struct{}

func (m *mockDeviceManager) Type() types.DeviceManagerType { return types.DeviceManagerTypeMock }

func (m *mockDeviceManager) ListDevices() ([]types.Device, error) { return nil, nil }

func (m *mockDeviceManager) RestoreDevice(data []byte) (types.Device, error) {
	d := &trackedDevice{}
	if err := d.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return d, nil
}

// buildDriverForPool builds a minimal *Driver ready for pool-related tests.
// It has no real device managers; caller can populate statedb table directly.
func buildDriverForPool(t *testing.T, pools []v2alpha1.CiliumNetworkDriverDevicePoolConfig, devsByMgr map[types.DeviceManagerType][]types.Device) *Driver {
	t.Helper()
	db, devTbl := newTestAllocDB(t)
	// Pre-populate the device table from the supplied devsByMgr map.
	if len(devsByMgr) > 0 {
		txn := db.WriteTxn(devTbl)
		for mgr, devs := range devsByMgr {
			for _, dev := range devs {
				devTbl.Insert(txn, &Device{
					Name:    dev.IfName(),
					Manager: mgr,
					Dev:     dev,
				})
			}
		}
		txn.Commit()
	}
	d := &Driver{
		logger: hivetest.Logger(t),
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
			Pools:      pools,
		},
		db:          db,
		deviceTable: devTbl,
		podNetns:    make(map[kubetypes.UID]string),
	}
	return d
}

// matchingDevice is a trackedDevice whose Match() returns the supplied bool.
// GetAttrs returns an initialised (non-nil) map so buildPools can write into it.
type matchingDevice struct {
	trackedDevice
	matches bool
}

func (m *matchingDevice) Match(_ v2alpha1.CiliumNetworkDriverDeviceFilter) bool { return m.matches }

func (m *matchingDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	return make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
}

// podSandbox builds a minimal NRI PodSandbox with an optional network namespace.
func podSandbox(uid, netnsPath string) *api.PodSandbox {
	sb := &api.PodSandbox{
		Uid:   uid,
		Linux: &api.LinuxPodSandbox{},
	}
	if netnsPath != "" {
		sb.Linux.Namespaces = []*api.LinuxNamespace{
			{Type: "network", Path: netnsPath},
		}
	}
	return sb
}

// buildNRIDriver builds a *Driver suitable for NRI-related tests.
func buildNRIDriver(t *testing.T) *Driver {
	t.Helper()
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)
	d := buildPrepDriver(t, cs)
	return d
}

func TestFilterDevices(t *testing.T) {
	t.Run("no match returns empty slice", func(t *testing.T) {
		devs := []types.Device{
			&matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: false},
			&matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: false},
		}
		got := filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{})
		require.Empty(t, got)
	})

	t.Run("all match returns all devices", func(t *testing.T) {
		devs := []types.Device{
			&matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true},
			&matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true},
		}
		got := filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{})
		require.Len(t, got, 2)
	})

	t.Run("partial match returns only matching devices", func(t *testing.T) {
		devs := []types.Device{
			&matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true},
			&matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: false},
		}
		got := filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{})
		require.Len(t, got, 1)
		require.Equal(t, "eth0", got[0].IfName())
	})

	t.Run("dummy devices filtered by manager type", func(t *testing.T) {
		mgr, err := dummy.NewManager(hivetest.Logger(t), &v2alpha1.DummyDeviceManagerConfig{Count: 3})
		require.NoError(t, err)
		devs, err := mgr.ListDevices()
		require.NoError(t, err)

		// Filter by dummy manager — all three must match.
		got := filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{
			DeviceManagers: []string{types.DeviceManagerTypeDummy.String()},
		})
		require.Len(t, got, 3)

		// Filter by a different manager — none must match.
		require.Empty(t, filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{
			DeviceManagers: []string{"sriov"},
		}))

		// IfName filter matching only dummy1 — exactly one must match.
		got = filterDevices(devs, v2alpha1.CiliumNetworkDriverDeviceFilter{
			IfNames: []string{"dummy1"},
		})
		require.Len(t, got, 1)
		require.Equal(t, "dummy1", got[0].IfName())
	})
}

func TestResolvePoolAssignments(t *testing.T) {
	t.Run("single pool assigns device", func(t *testing.T) {
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeMock: {dev},
			},
		)

		devicePool := driver.resolvePoolAssignments(t.Context(), []types.Device{dev})
		require.Equal(t, map[string]string{"eth0": "pool-a"}, devicePool)
	})

	t.Run("two pools honour prior assignment for stability", func(t *testing.T) {
		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}

		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "alpha", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
				{PoolName: "beta", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
			nil,
		)
		// Pre-populate previous assignments in the device table.
		txn := driver.db.WriteTxn(driver.deviceTable)
		driver.deviceTable.Insert(txn, &Device{Name: "eth0", Pool: "alpha"})
		driver.deviceTable.Insert(txn, &Device{Name: "eth1", Pool: "beta"})
		txn.Commit()

		devicePool := driver.resolvePoolAssignments(t.Context(), []types.Device{dev0, dev1})
		require.Equal(t, "alpha", devicePool["eth0"])
		require.Equal(t, "beta", devicePool["eth1"])
	})

	t.Run("stable across reconcile cycles", func(t *testing.T) {
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
				{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
			nil,
		)

		first := driver.resolvePoolAssignments(t.Context(), []types.Device{dev})
		require.Equal(t, "pool-a", first["eth0"])

		second := driver.resolvePoolAssignments(t.Context(), []types.Device{dev})
		require.Equal(t, "pool-a", second["eth0"], "assignment must be stable across reconcile cycles")
	})

	t.Run("pool with nil filter is skipped", func(t *testing.T) {
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "no-filter", Filter: nil},
			},
			nil,
		)

		devicePool := driver.resolvePoolAssignments(t.Context(), []types.Device{dev})
		require.Empty(t, devicePool, "pool with nil filter must be skipped entirely")
	})
}

func TestBuildPools(t *testing.T) {
	t.Run("empty devices pre-populates pool with empty slice", func(t *testing.T) {
		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
			nil,
		)

		pools := driver.buildPools(nil, nil)
		require.Contains(t, pools, "pool-a")
		require.Empty(t, pools["pool-a"].Slices[0].Devices)
	})

	t.Run("devices added to correct pool", func(t *testing.T) {
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver := buildDriverForPool(t,
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
			nil,
		)

		devicePool := map[string]string{"eth0": "pool-a"}
		pools := driver.buildPools([]types.Device{dev}, devicePool)

		require.Contains(t, pools, "pool-a")
		require.Len(t, pools["pool-a"].Slices[0].Devices, 1)
		require.Equal(t, "eth0", pools["pool-a"].Slices[0].Devices[0].Name)
	})

	t.Run("dummy devices assigned to pool", func(t *testing.T) {
		driver := buildDriverWithDummyManager(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			dummyPoolConfig("dummy-pool"),
		})

		// Get all available devices from statedb (populated by buildDriverWithDummyManager).
		rtxn := driver.db.ReadTxn()
		var allDevices []types.Device
		for row := range driver.deviceTable.All(rtxn) {
			allDevices = append(allDevices, row.Dev)
		}
		devicePool := driver.resolvePoolAssignments(t.Context(), allDevices)
		pools := driver.buildPools(allDevices, devicePool)

		require.Contains(t, pools, "dummy-pool")
		require.Len(t, pools["dummy-pool"].Slices[0].Devices, 2,
			"both dummy devices must appear in the pool")
	})
}

func buildClaimWithDeviceStatus(t *testing.T, driverName string, podUID, claimUID kubetypes.UID, devName string) *resourceapi.ResourceClaim {
	t.Helper()

	dev := &trackedDevice{name: devName}
	devData, err := dev.MarshalBinary()
	require.NoError(t, err)

	serialized, err := json.Marshal(types.SerializedDevice{
		Manager: types.DeviceManagerTypeMock,
		Dev:     devData,
		Config:  types.DeviceConfig{PodIfName: "eth-pod"},
	})
	require.NoError(t, err)

	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-claim", Namespace: "default", UID: claimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", UID: podUID},
			},
			Devices: []resourceapi.AllocatedDeviceStatus{
				{
					Driver: driverName,
					Pool:   "test-pool",
					Device: devName,
					Data:   &runtime.RawExtension{Raw: serialized},
				},
			},
		},
	}
}

func TestRestoreDevicesFromClaim(t *testing.T) {
	tlog := hivetest.Logger(t)

	buildDriver := func(t *testing.T) *Driver {
		t.Helper()
		cs, _ := k8sClient.NewFakeClientset(tlog)
		driver := buildPrepDriver(t, cs)
		driver.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: prepTestDriverName}
		driver.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
			types.DeviceManagerTypeMock: &mockDeviceManager{},
		}
		return driver
	}

	t.Run("success restores allocation", func(t *testing.T) {
		driver := buildDriver(t)
		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)

		err := driver.restoreDevicesFromClaim(claim)
		require.NoError(t, err)

		rtxn := driver.db.ReadTxn()
		row, _, ok := driver.deviceTable.Get(rtxn, DeviceByName(prepTestDev0))
		require.True(t, ok)
		require.Equal(t, prepTestDev0, row.Name)
		require.Equal(t, prepTestPodUID, row.PodUID)
		require.Equal(t, "eth-pod", row.Config.PodIfName)
	})

	t.Run("wrong driver is skipped without error", func(t *testing.T) {
		driver := buildDriver(t)
		claim := buildClaimWithDeviceStatus(t, "other.driver.io", prepTestPodUID, prepTestClaimUID, prepTestDev0)

		err := driver.restoreDevicesFromClaim(claim)
		require.NoError(t, err)
		// table must have no allocated rows
		rtxn := driver.db.ReadTxn()
		var count int
		for row := range driver.deviceTable.All(rtxn) {
			if row.IsAllocated() {
				count++
			}
		}
		require.Zero(t, count)
	})

	t.Run("unknown device manager returns error", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		driver := buildPrepDriver(t, cs)
		driver.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: prepTestDriverName}
		driver.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{} // empty

		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)

		err := driver.restoreDevicesFromClaim(claim)
		require.Error(t, err, "unknown device manager must return an error")
		// table must have no allocated rows
		if driver.deviceTable != nil {
			rtxn := driver.db.ReadTxn()
			var count int
			for row := range driver.deviceTable.All(rtxn) {
				if row.IsAllocated() {
					count++
				}
			}
			require.Zero(t, count)
		}
	})

	t.Run("allocated and reserved but no devices logs warning without error", func(t *testing.T) {
		driver := buildDriver(t)

		claim := &resourceapi.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "test-claim", Namespace: "default"},
			Status: resourceapi.ResourceClaimStatus{
				Allocation:  &resourceapi.AllocationResult{},
				ReservedFor: []resourceapi.ResourceClaimConsumerReference{{Resource: "pods", UID: "pod-uid"}},
				Devices:     nil,
			},
		}

		err := driver.restoreDevicesFromClaim(claim)
		require.NoError(t, err)
		// table must have no allocated rows
		rtxn := driver.db.ReadTxn()
		var count int
		for row := range driver.deviceTable.All(rtxn) {
			if row.IsAllocated() {
				count++
			}
		}
		require.Zero(t, count)
	})

	t.Run("dummy device restored via real DummyManager", func(t *testing.T) {
		driver := buildDriverWithDummyManager(t, nil)

		dev := &dummy.DummyDevice{Name: "dummy0"}
		devData, err := dev.MarshalBinary()
		require.NoError(t, err)

		serialized, err := json.Marshal(types.SerializedDevice{
			Manager: types.DeviceManagerTypeDummy,
			Dev:     devData,
			Config:  types.DeviceConfig{PodIfName: "eth0"},
		})
		require.NoError(t, err)

		claim := &resourceapi.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "test-claim", Namespace: "default", UID: prepTestClaimUID},
			Status: resourceapi.ResourceClaimStatus{
				ReservedFor: []resourceapi.ResourceClaimConsumerReference{
					{Resource: "pods", UID: prepTestPodUID},
				},
				Devices: []resourceapi.AllocatedDeviceStatus{
					{
						Driver: prepTestDriverName,
						Pool:   "dummy-pool",
						Device: "dummy0",
						Data:   &runtime.RawExtension{Raw: serialized},
					},
				},
			},
		}

		require.NoError(t, driver.restoreDevicesFromClaim(claim))

		rtxn := driver.db.ReadTxn()
		row, _, ok := driver.deviceTable.Get(rtxn, DeviceByName("dummy0"))
		require.True(t, ok)
		require.Equal(t, "dummy0", row.Name)
		require.Equal(t, prepTestPodUID, row.PodUID)
		require.Equal(t, "eth0", row.Config.PodIfName)
		require.Equal(t, types.DeviceManagerTypeDummy, row.Manager)
	})
}

func TestGetNetworkNamespace(t *testing.T) {
	t.Run("reads namespace from NRI sandbox", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-1", "/run/netns/abc")

		ns := d.getNetworkNamespace(sb)
		require.Equal(t, "/run/netns/abc", ns)
	})

	t.Run("falls back to map when sandbox has no namespaces", func(t *testing.T) {
		d := buildNRIDriver(t)
		// Pre-populate the podNetns map.
		d.podNetns[kubetypes.UID("pod-uid-2")] = "/run/netns/cached"
		sb := podSandbox("pod-uid-2", "")

		ns := d.getNetworkNamespace(sb)
		require.Equal(t, "/run/netns/cached", ns)
	})

	t.Run("empty when neither sandbox nor map has namespace", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-3", "")

		ns := d.getNetworkNamespace(sb)
		require.Empty(t, ns)
	})
}

func TestRememberNetworkNamespace(t *testing.T) {
	t.Run("stores and returns namespace path", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-4", "/run/netns/xyz")

		returned := d.rememberNetworkNamespace(sb)
		require.Equal(t, "/run/netns/xyz", returned)

		// Verify stored in the map.
		require.Equal(t, "/run/netns/xyz", d.podNetns["pod-uid-4"])
	})

	t.Run("host-network pod returns empty and is not cached", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-5", "")

		returned := d.rememberNetworkNamespace(sb)
		require.Empty(t, returned)

		// Must not be in the map.
		require.NotContains(t, d.podNetns, "pod-uid-5")
	})
}

func TestSynchronize(t *testing.T) {
	t.Run("caches all namespaces except host-network", func(t *testing.T) {
		d := buildNRIDriver(t)

		pods := []*api.PodSandbox{
			podSandbox("uid-a", "/run/netns/a"),
			podSandbox("uid-b", "/run/netns/b"),
			podSandbox("uid-c", ""), // host-network — must not be cached
		}

		updates, err := d.Synchronize(t.Context(), pods, nil)
		require.NoError(t, err)
		require.Nil(t, updates)

		require.Equal(t, "/run/netns/a", d.podNetns["uid-a"])
		require.Equal(t, "/run/netns/b", d.podNetns["uid-b"])
		require.NotContains(t, d.podNetns, "uid-c")
	})

	t.Run("empty input is a no-op", func(t *testing.T) {
		d := buildNRIDriver(t)
		updates, err := d.Synchronize(t.Context(), nil, nil)
		require.NoError(t, err)
		require.Nil(t, updates)
		require.Empty(t, d.podNetns)
	})
}

// ---------------------------------------------------------------------------
// DummyDevice-based extensions — real DummyManager wired into driver logic
// ---------------------------------------------------------------------------

// buildDriverWithDummyManager returns a *Driver whose deviceManagers map
// contains a real DummyManager with count=2. It also seeds the deviceTable
// by calling ListDevices so pool-resolution helpers have real devices to work
// with. No netlink calls are made here — that only happens in Setup/Free.
func buildDriverWithDummyManager(t *testing.T, pools []v2alpha1.CiliumNetworkDriverDevicePoolConfig) *Driver {
	t.Helper()
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	mgr, err := dummy.NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 2})
	require.NoError(t, err)

	devs, err := mgr.ListDevices()
	require.NoError(t, err)

	d := buildPrepDriver(t, cs)
	d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
		DriverName: prepTestDriverName,
		Pools:      pools,
	}
	d.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
		types.DeviceManagerTypeDummy: mgr,
	}

	// Seed the statedb device table.
	txn := d.db.WriteTxn(d.deviceTable)
	for _, dev := range devs {
		d.deviceTable.Insert(txn, &Device{
			Name:    dev.IfName(),
			Manager: types.DeviceManagerTypeDummy,
			Dev:     dev,
		})
	}
	txn.Commit()

	return d
}

// dummyPoolConfig returns a single pool config whose filter accepts all dummy
// devices (empty DeviceManagers list means "any").
func dummyPoolConfig(name string) v2alpha1.CiliumNetworkDriverDevicePoolConfig {
	return v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		PoolName: name,
		Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{
			DeviceManagers: []string{types.DeviceManagerTypeDummy.String()},
		},
	}
}

// ---------------------------------------------------------------------------
// podForClaim tests — declared here since they use buildPodForClaimDriver
// which depends on buildPrepDriver (in prepare_test.go).
// ---------------------------------------------------------------------------

func TestGetNetworkNamespaceFallback(t *testing.T) {
	// This is a regression test for the containerd < 2.1 scenario where
	// StopPodSandbox carries no namespaces; the driver must fall back to the
	// cached map entry set at RunPodSandbox / Synchronize time.
	d := buildNRIDriver(t)

	const uid = "pod-fallback-regression"
	d.podNetns[kubetypes.UID(uid)] = "/run/netns/fallback"
	require.Equal(t, "/run/netns/fallback", d.getNetworkNamespace(podSandbox(uid, "")))
}
