// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

// Tests for pure logic in driver.go and nri.go that requires no real kernel or
// cluster:
//
//   driver.go
//   - onDevices            — write device set from a manager into the statedb table
//   - resolvePool          — single-device pool resolution
//   - buildPoolsFromTable  — pool map construction from statedb table snapshot
//   - restoreDevicesFromClaim — rebuild in-memory allocations from claim status
//
//   nri.go
//   - getNetworkNamespace  — prefer NRI namespace over cached fallback
//   - rememberNetworkNamespace — cache population
//   - Synchronize          — lock + bulk cache population

import (
	"context"
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

// ---------------------------------------------------------------------------
// Minimal mock device manager (for restoreDevicesFromClaim)
// ---------------------------------------------------------------------------

// mockDeviceManager implements types.DeviceManager using trackedDevice.
// Run publishes devices once and then blocks until ctx is cancelled.
type mockDeviceManager struct {
	devices []types.Device
}

func (m *mockDeviceManager) Run(ctx context.Context, publish func([]types.Device)) error {
	publish(m.devices)
	<-ctx.Done()
	return nil
}

func (m *mockDeviceManager) Type() types.DeviceManagerType { return types.DeviceManagerTypeMock }

func (m *mockDeviceManager) RestoreDevice(data []byte) (types.Device, error) {
	d := &trackedDevice{}
	if err := d.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return d, nil
}

// buildDriverForPool builds a minimal *Driver ready for pool-related tests.
// It has a statedb device table but no device managers; devices are written
// directly via onDevices in individual tests.
func buildDriverForPool(t *testing.T, pools []v2alpha1.CiliumNetworkDriverDevicePoolConfig) *Driver {
	t.Helper()
	db := statedb.New()
	tbl, err := newDeviceTable(db)
	require.NoError(t, err)
	d := &Driver{
		logger: hivetest.Logger(t),
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
			Pools:      pools,
		},
		db:          db,
		deviceTable: tbl,
		podNetns:    make(map[kubetypes.UID]string),
	}
	return d
}

// matchingDevice is a trackedDevice whose Match() returns the supplied bool.
// GetAttrs returns a non-nil map; attrsToPartMap handles it without issue.
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
	d.podNetns = make(map[kubetypes.UID]string)
	return d
}

func TestOnDevices(t *testing.T) {
	t.Run("device matching a pool is inserted into table", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.True(t, found)
		require.Equal(t, "eth0", row.Name)
		require.Equal(t, "pool-a", row.Pool)
	})

	t.Run("device matching no pool is not inserted", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames: []string{"eth1"}, // only eth1 matches
			}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: false}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.False(t, found)
	})

	t.Run("device no longer reported is deleted from table", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})

		// First publish: two devices.
		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev0, dev1}, func(statedb.WriteTxn) {})

		// Second publish: only eth0.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev0}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found0 := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.True(t, found0, "eth0 must remain")
		_, _, found1 := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth1")))
		require.False(t, found1, "eth1 must be removed")
	})

	t.Run("deletion is scoped to the calling manager", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})

		// Insert a dummy-manager device directly.
		wtxn := driver.db.WriteTxn(driver.deviceTable)
		driver.deviceTable.Insert(wtxn, &DRADevice{
			Name:    "dummy0",
			Manager: types.DeviceManagerTypeDummy,
			Pool:    "pool-a",
		})
		wtxn.Commit()

		// Mock manager reports empty set — should not touch dummy0.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "dummy0")))
		require.True(t, found, "dummy manager's device must not be deleted by mock manager")
	})

	t.Run("pool with nil filter is skipped", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "no-filter", Filter: nil},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		var count int
		for range driver.deviceTable.All(txn) {
			count++
		}
		require.Zero(t, count, "nil-filter pool must not admit any devices")
	})

	t.Run("device matches multiple pools — assigned to first alphabetically", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "beta", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "alpha", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, inAlpha := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("alpha", "eth0")))
		_, _, inBeta := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("beta", "eth0")))
		require.True(t, inAlpha, "eth0 must be in alpha (first alphabetically)")
		require.False(t, inBeta, "eth0 must not be in beta")
	})

	t.Run("Merge carries KernelIfName forward when a rescan cannot determine one", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})

		// First scan: device manager reports a live kernel interface name.
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0", kernelIfName: "keth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev1}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName())

		// Second scan: the device has moved into a pod's netns, so the fresh
		// scan can no longer determine a kernel interface name.
		dev2 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev2}, func(statedb.WriteTxn) {})

		txn = driver.db.ReadTxn()
		row, _, found = driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName(),
			"Merge must carry the previous KernelIfName forward when the fresh scan has none")
	})
}

func TestResolvePool(t *testing.T) {
	t.Run("single matching pool returns that pool", func(t *testing.T) {
		driver := buildDriverForPool(t, nil)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		}
		got := driver.resolvePool(dev, pools)
		require.Equal(t, "pool-a", got)
	})

	t.Run("no matching pool returns empty string", func(t *testing.T) {
		driver := buildDriverForPool(t, nil)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: false}
		pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		}
		got := driver.resolvePool(dev, pools)
		require.Empty(t, got)
	})

	t.Run("pool with nil filter is skipped", func(t *testing.T) {
		driver := buildDriverForPool(t, nil)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "no-filter", Filter: nil},
		}
		got := driver.resolvePool(dev, pools)
		require.Empty(t, got)
	})

	t.Run("multiple matches returns first alphabetically", func(t *testing.T) {
		driver := buildDriverForPool(t, nil)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		// Pools already sorted alphabetically (as onDevices does before calling resolvePool).
		pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "alpha", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "beta", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		}
		got := driver.resolvePool(dev, pools)
		require.Equal(t, "alpha", got)
	})
}

func TestBuildPoolsFromTable(t *testing.T) {
	t.Run("empty table pre-populates configured pools with empty slices", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})

		pools := driver.buildPoolsFromTable()
		require.Contains(t, pools, "pool-a")
		require.Empty(t, pools["pool-a"].Slices[0].Devices)
	})

	t.Run("devices in table appear in their pool", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		pools := driver.buildPoolsFromTable()
		require.Contains(t, pools, "pool-a")
		require.Len(t, pools["pool-a"].Slices[0].Devices, 1)
		require.Equal(t, "eth0", pools["pool-a"].Slices[0].Devices[0].Name)
	})

	t.Run("nil-filter pool is excluded", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "no-filter", Filter: nil},
		})
		pools := driver.buildPoolsFromTable()
		require.NotContains(t, pools, "no-filter")
	})

	t.Run("dummy devices assigned to pool via onDevices", func(t *testing.T) {
		driver := buildDriverWithDummyManager(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			dummyPoolConfig("dummy-pool"),
		})

		ctx, cancel := context.WithCancel(t.Context())
		published := make(chan struct{})
		go func() {
			driver.deviceManagers[types.DeviceManagerTypeDummy].Run(ctx, func(devs []types.Device) {
				driver.onDevices(types.DeviceManagerTypeDummy, devs, func(statedb.WriteTxn) {})
				close(published)
			})
		}()
		<-published
		cancel()

		pools := driver.buildPoolsFromTable()
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

		wtxn := driver.db.WriteTxn(driver.deviceTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var rows []*DRADevice
		for row := range DevicesByClaimUID(driver.deviceTable, txn, prepTestClaimUID) {
			rows = append(rows, row)
		}
		require.Len(t, rows, 1)
		require.Equal(t, prepTestDev0, rows[0].Name)
		require.Equal(t, "eth-pod", rows[0].Config.PodIfName)
		require.Equal(t, prepTestPodUID, rows[0].PodUID)
	})

	t.Run("wrong driver is skipped without error", func(t *testing.T) {
		driver := buildDriver(t)
		claim := buildClaimWithDeviceStatus(t, "other.driver.io", prepTestPodUID, prepTestClaimUID, prepTestDev0)

		wtxn := driver.db.WriteTxn(driver.deviceTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var count int
		for range driver.deviceTable.All(txn) {
			count++
		}
		require.Zero(t, count)
	})

	t.Run("unknown device manager returns error", func(t *testing.T) {
		cs, _ := k8sClient.NewFakeClientset(tlog)
		driver := buildPrepDriver(t, cs)
		driver.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{DriverName: prepTestDriverName}
		driver.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{} // empty

		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)

		wtxn := driver.db.WriteTxn(driver.deviceTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.Error(t, err, "unknown device manager must return an error")

		txn := driver.db.ReadTxn()
		var count int
		for range driver.deviceTable.All(txn) {
			count++
		}
		require.Zero(t, count)
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

		wtxn := driver.db.WriteTxn(driver.deviceTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var count int
		for range driver.deviceTable.All(txn) {
			count++
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

		wtxn := driver.db.WriteTxn(driver.deviceTable)
		require.NoError(t, driver.restoreDevicesFromClaim(claim, wtxn))
		wtxn.Commit()

		txn := driver.db.ReadTxn()
		var rows []*DRADevice
		for row := range DevicesByClaimUID(driver.deviceTable, txn, prepTestClaimUID) {
			rows = append(rows, row)
		}
		require.Len(t, rows, 1)
		require.Equal(t, "dummy0", rows[0].Name)
		require.Equal(t, "eth0", rows[0].Config.PodIfName)
		require.Equal(t, types.DeviceManagerTypeDummy, rows[0].Manager)
		require.Equal(t, prepTestPodUID, rows[0].PodUID)
	})
}

func TestGetNetworkNamespace(t *testing.T) {
	t.Run("reads namespace from NRI sandbox", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-1", "/run/netns/abc")

		ns := d.getNetworkNamespace(sb)
		require.Equal(t, "/run/netns/abc", ns)
	})

	t.Run("falls back to cache when sandbox has no namespaces", func(t *testing.T) {
		d := buildNRIDriver(t)
		d.podNetns["pod-uid-2"] = "/run/netns/cached"
		sb := podSandbox("pod-uid-2", "")

		ns := d.getNetworkNamespace(sb)
		require.Equal(t, "/run/netns/cached", ns)
	})

	t.Run("empty when neither sandbox nor cache has namespace", func(t *testing.T) {
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
		require.Equal(t, "/run/netns/xyz", d.podNetns["pod-uid-4"])
	})

	t.Run("host-network pod returns empty and is not cached", func(t *testing.T) {
		d := buildNRIDriver(t)
		sb := podSandbox("pod-uid-5", "")

		returned := d.rememberNetworkNamespace(sb)
		require.Empty(t, returned)
		require.NotContains(t, d.podNetns, kubetypes.UID("pod-uid-5"))
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
		require.NotContains(t, d.podNetns, kubetypes.UID("uid-c"))
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
// contains a real DummyManager with count=2. It has a statedb device table
// but no devices pre-seeded — call onDevices or Run to populate it.
// No netlink calls are made here — that only happens in Setup/Free.
func buildDriverWithDummyManager(t *testing.T, pools []v2alpha1.CiliumNetworkDriverDevicePoolConfig) *Driver {
	t.Helper()
	tlog := hivetest.Logger(t)
	cs, _ := k8sClient.NewFakeClientset(tlog)

	mgr, err := dummy.NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 2})
	require.NoError(t, err)

	d := buildPrepDriver(t, cs)
	d.config = &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
		DriverName: prepTestDriverName,
		Pools:      pools,
	}
	d.deviceManagers = map[types.DeviceManagerType]types.DeviceManager{
		types.DeviceManagerTypeDummy: mgr,
	}
	d.podNetns = make(map[kubetypes.UID]string)
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
// setAllocationInTable / commitAllocation
// ---------------------------------------------------------------------------

func TestSetAllocationInTable(t *testing.T) {
	pool := "pool-a"
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: pool, Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}

	t.Run("commit writes PodUID and ClaimUID into the matching row", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		allocs := []allocation{{Device: dev, Config: types.DeviceConfig{PodIfName: "dmy0"}, Manager: types.DeviceManagerTypeMock}}
		driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		require.True(t, found)
		require.Equal(t, prepTestPodUID, row.PodUID)
		require.Equal(t, prepTestClaimUID, row.ClaimUID)
		require.Equal(t, "dmy0", row.Config.PodIfName)
	})

	t.Run("clearing resets PodUID, ClaimUID, and Config", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		allocs := []allocation{{Device: dev, Config: types.DeviceConfig{PodIfName: "dmy0"}, Manager: types.DeviceManagerTypeMock}}
		driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)
		driver.setAllocationInTable(allocs, "", "", true)

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		require.True(t, found, "row must still exist after clearing")
		require.Empty(t, row.PodUID, "PodUID must be cleared")
		require.Empty(t, row.ClaimUID, "ClaimUID must be cleared")
		require.Equal(t, types.DeviceConfig{}, row.Config, "Config must be zeroed")
	})

	t.Run("commit when device not yet in table is a no-op (no panic, no phantom row)", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		// table is empty — device manager goroutine has not run yet

		allocs := []allocation{{Device: &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}}, Manager: types.DeviceManagerTypeMock}}
		require.NotPanics(t, func() {
			driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)
		})

		txn := driver.db.ReadTxn()
		var count int
		for range driver.deviceTable.All(txn) {
			count++
		}
		require.Zero(t, count, "no phantom row must be created when device is not in the table")
	})

	t.Run("commit with nil Device in allocation is skipped safely", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		allocs := []allocation{{Device: nil}}
		require.NotPanics(t, func() {
			driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)
		})
	})

	t.Run("only the named device is updated; others are untouched", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev0, dev1}, func(statedb.WriteTxn) {})

		allocs := []allocation{{Device: dev0, Manager: types.DeviceManagerTypeMock}}
		driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)

		txn := driver.db.ReadTxn()
		row0, _, _ := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		row1, _, _ := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth1")))
		require.Equal(t, prepTestPodUID, row0.PodUID, "eth0 must be marked allocated")
		require.Empty(t, row1.PodUID, "eth1 must remain free")
	})
}

// ---------------------------------------------------------------------------
// onDevices — allocation restore path
// ---------------------------------------------------------------------------

func TestOnDevicesAllocationRestore(t *testing.T) {
	pool := "pool-a"
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: pool, Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}

	t.Run("onDevices preserves allocation state written by restoreDevices (post-restart path)", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}

		// Simulate restoreDevices writing allocation state before the device
		// manager goroutine fires: insert a row with PodUID/ClaimUID set.
		wtxn := driver.db.WriteTxn(driver.deviceTable)
		driver.deviceTable.Insert(wtxn, &DRADevice{
			Name:     "eth0",
			Pool:     pool,
			Manager:  types.DeviceManagerTypeMock,
			PodUID:   prepTestPodUID,
			ClaimUID: prepTestClaimUID,
			Config:   types.DeviceConfig{PodIfName: "dmy0"},
		})
		wtxn.Commit()

		// Now onDevices fires for the first time — it must Modify the existing
		// row (preserving allocation state) rather than overwriting it.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		require.True(t, found)
		require.Equal(t, prepTestPodUID, row.PodUID, "PodUID must be preserved by onDevices Modify")
		require.Equal(t, prepTestClaimUID, row.ClaimUID, "ClaimUID must be preserved by onDevices Modify")
		require.Equal(t, "dmy0", row.Config.PodIfName)
		// Live Dev field is updated by onDevices.
		require.Equal(t, dev, row.Dev)
	})

	t.Run("second onDevices call preserves existing row's allocation state", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}

		// First call: inserts the row.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		// Manually set allocation state (as commitAllocation would).
		allocs := []allocation{{Device: dev, Config: types.DeviceConfig{PodIfName: "dmy0"}, Manager: types.DeviceManagerTypeMock}}
		driver.setAllocationInTable(allocs, prepTestPodUID, prepTestClaimUID, false)

		// Second call: device manager fires again (e.g. a re-sync). The existing
		// row's PodUID must survive — onDevices clones the existing row.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		require.True(t, found)
		require.Equal(t, prepTestPodUID, row.PodUID, "PodUID must not be clobbered by subsequent onDevices call")
	})

	t.Run("unallocated device has empty PodUID after onDevices", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}

		// Pre-insert eth0 as allocated; eth1 has no prior row.
		wtxn := driver.db.WriteTxn(driver.deviceTable)
		driver.deviceTable.Insert(wtxn, &DRADevice{
			Name:     "eth0",
			Pool:     pool,
			Manager:  types.DeviceManagerTypeMock,
			PodUID:   prepTestPodUID,
			ClaimUID: prepTestClaimUID,
		})
		wtxn.Commit()

		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev0, dev1}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row0, _, _ := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth0")))
		row1, _, _ := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey(pool, "eth1")))
		require.Equal(t, prepTestPodUID, row0.PodUID, "eth0 is allocated — must have PodUID")
		require.Empty(t, row1.PodUID, "eth1 is free — PodUID must be empty")
	})
}

// ---------------------------------------------------------------------------
// buildPoolsFromTable — pool attribute injection
// ---------------------------------------------------------------------------

func TestBuildPoolsFromTablePoolAttr(t *testing.T) {
	t.Run("pool attribute is injected into published device attributes", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		pools := driver.buildPoolsFromTable()
		devices := pools["pool-a"].Slices[0].Devices
		require.Len(t, devices, 1)

		attr, ok := devices[0].Attributes[types.PoolNameLabel]
		require.True(t, ok, "pool attribute must be present in published device")
		require.NotNil(t, attr.StringValue)
		require.Equal(t, "pool-a", *attr.StringValue)
	})

	t.Run("pool attribute is not stored in the statedb row itself", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByKey.Query(DeviceKey("pool-a", "eth0")))
		require.True(t, found)

		_, hasPoolAttr := row.GetAttr(string(types.PoolNameLabel))
		require.False(t, hasPoolAttr, "pool attribute must not be stored in the statedb row")
	})
}
