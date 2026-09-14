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
//   - podResourceClaimNames — resolve direct and template-generated claim names
//   - restoreDevicesFromClaim — rebuild in-memory allocations from claim status
//
//   nri.go
//   - getNetworkNamespace  — prefer NRI namespace over cached fallback
//   - rememberNetworkNamespace — cache population
//   - Synchronize          — lock + bulk cache population

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

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
	deviceTable, err := newDeviceTable(db)
	require.NoError(t, err)
	allocationTable, err := newAllocationTable(db)
	require.NoError(t, err)
	d := &Driver{
		logger: hivetest.Logger(t),
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			DriverName: prepTestDriverName,
			Pools:      pools,
		},
		db:              db,
		deviceTable:     deviceTable,
		allocationTable: allocationTable,
		podNetns:        make(map[kubetypes.UID]string),
	}
	return d
}

// matchingDevice is a trackedDevice whose Match() returns the supplied bool.
// GetAttrs returns a non-nil map; buildPoolsFromTable handles it without issue.
type matchingDevice struct {
	trackedDevice
	matches bool
}

func (m *matchingDevice) Match(_ v2alpha1.CiliumNetworkDriverDeviceFilter) bool { return m.matches }

func (m *matchingDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	return make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
}

type ifNameMatchingDevice struct {
	trackedDevice
}

func (d *ifNameMatchingDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	return len(filter.IfNames) == 0 || slices.Contains(filter.IfNames, d.name)
}

// mergeTrackingDevice is a trackedDevice whose KernelIfName is mutable and
// whose Merge implements the real copy-forward semantics required by
// types.Device: if the fresh scan did not determine a KernelIfName, adopt the
// old device's value instead of losing it. This exercises the behavior that
// onDevices' Modify closure relies on (unlike trackedDevice/matchingDevice/
// DummyDevice, whose Merge is a no-op because their KernelIfName is always
// derivable).
type mergeTrackingDevice struct {
	trackedDevice
	kernelIfName string
	mergeCalls   int
}

func (m *mergeTrackingDevice) KernelIfName() string { return m.kernelIfName }

func (m *mergeTrackingDevice) Merge(old types.Device) {
	m.mergeCalls++
	if m.kernelIfName == "" {
		m.kernelIfName = old.KernelIfName()
	}
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

func TestPublishLoopRepublishesOnTableChanges(t *testing.T) {
	driver := buildDriverForPool(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	published := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		done <- driver.runPublishLoop(ctx, func(context.Context) error {
			published <- struct{}{}
			return nil
		})
	}()

	waitForPublish := func() {
		t.Helper()
		select {
		case <-published:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for resources to be published")
		}
	}

	waitForPublish()

	wtxn := driver.db.WriteTxn(driver.deviceTable)
	driver.deviceTable.Insert(wtxn, &DRADevice{Name: "eth0"})
	wtxn.Commit()
	waitForPublish()

	wtxn = driver.db.WriteTxn(driver.allocationTable)
	driver.allocationTable.Insert(wtxn, &DRAAllocation{
		Pool:       "pool-a",
		DeviceName: "eth0",
	})
	wtxn.Commit()
	waitForPublish()

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for publish loop to stop")
	}
}

func TestOnDevices(t *testing.T) {
	t.Run("device is inserted into table regardless of pool match", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Equal(t, "eth0", row.Name)
	})

	t.Run("device matching no pool is still discovered, but not advertised", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames: []string{"eth1"}, // only eth1 matches
			}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: false}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found, "device must be discovered even though it matches no pool")

		pools := driver.buildPoolsFromTable()
		require.Empty(t, pools["pool-a"].Slices[0].Devices, "device must not be advertised in a pool it does not match")
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
		_, _, found0 := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found0, "eth0 must remain")
		_, _, found1 := driver.deviceTable.Get(txn, deviceByName.Query("eth1"))
		require.False(t, found1, "eth1 must be removed")
	})

	t.Run("device that stops matching remains discovered but is no longer advertised", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		dev.matches = false
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Empty(t, driver.buildPoolsFromTable()["pool-a"].Slices[0].Devices)
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
		})
		wtxn.Commit()

		// Mock manager reports empty set — should not touch dummy0.
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("dummy0"))
		require.True(t, found, "dummy manager's device must not be deleted by mock manager")
	})

	t.Run("pool with nil filter never advertises devices", func(t *testing.T) {
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
		require.Equal(t, 1, count, "device is still discovered and present in the table")

		pools := driver.buildPoolsFromTable()
		_, hasPool := pools["no-filter"]
		require.False(t, hasPool, "a pool with a nil filter is never pre-populated or matched")
	})

	t.Run("device matches multiple pools — assigned to first alphabetically", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "beta", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "alpha", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		pools := driver.buildPoolsFromTable()
		require.Len(t, pools["alpha"].Slices[0].Devices, 1, "eth0 must be in alpha (first alphabetically)")
		require.Empty(t, pools["beta"].Slices[0].Devices, "eth0 must not be in beta")
	})

	t.Run("Merge carries KernelIfName forward when a rescan cannot determine one", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})

		// First scan: device manager reports a live kernel interface name.
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0", kernelIfName: "keth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev1}, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName())

		// Second scan: the device has moved into a pod's netns, so the fresh
		// scan can no longer determine a kernel interface name.
		dev2 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev2}, func(statedb.WriteTxn) {})

		txn = driver.db.ReadTxn()
		row, _, found = driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName(),
			"Merge must carry the previous KernelIfName forward when the fresh scan has none")
	})
}

// ---------------------------------------------------------------------------
// onDevices — Merge and attribute freshness
// ---------------------------------------------------------------------------

// TestOnDevicesMerge verifies that onDevices' Modify closure calls
// Dev.Merge(old.Dev) so a device implementation can copy forward fields a
// fresh scan could not determine (e.g. KernelIfName once a device has moved
// into a pod's network namespace).
func TestOnDevicesMerge(t *testing.T) {
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}

	t.Run("Merge is not called on first discovery (no prior row)", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &mergeTrackingDevice{trackedDevice: trackedDevice{name: "eth0"}, kernelIfName: "keth0"}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		require.Zero(t, dev.mergeCalls, "Merge must not be called when there is no existing row")

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName())
	})

	t.Run("Merge is called on subsequent onDevices calls and copies forward KernelIfName", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)

		dev1 := &mergeTrackingDevice{trackedDevice: trackedDevice{name: "eth0"}, kernelIfName: "keth0"}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev1}, func(statedb.WriteTxn) {})

		// Second scan: the device manager reports the same device but this time
		// could not determine a kernel ifname (e.g. moved into a pod netns).
		dev2 := &mergeTrackingDevice{trackedDevice: trackedDevice{name: "eth0"}, kernelIfName: ""}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev2}, func(statedb.WriteTxn) {})

		require.Equal(t, 1, dev2.mergeCalls, "Merge must be called exactly once against the old Dev")

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Equal(t, "keth0", row.Dev.KernelIfName(),
			"KernelIfName must be copied forward from the old device by Merge")
	})

	t.Run("Merge restores state from an allocation on first discovery", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		restored := &mergeTrackingDevice{
			trackedDevice: trackedDevice{name: "eth0"},
			kernelIfName:  "keth0",
		}
		driver.storeAllocations(
			[]allocation{{
				Device:     restored,
				DeviceName: "eth0",
				Pool:       "pool-a",
				Manager:    types.DeviceManagerTypeMock,
			}},
			prepTestPodUID,
			prepTestClaimUID,
		)

		fresh := &mergeTrackingDevice{trackedDevice: trackedDevice{name: "eth0"}}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{fresh}, func(statedb.WriteTxn) {})

		require.Equal(t, 1, fresh.mergeCalls)
		require.Equal(t, "keth0", fresh.KernelIfName())

		txn := driver.db.ReadTxn()
		row, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Same(t, fresh, row.Dev)
		require.Len(t, allocatedRowsForClaim(t, driver, prepTestClaimUID), 1)
	})
	t.Run("does not merge allocation-specific shares into a shared parent", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		parent := &mergeTrackingDevice{
			trackedDevice: trackedDevice{name: "eth0", allowMultiple: true},
		}
		driver.storeAllocations(
			[]allocation{
				{
					Device:     &mergeTrackingDevice{trackedDevice: trackedDevice{name: "prepared-0"}},
					DeviceName: "eth0",
					Pool:       "pool-a",
					Manager:    types.DeviceManagerTypeMock,
					ShareID:    prepTestShareID0,
				},
				{
					Device:     &mergeTrackingDevice{trackedDevice: trackedDevice{name: "prepared-1"}},
					DeviceName: "eth0",
					Pool:       "pool-a",
					Manager:    types.DeviceManagerTypeMock,
					ShareID:    prepTestShareID1,
				},
			},
			prepTestPodUID,
			prepTestClaimUID,
		)

		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{parent}, func(statedb.WriteTxn) {})

		require.Zero(t, parent.mergeCalls)
		require.Len(t, allocatedRowsForClaim(t, driver, prepTestClaimUID), 2)
	})
}

// TestOnDevicesAttrsNotPersisted verifies that device attributes are never
// stored in the statedb row (DRADevice has no Attrs field): buildPoolsFromTable
// must reflect live changes to Dev.GetAttrs() immediately, on every publish,
// without any stale copy lingering in the table.
func TestOnDevicesAttrsNotPersisted(t *testing.T) {
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}
	driver := buildDriverForPool(t, pools)

	dev := &attrDevice{trackedDevice: trackedDevice{name: "eth0"}, attrValue: "v1"}
	driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

	first := driver.buildPoolsFromTable()["pool-a"].Slices[0].Devices
	require.Len(t, first, 1)
	attr, ok := first[0].Attributes["custom"]
	require.True(t, ok)
	require.Equal(t, "v1", *attr.StringValue)

	// Mutate the live device's attribute in place — no onDevices call, no
	// statedb write. buildPoolsFromTable must pick up the new value because it
	// reads Dev.GetAttrs() live rather than a cached copy.
	dev.attrValue = "v2"

	second := driver.buildPoolsFromTable()["pool-a"].Slices[0].Devices
	require.Len(t, second, 1)
	attr, ok = second[0].Attributes["custom"]
	require.True(t, ok)
	require.Equal(t, "v2", *attr.StringValue,
		"buildPoolsFromTable must reflect the live device's current attributes, not a stale statedb copy")
}

// attrDevice is a trackedDevice whose GetAttrs() reflects a mutable field, so
// tests can assert that publish-time attribute resolution is live rather than
// cached from an earlier onDevices call.
type attrDevice struct {
	trackedDevice
	attrValue string
}

func (a *attrDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	return map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
		"custom": {StringValue: &a.attrValue},
	}
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
		published := pools["pool-a"].Slices[0].Devices[0]
		require.Equal(t, "eth0", published.Name)
		require.Nil(t, published.Capacity)
		require.Nil(t, published.AllowMultipleAllocations)
	})

	t.Run("consumable capacity is published", func(t *testing.T) {
		one := apiresource.MustParse("1")
		capacity := map[resourceapi.QualifiedName]resourceapi.DeviceCapacity{
			"rxQueues": {
				Value: apiresource.MustParse("4"),
				RequestPolicy: &resourceapi.CapacityRequestPolicy{
					Default:     ptr.To(one),
					ValidValues: []apiresource.Quantity{one},
				},
			},
		}
		dev := &matchingDevice{
			trackedDevice: trackedDevice{
				name:          "eth0",
				capacity:      capacity,
				allowMultiple: true,
			},
			matches: true,
		}
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		pools := driver.buildPoolsFromTable()
		published := pools["pool-a"].Slices[0].Devices[0]

		require.Equal(t, capacity, published.Capacity)
		require.Equal(t, ptr.To(true), published.AllowMultipleAllocations)
	})

	t.Run("allocations do not appear as additional published devices", func(t *testing.T) {
		const pool = "pool-a"
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: pool, Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{
			trackedDevice: trackedDevice{name: "eth0", allowMultiple: true},
			matches:       true,
		}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		prepared := &trackedDevice{name: "prepared-0"}
		driver.storeAllocations([]allocation{{
			Device:     prepared,
			DeviceName: "eth0",
			Pool:       pool,
			Manager:    types.DeviceManagerTypeMock,
			ShareID:    prepTestShareID0,
			ConsumedCapacity: map[resourceapi.QualifiedName]apiresource.Quantity{
				prepTestCapacity: apiresource.MustParse("1"),
			},
		}}, prepTestPodUID, prepTestClaimUID)

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		stored, _, found := driver.allocationTable.Get(txn, allocationByKey.Query(
			AllocationKey(pool, "eth0", prepTestShareID0),
		))
		require.True(t, found)
		require.Same(t, prepared, stored.PreparedDevice)

		publishedPools := driver.buildPoolsFromTable()
		require.Len(t, publishedPools[pool].Slices[0].Devices, 1)
		require.Equal(t, "eth0", publishedPools[pool].Slices[0].Devices[0].Name)
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

	t.Run("allocated device keeps its original pool when live matching changes", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})
		allocs := []allocation{{
			Device:     dev,
			DeviceName: "eth0",
			Manager:    types.DeviceManagerTypeMock,
			Pool:       "pool-b",
		}}
		driver.storeAllocations(allocs, prepTestPodUID, prepTestClaimUID)

		pools := driver.buildPoolsFromTable()
		require.Empty(t, pools["pool-a"].Slices[0].Devices)
		require.Len(t, pools["pool-b"].Slices[0].Devices, 1)
		require.Equal(t, "eth0", pools["pool-b"].Slices[0].Devices[0].Name)

		driver.deleteAllocations(allocs)
		pools = driver.buildPoolsFromTable()
		require.Len(t, pools["pool-a"].Slices[0].Devices, 1,
			"after the final allocation is released the device must follow live pool matching")
		require.Empty(t, pools["pool-b"].Slices[0].Devices)
	})

	t.Run("allocation with an empty pool is not advertised", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		driver.allocationTable.Insert(wtxn, &DRAAllocation{
			DeviceName:     "eth0",
			Manager:        types.DeviceManagerTypeMock,
			PreparedDevice: dev,
			PodUID:         prepTestPodUID,
			ClaimUID:       prepTestClaimUID,
		})
		wtxn.Commit()

		pools := driver.buildPoolsFromTable()
		require.Empty(t, pools["pool-a"].Slices[0].Devices)
	})

	t.Run("unallocated device can change pools between publications", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		first := driver.buildPoolsFromTable()
		require.Len(t, first["pool-a"].Slices[0].Devices, 1)
		require.Empty(t, first["pool-b"].Slices[0].Devices)

		driver.config.Pools = []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		}
		second := driver.buildPoolsFromTable()
		require.NotContains(t, second, "pool-a")
		require.Len(t, second["pool-b"].Slices[0].Devices, 1)
	})

	t.Run("allocated pool removed from config does not fall back to another pool", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})
		driver.storeAllocations(
			[]allocation{{
				Device:     dev,
				DeviceName: "eth0",
				Manager:    types.DeviceManagerTypeMock,
				Pool:       "pool-a",
			}},
			prepTestPodUID,
			prepTestClaimUID,
		)

		driver.config.Pools = []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-c", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		}
		pools := driver.buildPoolsFromTable()
		require.NotContains(t, pools, "pool-a")
		require.Empty(t, pools["pool-c"].Slices[0].Devices)
	})

	t.Run("allocations from different pools make device unavailable", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{
			trackedDevice: trackedDevice{name: "eth0", allowMultiple: true},
			matches:       true,
		}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})
		driver.storeAllocations(
			[]allocation{
				{Device: dev, DeviceName: "eth0", Manager: types.DeviceManagerTypeMock, Pool: "pool-a", ShareID: prepTestShareID0},
				{Device: dev, DeviceName: "eth0", Manager: types.DeviceManagerTypeMock, Pool: "pool-b", ShareID: prepTestShareID1},
			},
			prepTestPodUID,
			prepTestClaimUID,
		)

		pools := driver.buildPoolsFromTable()
		require.Empty(t, pools["pool-a"].Slices[0].Devices)
		require.Empty(t, pools["pool-b"].Slices[0].Devices)
	})

	t.Run("allocated and free devices are published in their respective pools", func(t *testing.T) {
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		devAllocated := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		devFree := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{devAllocated, devFree}, func(statedb.WriteTxn) {})
		driver.storeAllocations(
			[]allocation{{
				Device:     devAllocated,
				DeviceName: "eth0",
				Manager:    types.DeviceManagerTypeMock,
				Pool:       "pool-b",
			}},
			prepTestPodUID,
			prepTestClaimUID,
		)

		pools := driver.buildPoolsFromTable()
		require.Len(t, pools["pool-a"].Slices[0].Devices, 1)
		require.Equal(t, "eth1", pools["pool-a"].Slices[0].Devices[0].Name)
		require.Len(t, pools["pool-b"].Slices[0].Devices, 1)
		require.Equal(t, "eth0", pools["pool-b"].Slices[0].Devices[0].Name)
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

func TestPodResourceClaimNames(t *testing.T) {
	t.Run("direct claim", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ResourceClaims: []corev1.PodResourceClaim{{
					Name:              "queue",
					ResourceClaimName: ptr.To("direct-claim"),
				}},
			},
		}

		names, err := podResourceClaimNames(pod)
		require.NoError(t, err)
		require.Equal(t, []string{"direct-claim"}, names)
	})

	t.Run("claim generated from template", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ResourceClaims: []corev1.PodResourceClaim{{
					Name:                      "queue",
					ResourceClaimTemplateName: ptr.To("queue-template"),
				}},
			},
			Status: corev1.PodStatus{
				ResourceClaimStatuses: []corev1.PodResourceClaimStatus{{
					Name:              "queue",
					ResourceClaimName: ptr.To("generated-claim"),
				}},
			},
		}

		names, err := podResourceClaimNames(pod)
		require.NoError(t, err)
		require.Equal(t, []string{"generated-claim"}, names)
	})

	t.Run("claim from template not created yet", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ResourceClaims: []corev1.PodResourceClaim{{
					Name:                      "queue",
					ResourceClaimTemplateName: ptr.To("queue-template"),
				}},
			},
		}

		names, err := podResourceClaimNames(pod)
		require.NoError(t, err)
		require.Empty(t, names)
	})

	t.Run("invalid claim source", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: corev1.PodSpec{
				ResourceClaims: []corev1.PodResourceClaim{{Name: "queue"}},
			},
		}

		names, err := podResourceClaimNames(pod)
		require.Error(t, err)
		require.Empty(t, names)
	})
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

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var rows []*DRAAllocation
		for row := range AllocationsByClaimUID(driver.allocationTable, txn, prepTestClaimUID) {
			rows = append(rows, row)
		}
		require.Len(t, rows, 1)
		require.Equal(t, prepTestDev0, rows[0].DeviceName)
		require.Equal(t, "eth-pod", rows[0].Config.PodIfName)
		require.Equal(t, prepTestPodUID, rows[0].PodUID)
		require.Equal(t, "test-pool", rows[0].Pool, "Pool from AllocatedDeviceStatus.Pool must be restored into the row")
	})

	t.Run("restored allocation keeps its pool when published", func(t *testing.T) {
		driver := buildDriver(t)
		driver.config.Pools = []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"other"}}},
			{PoolName: "pool-b", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{prepTestDev0}}},
		}
		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)
		claim.Status.Devices[0].Pool = "pool-a"

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		require.NoError(t, driver.restoreDevicesFromClaim(claim, wtxn))
		wtxn.Commit()
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{
			&ifNameMatchingDevice{trackedDevice: trackedDevice{name: prepTestDev0}},
		}, func(statedb.WriteTxn) {})

		pools := driver.buildPoolsFromTable()
		require.Len(t, pools["pool-a"].Slices[0].Devices, 1)
		require.Empty(t, pools["pool-b"].Slices[0].Devices)
	})

	t.Run("shared allocation restores its identity and capacity", func(t *testing.T) {
		driver := buildDriver(t)
		claim := buildClaimWithDeviceStatus(t, prepTestDriverName, prepTestPodUID, prepTestClaimUID, prepTestDev0)
		claim.Status.Devices[0].ShareID = ptr.To(string(prepTestShareID0))

		var serialized types.SerializedDevice
		require.NoError(t, json.Unmarshal(claim.Status.Devices[0].Data.Raw, &serialized))
		serialized.ConsumedCapacity = map[resourceapi.QualifiedName]apiresource.Quantity{
			prepTestCapacity: apiresource.MustParse("1"),
		}
		raw, err := json.Marshal(serialized)
		require.NoError(t, err)
		claim.Status.Devices[0].Data.Raw = raw

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		err = driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
		require.Len(t, rows, 1)
		require.Equal(t, prepTestDev0, rows[0].DeviceName)
		require.Equal(t, "test-pool", rows[0].Pool)
		require.Equal(t, prepTestShareID0, rows[0].ShareID)
		require.Equal(t, apiresource.MustParse("1"), rows[0].ConsumedCapacity[prepTestCapacity])
		require.NotNil(t, rows[0].PreparedDevice)
	})

	t.Run("wrong driver is skipped without error", func(t *testing.T) {
		driver := buildDriver(t)
		claim := buildClaimWithDeviceStatus(t, "other.driver.io", prepTestPodUID, prepTestClaimUID, prepTestDev0)

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var count int
		for range driver.allocationTable.All(txn) {
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

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.Error(t, err, "unknown device manager must return an error")

		txn := driver.db.ReadTxn()
		var count int
		for range driver.allocationTable.All(txn) {
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

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		err := driver.restoreDevicesFromClaim(claim, wtxn)
		wtxn.Commit()
		require.NoError(t, err)

		txn := driver.db.ReadTxn()
		var count int
		for range driver.allocationTable.All(txn) {
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

		wtxn := driver.db.WriteTxn(driver.allocationTable)
		require.NoError(t, driver.restoreDevicesFromClaim(claim, wtxn))
		wtxn.Commit()

		txn := driver.db.ReadTxn()
		var rows []*DRAAllocation
		for row := range AllocationsByClaimUID(driver.allocationTable, txn, prepTestClaimUID) {
			rows = append(rows, row)
		}
		require.Len(t, rows, 1)
		require.Equal(t, "dummy0", rows[0].DeviceName)
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
// Allocation table
// ---------------------------------------------------------------------------

func TestAllocationTable(t *testing.T) {
	pool := "pool-a"
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: pool, Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}

	t.Run("store records ownership and prepared device", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		advertised := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		prepared := &trackedDevice{name: "prepared0"}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{advertised}, func(statedb.WriteTxn) {})

		allocs := []allocation{{
			Device: prepared, DeviceName: "eth0", Pool: pool,
			Config:  types.DeviceConfig{PodIfName: "dmy0"},
			Manager: types.DeviceManagerTypeMock,
		}}
		driver.storeAllocations(allocs, prepTestPodUID, prepTestClaimUID)

		rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
		require.Len(t, rows, 1)
		require.Equal(t, "eth0", rows[0].DeviceName)
		require.Same(t, prepared, rows[0].PreparedDevice)
		require.Equal(t, prepTestPodUID, rows[0].PodUID)
		require.Equal(t, "dmy0", rows[0].Config.PodIfName)
	})

	t.Run("delete removes allocation but retains inventory", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		allocs := []allocation{{Device: dev, DeviceName: "eth0", Pool: pool}}
		driver.storeAllocations(allocs, prepTestPodUID, prepTestClaimUID)
		driver.deleteAllocations(allocs)

		requireNoAllocations(t, driver)
		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
	})

	t.Run("store does not depend on current inventory", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		prepared := &matchingDevice{trackedDevice: trackedDevice{name: "prepared0"}}
		driver.storeAllocations([]allocation{{
			Device:     prepared,
			DeviceName: "eth0",
			Pool:       pool,
			Manager:    types.DeviceManagerTypeMock,
		}}, prepTestPodUID, prepTestClaimUID)

		rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
		require.Len(t, rows, 1)
		require.Same(t, prepared, rows[0].PreparedDevice)
	})

	t.Run("store skips an incomplete allocation", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		require.NotPanics(t, func() {
			driver.storeAllocations([]allocation{{}}, prepTestPodUID, prepTestClaimUID)
		})
		requireNoAllocations(t, driver)
	})

	t.Run("store only records the named device", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		dev0 := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		dev1 := &matchingDevice{trackedDevice: trackedDevice{name: "eth1"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev0, dev1}, func(statedb.WriteTxn) {})

		driver.storeAllocations(
			[]allocation{{Device: dev0, DeviceName: "eth0", Pool: pool}},
			prepTestPodUID,
			prepTestClaimUID,
		)
		rows := allocatedRowsForPod(t, driver, prepTestPodUID)
		require.Len(t, rows, 1)
		require.Equal(t, "eth0", rows[0].DeviceName)
	})
}

// ---------------------------------------------------------------------------
// Inventory updates are independent from allocations
// ---------------------------------------------------------------------------

func TestOnDevicesDoesNotModifyAllocations(t *testing.T) {
	const pool = "pool-a"
	pools := []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
		{PoolName: pool, Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
	}

	t.Run("initial discovery preserves restored allocation", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		prepared := &trackedDevice{name: "prepared0"}
		wtxn := driver.db.WriteTxn(driver.allocationTable)
		driver.allocationTable.Insert(wtxn, &DRAAllocation{
			DeviceName:     "eth0",
			Pool:           pool,
			Manager:        types.DeviceManagerTypeMock,
			PreparedDevice: prepared,
			PodUID:         prepTestPodUID,
			ClaimUID:       prepTestClaimUID,
			Config:         types.DeviceConfig{PodIfName: "dmy0"},
		})
		wtxn.Commit()

		advertised := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{advertised}, func(statedb.WriteTxn) {})

		rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
		require.Len(t, rows, 1)
		require.Same(t, prepared, rows[0].PreparedDevice)
		require.Equal(t, "dmy0", rows[0].Config.PodIfName)

		txn := driver.db.ReadTxn()
		device, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.True(t, found)
		require.Same(t, advertised, device.Dev)
	})

	t.Run("inventory resync preserves allocation", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		advertised := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		prepared := &trackedDevice{name: "prepared0"}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{advertised}, func(statedb.WriteTxn) {})
		driver.storeAllocations(
			[]allocation{{Device: prepared, DeviceName: "eth0", Pool: pool}},
			prepTestPodUID,
			prepTestClaimUID,
		)

		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{advertised}, func(statedb.WriteTxn) {})

		rows := allocatedRowsForClaim(t, driver, prepTestClaimUID)
		require.Len(t, rows, 1)
		require.Same(t, prepared, rows[0].PreparedDevice)
	})

	t.Run("inventory removal retains allocation for cleanup", func(t *testing.T) {
		driver := buildDriverForPool(t, pools)
		advertised := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{advertised}, func(statedb.WriteTxn) {})
		driver.storeAllocations(
			[]allocation{{Device: advertised, DeviceName: "eth0", Pool: pool}},
			prepTestPodUID,
			prepTestClaimUID,
		)

		driver.onDevices(types.DeviceManagerTypeMock, nil, func(statedb.WriteTxn) {})

		txn := driver.db.ReadTxn()
		_, _, found := driver.deviceTable.Get(txn, deviceByName.Query("eth0"))
		require.False(t, found)
		require.Len(t, allocatedRowsForClaim(t, driver, prepTestClaimUID), 1)
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

		mgrAttr, ok := devices[0].Attributes[types.DeviceManagerLabel]
		require.True(t, ok, "deviceManager attribute must be present in published device")
		require.NotNil(t, mgrAttr.StringValue)
		require.Equal(t, types.DeviceManagerTypeMock.String(), *mgrAttr.StringValue)
	})

	t.Run("pool attribute is not persisted — repeated publishes stay consistent", func(t *testing.T) {
		// DRADevice has no Attrs field: attributes are computed fresh from
		// Dev.GetAttrs() on every publish. Calling buildPoolsFromTable twice
		// must not leak the injected pool label back into the device's own
		// attribute set (which would happen if GetAttrs() returned a shared,
		// mutable map instead of a fresh one).
		driver := buildDriverForPool(t, []v2alpha1.CiliumNetworkDriverDevicePoolConfig{
			{PoolName: "pool-a", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
		})
		dev := &matchingDevice{trackedDevice: trackedDevice{name: "eth0"}, matches: true}
		driver.onDevices(types.DeviceManagerTypeMock, []types.Device{dev}, func(statedb.WriteTxn) {})

		first := driver.buildPoolsFromTable()
		second := driver.buildPoolsFromTable()

		require.Len(t, first["pool-a"].Slices[0].Devices, 1)
		require.Len(t, second["pool-a"].Slices[0].Devices, 1)
		require.Equal(t, first["pool-a"].Slices[0].Devices, second["pool-a"].Slices[0].Devices,
			"published attributes must be identical across independent publishes")
	})
}
