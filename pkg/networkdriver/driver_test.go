// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/dynamic-resource-allocation/resourceslice"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// mockDevice is a test Device that is aware of its manager type, giving correct
// Match() behaviour without importing real device manager packages.
type mockDevice struct {
	name        string
	managerType types.DeviceManagerType
}

func (d *mockDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	name := d.name
	return map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
		types.IfNameLabel: {StringValue: &name},
	}
}
func (d *mockDevice) Setup(_ types.DeviceConfig) error { return nil }
func (d *mockDevice) Free(_ types.DeviceConfig) error  { return nil }
func (d *mockDevice) IfName() string                   { return d.name }
func (d *mockDevice) KernelIfName() string             { return d.name }
func (d *mockDevice) MarshalBinary() ([]byte, error)   { return nil, nil }
func (d *mockDevice) UnmarshalBinary(_ []byte) error   { return nil }
func (d *mockDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 && !slices.Contains(filter.DeviceManagers, d.managerType.String()) {
		return false
	}
	if len(filter.IfNames) != 0 {
		for _, prefix := range filter.IfNames {
			if len(d.name) >= len(prefix) && d.name[:len(prefix)] == prefix {
				return true
			}
		}
		return false
	}
	return true
}

// mkDevice creates a mockDevice with the given name and manager type.
func mkDevice(name string, mgr types.DeviceManagerType) types.Device {
	return &mockDevice{name: name, managerType: mgr}
}

// mockDeviceManager is a test double for types.DeviceManager.
type mockDeviceManager struct {
	managerType types.DeviceManagerType
	devices     []types.Device
}

func (m *mockDeviceManager) Type() types.DeviceManagerType                { return m.managerType }
func (m *mockDeviceManager) ListDevices() ([]types.Device, error)         { return m.devices, nil }
func (m *mockDeviceManager) RestoreDevice(_ []byte) (types.Device, error) { return nil, nil }

// newTestDriver creates a Driver whose device managers return the given device
// lists, and whose pool config is set to the provided pools.
func newTestDriver(t *testing.T, managers map[types.DeviceManagerType][]types.Device, pools []v2alpha1.CiliumNetworkDriverDevicePoolConfig) *Driver {
	t.Helper()

	mgrs := make(map[types.DeviceManagerType]types.DeviceManager, len(managers))
	for mgType, devs := range managers {
		mgrs[mgType] = &mockDeviceManager{managerType: mgType, devices: devs}
	}

	return &Driver{
		logger:         hivetest.Logger(t),
		deviceManagers: mgrs,
		config: &v2alpha1.CiliumNetworkDriverNodeConfigSpec{
			Pools: pools,
		},
	}
}

func newFilter(deviceManagers ...string) *v2alpha1.CiliumNetworkDriverDeviceFilter {
	return &v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: deviceManagers}
}

// poolDeviceNames returns device names for a given pool, for easy assertion.
func poolDeviceNames(pools map[string]resourceslice.Pool, poolName string) []string {
	devices := pools[poolName].Slices[0].Devices
	names := make([]string, 0, len(devices))

	for _, d := range devices {
		names = append(names, d.Name)
	}

	return names
}

// TestGetDevicePools verifies that:
//   - devices from a single device manager are correctly placed into a pool.
//   - devices from multiple device managers are correctly placed into a pool
func TestGetDevicePools(t *testing.T) {
	t.Run("single device manager", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeDummy: {
					mkDevice("dummy0", types.DeviceManagerTypeDummy),
					mkDevice("dummy1", types.DeviceManagerTypeDummy),
				},
			},
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "pool-a", Filter: newFilter(types.DeviceManagerTypeDummy.String())},
			},
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.Len(t, pools, 1)
		require.Contains(t, pools, "pool-a")
		require.ElementsMatch(t, []string{"dummy0", "dummy1"}, poolDeviceNames(pools, "pool-a"))
	})

	// tests that devices from different managers can end up in the same pool
	// if the filters match them.
	t.Run("multiple device managers, one pool", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeDummy:   {mkDevice("dummy0", types.DeviceManagerTypeDummy), mkDevice("dummy1", types.DeviceManagerTypeDummy)},
				types.DeviceManagerTypeMacvlan: {mkDevice("macvlan0", types.DeviceManagerTypeMacvlan), mkDevice("macvlan1", types.DeviceManagerTypeMacvlan)},
				types.DeviceManagerTypeSRIOV:   {mkDevice("sriov0", types.DeviceManagerTypeSRIOV)},
			},
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "all", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.Contains(t, pools, "all")

		require.ElementsMatch(t,
			[]string{"dummy0", "dummy1", "macvlan0", "macvlan1", "sriov0"},
			poolDeviceNames(pools, "all"),
		)
	})

	t.Run("multiple device managers, multiple pools", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeDummy:   {mkDevice("dummy0", types.DeviceManagerTypeDummy)},
				types.DeviceManagerTypeMacvlan: {mkDevice("macvlan0", types.DeviceManagerTypeMacvlan)},
				types.DeviceManagerTypeSRIOV:   {mkDevice("sriov0", types.DeviceManagerTypeSRIOV), mkDevice("sriov1", types.DeviceManagerTypeSRIOV)},
			},
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{
					PoolName: "soft-pool",
					Filter:   newFilter(types.DeviceManagerTypeDummy.String(), types.DeviceManagerTypeMacvlan.String()),
				},
				{
					PoolName: "hw-pool",
					Filter:   newFilter(types.DeviceManagerTypeSRIOV.String()),
				},
			},
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.Len(t, pools, 2)

		require.ElementsMatch(t, []string{"dummy0", "macvlan0"}, poolDeviceNames(pools, "soft-pool"))
		require.ElementsMatch(t, []string{"sriov0", "sriov1"}, poolDeviceNames(pools, "hw-pool"))
	})
}

func TestGetDevicePoolsEmptyFilters(t *testing.T) {
	t.Run("nil filter doesn't appear", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeDummy: {mkDevice("dummy0", types.DeviceManagerTypeDummy)},
			},
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "bad-pool", Filter: nil},
				{PoolName: "good-pool", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.NotContains(t, pools, "bad-pool")
		require.Contains(t, pools, "good-pool")
	})

	t.Run("pool without matches ends up empty", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{},
			[]v2alpha1.CiliumNetworkDriverDevicePoolConfig{
				{PoolName: "empty-pool", Filter: &v2alpha1.CiliumNetworkDriverDeviceFilter{}},
			},
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.Contains(t, pools, "empty-pool")
		require.Empty(t, pools["empty-pool"].Slices[0].Devices)
	})

	// when no pools are configured,
	// an empty map is returned without error.
	t.Run("no pools", func(t *testing.T) {
		driver := newTestDriver(t,
			map[types.DeviceManagerType][]types.Device{
				types.DeviceManagerTypeDummy: {mkDevice("dummy0", types.DeviceManagerTypeDummy)},
			},
			nil,
		)

		pools, err := driver.getDevicePools(context.Background())
		require.NoError(t, err)
		require.Empty(t, pools)
	})
}

// TestFilterDevices tests the filterDevices helper in isolation.
func TestFilterDevices(t *testing.T) {
	devices := []types.Device{
		mkDevice("eth0", types.DeviceManagerTypeDummy),
		mkDevice("eth1", types.DeviceManagerTypeDummy),
		mkDevice("dummy0", types.DeviceManagerTypeDummy),
	}

	t.Run("match by ifName prefix", func(t *testing.T) {
		got := filterDevices(devices, v2alpha1.CiliumNetworkDriverDeviceFilter{
			IfNames: []string{"eth"},
		})

		require.Len(t, got, 2)
	})

	t.Run("match all with empty filter", func(t *testing.T) {
		got := filterDevices(devices, v2alpha1.CiliumNetworkDriverDeviceFilter{})
		require.Len(t, got, 3)
	})

	t.Run("match by device manager", func(t *testing.T) {
		got := filterDevices(devices, v2alpha1.CiliumNetworkDriverDeviceFilter{
			DeviceManagers: []string{types.DeviceManagerTypeDummy.String()},
		})

		require.Len(t, got, 3)
	})

	t.Run("no match", func(t *testing.T) {
		got := filterDevices(devices, v2alpha1.CiliumNetworkDriverDeviceFilter{
			IfNames: []string{"nonexistent"},
		})

		require.Empty(t, got)
	})
}
