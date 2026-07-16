// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dummy

// Comprehensive tests for DummyDevice and DummyManager.
//
// All netlink primitives are exercised through the package-level function vars
// (netlinkLinkAdd, netlinkLinkByName, netlinkLinkDel) so no kernel privileges
// are required.

import (
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ---------------------------------------------------------------------------
// Seam helpers
// ---------------------------------------------------------------------------

// patchNetlink temporarily replaces the package-level netlink function vars
// with the supplied fakes and restores the originals when the test ends.
func patchNetlink(
	t *testing.T,
	addFn func(netlink.Link) error,
	getByNameFn func(string) (netlink.Link, error),
	delFn func(netlink.Link) error,
) {
	t.Helper()
	origAdd := netlinkLinkAdd
	origGet := netlinkLinkByName
	origDel := netlinkLinkDel
	t.Cleanup(func() {
		netlinkLinkAdd = origAdd
		netlinkLinkByName = origGet
		netlinkLinkDel = origDel
	})
	netlinkLinkAdd = addFn
	netlinkLinkByName = getByNameFn
	netlinkLinkDel = delFn
}

// dummyLink returns a minimal *netlink.Dummy with the given name.
func dummyLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// vethLink returns a non-dummy link (used to simulate a type mismatch).
func vethLink(name string) netlink.Link {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// ---------------------------------------------------------------------------
// validateConfig
// ---------------------------------------------------------------------------

func TestValidateConfig(t *testing.T) {
	t.Run("zero count is valid", func(t *testing.T) {
		require.NoError(t, validateConfig(0))
	})

	t.Run("positive count is valid", func(t *testing.T) {
		require.NoError(t, validateConfig(5))
	})

	t.Run("negative count returns errNegativeCount", func(t *testing.T) {
		err := validateConfig(-1)
		require.Error(t, err)
		require.ErrorIs(t, err, errNegativeCount)
	})
}

func TestNewManager(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("valid count returns manager with correct type", func(t *testing.T) {
		mgr, err := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 3})
		require.NoError(t, err)
		require.NotNil(t, mgr)
		require.Equal(t, types.DeviceManagerTypeDummy, mgr.Type())
	})

	t.Run("zero count succeeds", func(t *testing.T) {
		_, err := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 0})
		require.NoError(t, err)
	})

	t.Run("negative count returns error", func(t *testing.T) {
		_, err := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: -1})
		require.Error(t, err)
		require.ErrorIs(t, err, errNegativeCount)
	})
}

func TestListDevices(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("count N returns N named devices", func(t *testing.T) {
		mgr, _ := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 3})
		devs, err := mgr.ListDevices()
		require.NoError(t, err)
		require.Len(t, devs, 3)
		require.Equal(t, "dummy0", devs[0].IfName())
		require.Equal(t, "dummy1", devs[1].IfName())
		require.Equal(t, "dummy2", devs[2].IfName())
	})

	t.Run("zero count returns empty slice", func(t *testing.T) {
		mgr, _ := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 0})
		devs, err := mgr.ListDevices()
		require.NoError(t, err)
		require.Empty(t, devs)
	})
}
func TestRestoreDevice(t *testing.T) {
	tlog := hivetest.Logger(t)

	t.Run("round-trip preserves device name", func(t *testing.T) {
		mgr, _ := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 1})
		original := &DummyDevice{Name: "dummy0", HWAddr: "aa:bb:cc:dd:ee:ff", MTU: 9000}

		data, err := original.MarshalBinary()
		require.NoError(t, err)

		restored, err := mgr.RestoreDevice(data)
		require.NoError(t, err)
		require.Equal(t, original.IfName(), restored.IfName())
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		mgr, _ := NewManager(tlog, &v2alpha1.DummyDeviceManagerConfig{Count: 1})
		_, err := mgr.RestoreDevice([]byte("not-json"))
		require.Error(t, err)
	})
}

func TestDummyDevice(t *testing.T) {
	t.Run("IfName and KernelIfName return device name", func(t *testing.T) {
		d := DummyDevice{Name: "dummy0"}
		require.Equal(t, "dummy0", d.IfName())
		require.Equal(t, "dummy0", d.KernelIfName())
	})

	t.Run("GetAttrs contains ifname and kernel ifname labels", func(t *testing.T) {
		d := DummyDevice{Name: "dummy0"}
		attrs := d.GetAttrs()
		ifNameKey := resourceapi.QualifiedName(types.IfNameLabel)
		kernelIfNameKey := resourceapi.QualifiedName(types.KernelIfNameLabel)
		require.Contains(t, attrs, ifNameKey)
		require.Contains(t, attrs, kernelIfNameKey)
		require.Equal(t, "dummy0", *attrs[ifNameKey].StringValue)
		require.Equal(t, "dummy0", *attrs[kernelIfNameKey].StringValue)
	})

	t.Run("MarshalBinary / UnmarshalBinary round-trip", func(t *testing.T) {
		d := DummyDevice{Name: "dummy1", HWAddr: "11:22:33:44:55:66", MTU: 1500}
		data, err := d.MarshalBinary()
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var restored DummyDevice
		require.NoError(t, restored.UnmarshalBinary(data))
		require.Equal(t, d.Name, restored.Name)
		require.Equal(t, d.HWAddr, restored.HWAddr)
		require.Equal(t, d.MTU, restored.MTU)
	})
}

func TestMatch(t *testing.T) {
	d := DummyDevice{Name: "dummy0"}

	require.True(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{}), "empty filter must match")

	require.True(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		DeviceManagers: []string{types.DeviceManagerTypeDummy.String()},
	}), "dummy manager filter must match")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		DeviceManagers: []string{"sriov"},
	}), "non-dummy manager filter must not match")

	require.True(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		IfNames: []string{"dummy0", "dummy1"},
	}), "ifname filter containing device name must match")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		IfNames: []string{"eth0"},
	}), "ifname filter not containing device name must not match")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		ParentIfNames: []string{"bond0"},
	}), "parent ifname filter must not match (dummy has no parent)")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		PCIAddrs: []string{"0000:01:00.0"},
	}), "pci addr filter must not match")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		VendorIDs: []string{"8086"},
	}), "vendor id filter must not match")

	require.False(t, d.Match(v2alpha1.CiliumNetworkDriverDeviceFilter{
		Drivers: []string{"i40e"},
	}), "driver filter must not match")
}

func TestSetup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patchNetlink(t, func(_ netlink.Link) error { return nil }, nil, nil)
		d := DummyDevice{Name: "dummy0"}
		require.NoError(t, d.Setup(types.DeviceConfig{}))
	})

	t.Run("generic error is propagated", func(t *testing.T) {
		boom := errors.New("permission denied")
		patchNetlink(t, func(_ netlink.Link) error { return boom }, nil, nil)
		d := DummyDevice{Name: "dummy0"}
		err := d.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, boom)
	})

	t.Run("EEXIST with existing dummy link adopts it", func(t *testing.T) {
		patchNetlink(t,
			func(_ netlink.Link) error { return unix.EEXIST },
			func(name string) (netlink.Link, error) { return dummyLink(name), nil },
			nil,
		)
		d := DummyDevice{Name: "dummy0"}
		require.NoError(t, d.Setup(types.DeviceConfig{}))
	})

	t.Run("EEXIST with non-dummy link deletes and recreates", func(t *testing.T) {
		deleted := false
		addCount := 0
		patchNetlink(t,
			func(_ netlink.Link) error {
				addCount++
				if addCount == 1 {
					return unix.EEXIST
				}
				return nil
			},
			func(name string) (netlink.Link, error) { return vethLink(name), nil },
			func(_ netlink.Link) error { deleted = true; return nil },
		)
		d := DummyDevice{Name: "dummy0"}
		require.NoError(t, d.Setup(types.DeviceConfig{}))
		require.True(t, deleted, "stale non-dummy link must be deleted")
		require.Equal(t, 2, addCount, "LinkAdd must be called twice (initial + recreate)")
	})

	t.Run("EEXIST with lookup failure returns error", func(t *testing.T) {
		lookupErr := errors.New("link lookup failed")
		patchNetlink(t,
			func(_ netlink.Link) error { return unix.EEXIST },
			func(_ string) (netlink.Link, error) { return nil, lookupErr },
			nil,
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, lookupErr)
	})

	t.Run("EEXIST with delete failure returns error", func(t *testing.T) {
		delErr := errors.New("delete failed")
		patchNetlink(t,
			func(_ netlink.Link) error { return unix.EEXIST },
			func(name string) (netlink.Link, error) { return vethLink(name), nil },
			func(_ netlink.Link) error { return delErr },
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, delErr)
	})

	t.Run("EEXIST with recreate failure returns error", func(t *testing.T) {
		addCount := 0
		recreateErr := errors.New("recreate failed")
		patchNetlink(t,
			func(_ netlink.Link) error {
				addCount++
				if addCount == 1 {
					return unix.EEXIST
				}
				return recreateErr
			},
			func(name string) (netlink.Link, error) { return vethLink(name), nil },
			func(_ netlink.Link) error { return nil },
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, recreateErr)
	})
}

func TestFree(t *testing.T) {
	t.Run("link not found is not an error", func(t *testing.T) {
		patchNetlink(t,
			nil,
			func(_ string) (netlink.Link, error) { return nil, netlink.LinkNotFoundError{} },
			nil,
		)
		d := DummyDevice{Name: "dummy0"}
		require.NoError(t, d.Free(types.DeviceConfig{}))
	})

	t.Run("found dummy link is deleted", func(t *testing.T) {
		deleted := false
		patchNetlink(t,
			nil,
			func(name string) (netlink.Link, error) { return dummyLink(name), nil },
			func(_ netlink.Link) error { deleted = true; return nil },
		)
		d := DummyDevice{Name: "dummy0"}
		require.NoError(t, d.Free(types.DeviceConfig{}))
		require.True(t, deleted)
	})

	t.Run("non-dummy link returns errNotADummy", func(t *testing.T) {
		patchNetlink(t,
			nil,
			func(name string) (netlink.Link, error) { return vethLink(name), nil },
			nil,
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Free(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, errNotADummy)
	})

	t.Run("lookup error is propagated", func(t *testing.T) {
		boom := errors.New("lookup blew up")
		patchNetlink(t,
			nil,
			func(_ string) (netlink.Link, error) { return nil, boom },
			nil,
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Free(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, boom)
	})

	t.Run("delete error is propagated", func(t *testing.T) {
		delErr := errors.New("delete failed")
		patchNetlink(t,
			nil,
			func(name string) (netlink.Link, error) { return dummyLink(name), nil },
			func(_ netlink.Link) error { return delErr },
		)
		d := DummyDevice{Name: "dummy0"}
		err := d.Free(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorIs(t, err, delErr)
	})
}
