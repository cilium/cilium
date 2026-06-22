// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dummy

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ── netlink seam fake ────────────────────────────────────────────────────────

// fakeNetlink is an in-memory stand-in for the package-level netlink seams used
// by DummyDevice.Setup/Free. LinkAdd reflects created interfaces back into the
// links map so a subsequent LinkByName observes them.
type fakeNetlink struct {
	links   map[string]netlink.Link
	addErrs []error // consumed in order, one per LinkAdd call (nil once exhausted)
	delErr  error
	added   []netlink.Link
	deleted []netlink.Link
}

func (f *fakeNetlink) linkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (f *fakeNetlink) linkAdd(link netlink.Link) error {
	var err error
	if len(f.addErrs) > 0 {
		err, f.addErrs = f.addErrs[0], f.addErrs[1:]
	}
	if err != nil {
		return err
	}
	f.added = append(f.added, link)
	if f.links == nil {
		f.links = make(map[string]netlink.Link)
	}
	f.links[link.Attrs().Name] = link
	return nil
}

func (f *fakeNetlink) linkDel(link netlink.Link) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, link)
	delete(f.links, link.Attrs().Name)
	return nil
}

// install swaps the package-level netlink seams for the fake and restores them
// when the test ends.
func (f *fakeNetlink) install(t *testing.T) {
	t.Helper()
	origByName, origAdd, origDel := netlinkLinkByName, netlinkLinkAdd, netlinkLinkDel
	netlinkLinkByName = f.linkByName
	netlinkLinkAdd = f.linkAdd
	netlinkLinkDel = f.linkDel
	t.Cleanup(func() {
		netlinkLinkByName = origByName
		netlinkLinkAdd = origAdd
		netlinkLinkDel = origDel
	})
}

func TestDummyDevice_Match(t *testing.T) {
	dev := DummyDevice{Name: "dummy0"}

	tests := []struct {
		name   string
		filter v2alpha1.CiliumNetworkDriverDeviceFilter
		want   bool
	}{
		// ── basic cases ────────────────────────────────────────────────────
		{
			name:   "empty filter matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{},
			want:   true,
		},
		{
			name:   "matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"dummy"}},
			want:   true,
		},
		{
			name:   "non-matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"sr-iov"}},
			want:   false,
		},

		// ── ifNames: exact match only (no prefix) ─────────────────────────
		{
			name:   "ifNames exact match",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"dummy0"}},
			want:   true,
		},
		{
			name:   "ifNames prefix must not match",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"dummy"}},
			want:   false,
		},
		{
			name:   "ifNames non-matching",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0"}},
			want:   false,
		},
		{
			name:   "ifNames multiple candidates, one matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0", "dummy0"}},
			want:   true,
		},

		// ── unsupported fields must reject ────────────────────────────────
		{
			name:   "parentIfNames rejects dummy device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{ParentIfNames: []string{"eth0"}},
			want:   false,
		},
		{
			name:   "pciAddrs rejects dummy device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.0"}},
			want:   false,
		},
		{
			name:   "vendorIDs rejects dummy device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x8086"}},
			want:   false,
		},
		{
			name:   "deviceIDs rejects dummy device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0x1234"}},
			want:   false,
		},
		{
			name:   "drivers rejects dummy device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"vfio-pci"}},
			want:   false,
		},

		// ── combinations ─────────────────────────────────────────────────
		{
			name: "deviceManager + exact ifName matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"dummy"},
				IfNames:        []string{"dummy0"},
			},
			want: true,
		},
		{
			name: "correct deviceManager but wrong ifName",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"dummy"},
				IfNames:        []string{"dummy1"},
			},
			want: false,
		},
		{
			name: "correct ifName but unsupported pciAddr field",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:  []string{"dummy0"},
				PCIAddrs: []string{"0000:03:00.0"},
			},
			want: false,
		},
		{
			name: "dummy manager + parentIfNames always rejects",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"dummy"},
				ParentIfNames:  []string{"eth0"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dev.Match(tt.filter)
			require.Equal(t, tt.want, got)
		})
	}
}

// ── ListDevices ──────────────────────────────────────────────────────────────

func TestDummyManager_ListDevices(t *testing.T) {
	mgr := &DummyManager{
		logger: slog.Default(),
		config: &v2alpha1.DummyDeviceManagerConfig{
			Count: 2,
		},
	}

	devices, err := mgr.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 2)

	var names, kernelNames []string
	for _, dev := range devices {
		names = append(names, dev.IfName())
		kernelNames = append(kernelNames, dev.KernelIfName())
		_, ok := dev.(*DummyDevice)
		require.True(t, ok)
	}
	require.ElementsMatch(t, []string{"dummy0", "dummy1"}, names)
	// Dummy has no separate kernel name; ifName == kernelIfName.
	require.ElementsMatch(t, []string{"dummy0", "dummy1"}, kernelNames)
}

func TestDummyManager_ListDevices_Empty(t *testing.T) {
	mgr := &DummyManager{
		logger: slog.Default(),
		config: &v2alpha1.DummyDeviceManagerConfig{},
	}
	devices, err := mgr.ListDevices()
	require.NoError(t, err)
	require.Empty(t, devices)
}

// ── Setup ────────────────────────────────────────────────────────────────────

func TestDummyDevice_Setup(t *testing.T) {
	dev := DummyDevice{Name: "dummy0"}

	t.Run("creates dummy in root namespace", func(t *testing.T) {
		f := &fakeNetlink{}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))

		require.Len(t, f.added, 1)
		d, ok := f.added[0].(*netlink.Dummy)
		require.True(t, ok)
		require.Equal(t, "dummy0", d.Attrs().Name)
		require.Empty(t, f.deleted)
	})

	t.Run("EEXIST on an existing dummy adopts it", func(t *testing.T) {
		existing := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0"}}
		f := &fakeNetlink{
			links:   map[string]netlink.Link{"dummy0": existing},
			addErrs: []error{unix.EEXIST},
		}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))
		// Adopted, not replaced.
		require.Empty(t, f.deleted)
		require.Empty(t, f.added)
	})

	t.Run("EEXIST on a non-dummy replaces it", func(t *testing.T) {
		// A device of the wrong type squatting on the name.
		existing := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "dummy0", Index: 7}}
		f := &fakeNetlink{
			links:   map[string]netlink.Link{"dummy0": existing},
			addErrs: []error{unix.EEXIST},
		}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))
		require.Len(t, f.deleted, 1)
		require.Equal(t, "dummy0", f.deleted[0].Attrs().Name)
		require.Len(t, f.added, 1)
		_, ok := f.added[0].(*netlink.Dummy)
		require.True(t, ok)
	})

	t.Run("non-EEXIST add error is returned", func(t *testing.T) {
		f := &fakeNetlink{addErrs: []error{unix.EINVAL}}
		f.install(t)

		err := dev.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorContains(t, err, "dummy0")
		require.Empty(t, f.deleted)
	})
}

// ── Free ─────────────────────────────────────────────────────────────────────

func TestDummyDevice_Free(t *testing.T) {
	dev := DummyDevice{Name: "dummy0"}

	t.Run("deletes existing dummy", func(t *testing.T) {
		d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0"}}
		f := &fakeNetlink{links: map[string]netlink.Link{"dummy0": d}}
		f.install(t)

		require.NoError(t, dev.Free(types.DeviceConfig{}))
		require.Len(t, f.deleted, 1)
		require.Equal(t, "dummy0", f.deleted[0].Attrs().Name)
	})

	t.Run("interface already gone is a no-op", func(t *testing.T) {
		f := &fakeNetlink{}
		f.install(t)

		require.NoError(t, dev.Free(types.DeviceConfig{}))
		require.Empty(t, f.deleted)
	})

	t.Run("refuses to delete a non-dummy interface", func(t *testing.T) {
		existing := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "dummy0", Index: 5}}
		f := &fakeNetlink{links: map[string]netlink.Link{"dummy0": existing}}
		f.install(t)

		err := dev.Free(types.DeviceConfig{})
		require.ErrorIs(t, err, errNotADummy)
		require.Empty(t, f.deleted)
	})
}

// ── validateConfig ───────────────────────────────────────────────────────────

func TestDummyManager_validateConfig(t *testing.T) {
	t.Run("positive count is valid", func(t *testing.T) {
		require.NoError(t, validateConfig(3))
	})

	t.Run("zero count is a no-op", func(t *testing.T) {
		require.NoError(t, validateConfig(0))
	})

	t.Run("negative count is rejected", func(t *testing.T) {
		err := validateConfig(-1)
		require.ErrorIs(t, err, errNegativeCount)
	})
}
