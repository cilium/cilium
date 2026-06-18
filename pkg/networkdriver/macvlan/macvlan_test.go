// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// parentLink returns a minimal Device link that acts as a parent interface.
// It is deliberately a *netlink.Device (not a *netlink.Macvlan) so it can also
// be used to exercise the "not a macvlan" guard in Free.
func parentLink(name string, index int) netlink.Link {
	return &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Index: index,
		},
	}
}

// fakeNetlink is an in-memory stand-in for the package-level netlink seams used
// by MacvlanDevice.Setup/Free. LinkAdd reflects created interfaces back into the
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

// ── GetAttrs ─────────────────────────────────────────────────────────────────

func TestMacvlanDevice_GetAttrs(t *testing.T) {
	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
		Mode:            netlink.MACVLAN_MODE_BRIDGE,
	}

	attrs := dev.GetAttrs()

	require.NotNil(t, attrs)
	require.Equal(t, "eth0-0", *attrs[types.IfNameLabel].StringValue)
	require.Equal(t, "eth0.0", *attrs[types.KernelIfNameLabel].StringValue)
	require.Equal(t, "eth0", *attrs[types.ParentIfNameLabel].StringValue)
	require.Equal(t, "bridge", *attrs[types.MacVlanModeLabel].StringValue)

	// Runtime-only attributes are not known at advertise time for on-demand
	// devices and must not be published (an mtu:0 would break DRA CEL selectors).
	_, hasHWAddr := attrs[types.HWAddrLabel]
	require.False(t, hasHWAddr)
	_, hasMTU := attrs[types.MTULabel]
	require.False(t, hasMTU)
	_, hasFlags := attrs[types.FlagsLabel]
	require.False(t, hasFlags)
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestMacvlanDevice_Match(t *testing.T) {
	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
	}

	tests := []struct {
		name   string
		filter v2alpha1.CiliumNetworkDriverDeviceFilter
		want   bool
	}{
		// ── deviceManagers ────────────────────────────────────────────────
		{
			name:   "empty filter matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{},
			want:   true,
		},
		{
			name:   "matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"macvlan"}},
			want:   true,
		},
		{
			name:   "non-matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"sr-iov"}},
			want:   false,
		},

		// ── ifNames: normalized dot→dash ──────────────────────────────────
		{
			name:   "ifNames exact normalized match (dash form)",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0-0"}},
			want:   true,
		},
		{
			name:   "ifNames with dot form is normalized and matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0.0"}},
			want:   true,
		},
		{
			name:   "ifNames non-matching",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth1-0"}},
			want:   false,
		},
		{
			name:   "ifNames multiple candidates, dot form matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth1.0", "eth0.0"}},
			want:   true,
		},

		// ── parentIfNames ─────────────────────────────────────────────────
		{
			name:   "parentIfNames matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{ParentIfNames: []string{"eth0"}},
			want:   true,
		},
		{
			name:   "parentIfNames non-matching",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{ParentIfNames: []string{"eth1"}},
			want:   false,
		},

		// ── unsupported PCI fields must reject ────────────────────────────
		{
			name:   "pciAddrs rejects macvlan device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.0"}},
			want:   false,
		},
		{
			name:   "vendorIDs rejects macvlan device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x8086"}},
			want:   false,
		},
		{
			name:   "deviceIDs rejects macvlan device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0x1234"}},
			want:   false,
		},
		{
			name:   "drivers rejects macvlan device",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"mlx5_core"}},
			want:   false,
		},

		// ── combinations ──────────────────────────────────────────────────
		{
			name: "deviceManager + parentIfName both match",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"macvlan"},
				ParentIfNames:  []string{"eth0"},
			},
			want: true,
		},
		{
			name: "deviceManager + dot-form ifName matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"macvlan"},
				IfNames:        []string{"eth0.0"},
			},
			want: true,
		},
		{
			name: "correct parent but wrong ifName",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				ParentIfNames: []string{"eth0"},
				IfNames:       []string{"eth0-1"},
			},
			want: false,
		},
		{
			name: "correct ifName but wrong parent",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:       []string{"eth0-0"},
				ParentIfNames: []string{"eth1"},
			},
			want: false,
		},
		{
			name: "dot ifName + parentIfName + deviceManager all match",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"macvlan"},
				IfNames:        []string{"eth0.0"},
				ParentIfNames:  []string{"eth0"},
			},
			want: true,
		},
		{
			name: "correct fields but also PCI addr set — rejects",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"macvlan"},
				ParentIfNames:  []string{"eth0"},
				PCIAddrs:       []string{"0000:03:00.0"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, dev.Match(tt.filter))
		})
	}
}

// ── Manager ───────────────────────────────────────────────────────────────────

func TestMacvlanManager_Type(t *testing.T) {
	mgr := &MacvlanManager{logger: slog.Default()}
	require.Equal(t, types.DeviceManagerTypeMacvlan, mgr.Type())
}

func TestMacvlanManager_RestoreDevice(t *testing.T) {
	mgr := &MacvlanManager{logger: slog.Default()}

	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
		Mode:            netlink.MACVLAN_MODE_BRIDGE,
	}

	data, err := dev.MarshalBinary()
	require.NoError(t, err)

	restored, err := mgr.RestoreDevice(data)
	require.NoError(t, err)
	require.NotNil(t, restored)

	restoredDev, ok := restored.(*MacvlanDevice)
	require.True(t, ok)
	require.Equal(t, dev, *restoredDev)
}

// ListDevices advertises Count discrete devices per configured parent, derived
// purely from configuration with no kernel scan.
func TestMacvlanManager_ListDevices(t *testing.T) {
	mgr := &MacvlanManager{
		logger: slog.Default(),
		config: &v2alpha1.MacvlanDeviceManagerConfig{
			Ifaces: []v2alpha1.MacvlanDeviceConfig{
				{ParentIfName: "eth0", Mode: "bridge", Count: 3},
				{ParentIfName: "eth1", Mode: "private", Count: 1},
				{ParentIfName: "eth2", Mode: "bridge", Count: 0}, // advertises nothing
			},
		},
	}

	devices, err := mgr.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 4)

	var names, kernelNames []string
	modeByName := make(map[string]netlink.MacvlanMode)
	for _, dev := range devices {
		names = append(names, dev.IfName())
		kernelNames = append(kernelNames, dev.KernelIfName())
		mv, ok := dev.(*MacvlanDevice)
		require.True(t, ok)
		modeByName[dev.IfName()] = mv.Mode
	}

	require.ElementsMatch(t, []string{"eth0-0", "eth0-1", "eth0-2", "eth1-0"}, names)
	require.ElementsMatch(t, []string{"eth0.0", "eth0.1", "eth0.2", "eth1.0"}, kernelNames)
	require.Equal(t, netlink.MACVLAN_MODE_BRIDGE, modeByName["eth0-0"])
	require.Equal(t, netlink.MACVLAN_MODE_PRIVATE, modeByName["eth1-0"])
}

func TestMacvlanManager_ListDevices_InvalidMode(t *testing.T) {
	mgr := &MacvlanManager{
		logger: slog.Default(),
		config: &v2alpha1.MacvlanDeviceManagerConfig{
			Ifaces: []v2alpha1.MacvlanDeviceConfig{
				{ParentIfName: "eth0", Mode: "bogus", Count: 1},
			},
		},
	}

	_, err := mgr.ListDevices()
	require.Error(t, err)
	require.ErrorContains(t, err, "bogus")
}

// ── Setup ──────────────────────────────────────────────────────────────────

func TestMacvlanDevice_Setup(t *testing.T) {
	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
		Mode:            netlink.MACVLAN_MODE_BRIDGE,
	}

	t.Run("creates macvlan in root namespace", func(t *testing.T) {
		f := &fakeNetlink{links: map[string]netlink.Link{"eth0": parentLink("eth0", 2)}}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))

		require.Len(t, f.added, 1)
		mv, ok := f.added[0].(*netlink.Macvlan)
		require.True(t, ok)
		require.Equal(t, "eth0.0", mv.Attrs().Name)
		require.Equal(t, 2, mv.Attrs().ParentIndex)
		require.Equal(t, netlink.MACVLAN_MODE_BRIDGE, mv.Mode)
		require.Empty(t, f.deleted)
	})

	t.Run("parent interface missing returns error", func(t *testing.T) {
		f := &fakeNetlink{}
		f.install(t)

		err := dev.Setup(types.DeviceConfig{})
		require.Error(t, err)
		require.ErrorContains(t, err, "eth0")
		require.Empty(t, f.added)
	})

	t.Run("EEXIST with matching config adopts existing device", func(t *testing.T) {
		existing := &netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", ParentIndex: 2},
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		}
		f := &fakeNetlink{
			links: map[string]netlink.Link{
				"eth0":   parentLink("eth0", 2),
				"eth0.0": existing,
			},
			addErrs: []error{unix.EEXIST},
		}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))
		// Adopted, not replaced.
		require.Empty(t, f.deleted)
		require.Empty(t, f.added)
	})

	t.Run("EEXIST with mismatched mode replaces device", func(t *testing.T) {
		existing := &netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", ParentIndex: 2},
			Mode:      netlink.MACVLAN_MODE_PRIVATE, // differs from dev.Mode (bridge)
		}
		f := &fakeNetlink{
			links: map[string]netlink.Link{
				"eth0":   parentLink("eth0", 2),
				"eth0.0": existing,
			},
			// First add fails EEXIST; the recreate after delete succeeds.
			addErrs: []error{unix.EEXIST},
		}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))
		require.Len(t, f.deleted, 1)
		require.Equal(t, "eth0.0", f.deleted[0].Attrs().Name)
		require.Len(t, f.added, 1)
		mv, ok := f.added[0].(*netlink.Macvlan)
		require.True(t, ok)
		require.Equal(t, netlink.MACVLAN_MODE_BRIDGE, mv.Mode)
	})

	t.Run("EEXIST with mismatched parent replaces device", func(t *testing.T) {
		existing := &netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", ParentIndex: 99}, // wrong parent
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		}
		f := &fakeNetlink{
			links: map[string]netlink.Link{
				"eth0":   parentLink("eth0", 2),
				"eth0.0": existing,
			},
			addErrs: []error{unix.EEXIST},
		}
		f.install(t)

		require.NoError(t, dev.Setup(types.DeviceConfig{}))
		require.Len(t, f.deleted, 1)
		require.Len(t, f.added, 1)
	})
}

// ── Free ───────────────────────────────────────────────────────────────────

func TestMacvlanDevice_Free(t *testing.T) {
	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
		Mode:            netlink.MACVLAN_MODE_BRIDGE,
	}

	t.Run("deletes existing macvlan", func(t *testing.T) {
		mv := &netlink.Macvlan{LinkAttrs: netlink.LinkAttrs{Name: "eth0.0"}}
		f := &fakeNetlink{links: map[string]netlink.Link{"eth0.0": mv}}
		f.install(t)

		require.NoError(t, dev.Free(types.DeviceConfig{}))
		require.Len(t, f.deleted, 1)
		require.Equal(t, "eth0.0", f.deleted[0].Attrs().Name)
	})

	t.Run("interface already gone is a no-op", func(t *testing.T) {
		f := &fakeNetlink{}
		f.install(t)

		require.NoError(t, dev.Free(types.DeviceConfig{}))
		require.Empty(t, f.deleted)
	})

	t.Run("refuses to delete a non-macvlan interface", func(t *testing.T) {
		f := &fakeNetlink{links: map[string]netlink.Link{"eth0.0": parentLink("eth0.0", 5)}}
		f.install(t)

		err := dev.Free(types.DeviceConfig{})
		require.ErrorIs(t, err, errNotAMacvlan)
		require.Empty(t, f.deleted)
	})
}

// ── parseMacvlanMode ─────────────────────────────────────────────────────────

func TestParseMacvlanMode(t *testing.T) {
	tests := []struct {
		in      string
		want    netlink.MacvlanMode
		wantErr bool
	}{
		{in: "", want: netlink.MACVLAN_MODE_BRIDGE},
		{in: "bridge", want: netlink.MACVLAN_MODE_BRIDGE},
		{in: "private", want: netlink.MACVLAN_MODE_PRIVATE},
		{in: "vepa", want: netlink.MACVLAN_MODE_VEPA},
		{in: "passthru", want: netlink.MACVLAN_MODE_PASSTHRU},
		{in: "source", want: netlink.MACVLAN_MODE_SOURCE},
		{in: "nonsense", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseMacvlanMode(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// ── validateConfig ───────────────────────────────────────────────────────────

func TestMacvlanManager_validateConfig(t *testing.T) {
	links := []netlink.Link{parentLink("eth0", 1), parentLink("eth1", 2)}
	lister := func() ([]netlink.Link, error) { return links, nil }

	t.Run("all parents present and modes valid", func(t *testing.T) {
		mgr := &MacvlanManager{logger: slog.Default(), netlinkLinkLister: lister}
		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 2},
			{ParentIfName: "eth1", Mode: "", Count: 1},
		}
		require.NoError(t, mgr.validateConfig(ifaces))
	})

	t.Run("empty config is a no-op", func(t *testing.T) {
		mgr := &MacvlanManager{logger: slog.Default(), netlinkLinkLister: lister}
		require.NoError(t, mgr.validateConfig(nil))
	})

	t.Run("missing parent interface errors", func(t *testing.T) {
		mgr := &MacvlanManager{logger: slog.Default(), netlinkLinkLister: lister}
		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "missing0", Mode: "bridge", Count: 1},
		}
		err := mgr.validateConfig(ifaces)
		require.Error(t, err)
		require.ErrorIs(t, err, errInterfaceNotFound)
	})

	t.Run("invalid mode errors", func(t *testing.T) {
		mgr := &MacvlanManager{logger: slog.Default(), netlinkLinkLister: lister}
		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bogus", Count: 1},
		}
		err := mgr.validateConfig(ifaces)
		require.Error(t, err)
		require.ErrorContains(t, err, "bogus")
	})
}
