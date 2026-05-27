// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// mockNetlinkOps records calls to LinkAdd and LinkDel so tests can assert the
// exact sequence of operations performed by setupMacvlans.
type mockNetlinkOps struct {
	added   []string
	deleted []string

	// Injected errors keyed by interface name. A nil value means success.
	addErrors map[string]error
	delErrors map[string]error
}

func newMockNetlinkOps() *mockNetlinkOps {
	return &mockNetlinkOps{
		addErrors: make(map[string]error),
		delErrors: make(map[string]error),
	}
}

func (m *mockNetlinkOps) LinkAdd(link netlink.Link) error {
	name := link.Attrs().Name
	m.added = append(m.added, name)
	return m.addErrors[name]
}

func (m *mockNetlinkOps) LinkDel(link netlink.Link) error {
	name := link.Attrs().Name
	m.deleted = append(m.deleted, name)
	return m.delErrors[name]
}

// installMockNetlinkOps wires the mock's LinkAdd/LinkDel into the manager.
func installMockNetlinkOps(mgr *MacvlanManager, m *mockNetlinkOps) {
	mgr.netlinkLinkAdd = m.LinkAdd
	mgr.netlinkLinkDel = m.LinkDel
}

// parentLink returns a minimal Device link that acts as a parent interface.
func parentLink(name string, index int) netlink.Link {
	return &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Index: index,
		},
	}
}

// newTestManager builds a MacvlanManager whose link-lister returns the
// provided links without touching the real kernel.
func newTestManager(links []netlink.Link, ifaces []v2alpha1.MacvlanDeviceConfig) *MacvlanManager {
	return &MacvlanManager{
		logger: slog.Default(),
		config: &v2alpha1.MacvlanDeviceManagerConfig{Ifaces: ifaces},
		netlinkLinkLister: func() ([]netlink.Link, error) {
			return links, nil
		},
		netlinkLinkAdd: func(link netlink.Link) error { return nil },
		netlinkLinkDel: func(link netlink.Link) error { return nil },
	}
}

// ── GetAttrs ─────────────────────────────────────────────────────────────────

func TestMacvlanDevice_GetAttrs(t *testing.T) {
	dev := MacvlanDevice{
		Name:            "eth0-0",
		ParentName:      "eth0",
		KernelIfaceName: "eth0.0",
		HWAddr:          "00:11:22:33:44:55",
		MTU:             1500,
		Flags:           "up|broadcast|running",
		Mode:            netlink.MACVLAN_MODE_BRIDGE,
	}

	attrs := dev.GetAttrs()

	require.NotNil(t, attrs)
	require.Equal(t, "eth0-0", *attrs[types.IfNameLabel].StringValue)
	require.Equal(t, "eth0.0", *attrs[types.KernelIfNameLabel].StringValue)
	require.Equal(t, "00:11:22:33:44:55", *attrs[types.HWAddrLabel].StringValue)
	require.Equal(t, int64(1500), *attrs[types.MTULabel].IntValue)
	require.Equal(t, "eth0", *attrs["parentIfName"].StringValue)
	require.Equal(t, "bridge", *attrs["macvlanMode"].StringValue)
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
		HWAddr:          "00:11:22:33:44:55",
		MTU:             1500,
		Flags:           "up|broadcast|running",
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

func TestMacvlanManager_ListDevices(t *testing.T) {
	parentLk := &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 2, Flags: 1, MTU: 1500},
	}

	mockLinks := []netlink.Link{
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", Index: 10, ParentIndex: 2, Flags: 1, MTU: 1500},
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		},
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.1", Index: 11, ParentIndex: 2, Flags: 1, MTU: 1500},
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		},
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.2", Index: 12, ParentIndex: 2, Flags: 0, MTU: 1500},
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		},
		parentLk,
	}

	origLinkByIndex := netlinkLinkByIndex
	t.Cleanup(func() { netlinkLinkByIndex = origLinkByIndex })

	netlinkLinkByIndex = func(index int) (netlink.Link, error) {
		if index == 2 {
			return parentLk, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}

	mgr := &MacvlanManager{
		logger:            slog.Default(),
		config:            &v2alpha1.MacvlanDeviceManagerConfig{},
		netlinkLinkLister: func() ([]netlink.Link, error) { return mockLinks, nil },
	}

	devices, err := mgr.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 3)

	var names, kernelNames []string
	for _, dev := range devices {
		names = append(names, dev.IfName())
		kernelNames = append(kernelNames, dev.KernelIfName())
	}

	t.Run("IfName uses dash notation", func(t *testing.T) {
		require.ElementsMatch(t, []string{"eth0-0", "eth0-1", "eth0-2"}, names)
	})
	t.Run("KernelIfName preserves dot notation", func(t *testing.T) {
		require.ElementsMatch(t, []string{"eth0.0", "eth0.1", "eth0.2"}, kernelNames)
	})
}

// ── setupMacvlans ─────────────────────────────────────────────────────────────

func TestSetupMacvlans(t *testing.T) {
	t.Run("success creates interfaces and nothing is deleted", func(t *testing.T) {
		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 3},
		}
		mock := newMockNetlinkOps()
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
		installMockNetlinkOps(mgr, mock)

		require.NoError(t, mgr.setupMacvlans(ifaces))
		require.Equal(t, []string{"eth0.0", "eth0.1", "eth0.2"}, mock.added)
		require.Empty(t, mock.deleted)
	})

	t.Run("empty ifaces is a no-op", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mgr := newTestManager(nil, nil)
		installMockNetlinkOps(mgr, mock)

		require.NoError(t, mgr.setupMacvlans(nil))
		require.Empty(t, mock.added)
		require.Empty(t, mock.deleted)
	})

	t.Run("LinkAdd error triggers cleanup of previously created interfaces", func(t *testing.T) {
		// eth0.1 will fail; eth0.0 was already created and eth0.2 succeeds after the continue.
		mock := newMockNetlinkOps()
		mock.addErrors["eth0.1"] = errors.New("kernel error")

		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 3},
		}
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
		installMockNetlinkOps(mgr, mock)

		err := mgr.setupMacvlans(ifaces)
		require.Error(t, err)
		require.ErrorContains(t, err, "eth0.1")

		// All three were attempted; eth0.1 failed (not tracked), so only eth0.0 and eth0.2 are cleaned up.
		require.Equal(t, []string{"eth0.0", "eth0.1", "eth0.2"}, mock.added)
		require.Equal(t, []string{"eth0.0", "eth0.2"}, mock.deleted)
	})

	t.Run("cleanup spans multiple parents on error in second parent", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.addErrors["eth1.0"] = errors.New("kernel error")

		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 2},
			{ParentIfName: "eth1", Mode: "bridge", Count: 1},
		}
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1), parentLink("eth1", 2)}, ifaces)
		installMockNetlinkOps(mgr, mock)

		err := mgr.setupMacvlans(ifaces)
		require.Error(t, err)

		require.Equal(t, []string{"eth0.0", "eth0.1", "eth1.0"}, mock.added)
		// eth0.0 and eth0.1 created before the error must be cleaned up.
		require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.deleted)
	})

	t.Run("missing parent interface errors and cleans up earlier interfaces", func(t *testing.T) {
		mock := newMockNetlinkOps()

		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 2},
			{ParentIfName: "eth1", Mode: "bridge", Count: 1}, // eth1 not in link list
		}
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
		installMockNetlinkOps(mgr, mock)

		err := mgr.setupMacvlans(ifaces)
		require.Error(t, err)
		require.ErrorIs(t, err, errInterfaceNotFound)

		require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.added)
		require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.deleted)
	})

	t.Run("existing interfaces are skipped and not recreated", func(t *testing.T) {
		mock := newMockNetlinkOps()

		existingMacvlan := &netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", Index: 10, ParentIndex: 1, Flags: 1},
			Mode:      netlink.MACVLAN_MODE_BRIDGE,
		}

		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 2},
		}
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1), existingMacvlan}, ifaces)
		installMockNetlinkOps(mgr, mock)

		require.NoError(t, mgr.setupMacvlans(ifaces))
		// eth0.0 was skipped; only eth0.1 should have been created.
		require.Equal(t, []string{"eth0.1"}, mock.added)
		require.Empty(t, mock.deleted)
	})

	t.Run("cleanup LinkDel error does not shadow original add error", func(t *testing.T) {
		mock := newMockNetlinkOps()
		mock.addErrors["eth0.1"] = errors.New("kernel add error")
		mock.delErrors["eth0.0"] = errors.New("kernel del error")

		ifaces := []v2alpha1.MacvlanDeviceConfig{
			{ParentIfName: "eth0", Mode: "bridge", Count: 2},
		}
		mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
		installMockNetlinkOps(mgr, mock)

		err := mgr.setupMacvlans(ifaces)
		require.Error(t, err)
		require.ErrorContains(t, err, "eth0.1")
		require.ErrorContains(t, err, "kernel add error")
		require.NotErrorIs(t, err, errors.New("kernel del error"), "cleanup errors must not propagate")

		// Cleanup was still attempted for the successfully created eth0.0.
		require.Equal(t, []string{"eth0.0"}, mock.deleted)
	})
}
