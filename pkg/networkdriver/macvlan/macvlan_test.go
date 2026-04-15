// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

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
		{
			name:   "empty filter matches",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{},
			want:   true,
		},
		{
			name: "matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"macvlan"},
			},
			want: true,
		},
		{
			name: "non-matching device manager",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"sr-iov"},
			},
			want: false,
		},
		{
			name: "matching ifname",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames: []string{"eth0-0"},
			},
			want: true,
		},
		{
			name: "non-matching ifname",
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames: []string{"eth1-0"},
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

func TestMacvlanManager_Type(t *testing.T) {
	mgr := &MacvlanManager{
		logger: slog.Default(),
	}

	require.Equal(t, types.DeviceManagerTypeMacvlan, mgr.Type())
}

func TestMacvlanManager_RestoreDevice(t *testing.T) {
	mgr := &MacvlanManager{
		logger: slog.Default(),
	}

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
	// Parent interface
	parentLink := &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "eth0",
			Index: 2,
			Flags: 1,
			MTU:   1500,
		},
	}

	// Create mock netlink lister
	mockLinks := []netlink.Link{
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        "eth0.0",
				Index:       10,
				ParentIndex: 2,
				Flags:       1,
				MTU:         1500,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        "eth0.1",
				Index:       11,
				ParentIndex: 2,
				Flags:       1,
				MTU:         1500,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        "eth0.2",
				Index:       12,
				ParentIndex: 2,
				Flags:       0,
				MTU:         1500,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
		parentLink,
	}

	// Create a mock LinkByIndex function
	origLinkByIndex := netlinkLinkByIndex
	defer func() { netlinkLinkByIndex = origLinkByIndex }()

	netlinkLinkByIndex = func(index int) (netlink.Link, error) {
		if index == 2 {
			return parentLink, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}

	mockLister := func() ([]netlink.Link, error) {
		return mockLinks, nil
	}

	mgr := &MacvlanManager{
		logger:            slog.Default(),
		config:            &v2alpha1.MacvlanDeviceManagerConfig{},
		netlinkLinkLister: mockLister,
	}

	devices, err := mgr.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 3)

	// Verify device names (dots replaced with dashes)
	names := make([]string, len(devices))
	kernelNames := make([]string, len(devices))
	for i, dev := range devices {
		names[i] = dev.IfName()
		kernelNames[i] = dev.KernelIfName()
	}
	require.Contains(t, names, "eth0-0")
	require.Contains(t, names, "eth0-1")
	require.Contains(t, names, "eth0-2")

	// Kernel names should preserve the dot notation
	require.Contains(t, kernelNames, "eth0.0")
	require.Contains(t, kernelNames, "eth0.1")
	require.Contains(t, kernelNames, "eth0.2")
}

// mockNetlinkOps records calls to LinkAdd and LinkDel so tests can
// assert the exact sequence of operations performed by setupMacvlans.
type mockNetlinkOps struct {
	added   []string
	deleted []string

	// Injected errors – keyed by interface name.  A nil value means success.
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

// TestSetupMacvlans_Success verifies that when everything succeeds, the right
// interfaces are created and nothing is deleted.
func TestSetupMacvlans_Success(t *testing.T) {
	ifaces := []v2alpha1.MacvlanDeviceConfig{
		{ParentIfName: "eth0", Mode: "bridge", Count: 3},
	}

	mock := newMockNetlinkOps()
	mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(ifaces)
	require.NoError(t, err)

	require.Equal(t, []string{"eth0.0", "eth0.1", "eth0.2"}, mock.added)
	require.Empty(t, mock.deleted, "no cleanup expected on success")
}

// TestSetupMacvlans_NoInterfaces verifies that an empty ifaces slice is a
// no-op and no kernel calls are made.
func TestSetupMacvlans_NoInterfaces(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newTestManager(nil, nil)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(nil)
	require.NoError(t, err)

	require.Empty(t, mock.added)
	require.Empty(t, mock.deleted)
}

// TestSetupMacvlans_CleanupOnLinkAddError verifies that interfaces already
// created before a LinkAdd failure are deleted during cleanup, and that
// interfaces created after the failure (the loop continues) are also cleaned up.
func TestSetupMacvlans_CleanupOnLinkAddError(t *testing.T) {
	// eth0.1 will fail to be created; eth0.0 was already added successfully,
	// and eth0.2 will succeed after the continue.
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

	// All three attempted: eth0.0 succeeded, eth0.1 failed, eth0.2 succeeded.
	require.Equal(t, []string{"eth0.0", "eth0.1", "eth0.2"}, mock.added)

	// eth0.1 was never tracked (LinkAdd failed), so only eth0.0 and eth0.2
	// appear in the cleanup list.
	require.Equal(t, []string{"eth0.0", "eth0.2"}, mock.deleted)
}

// TestSetupMacvlans_CleanupAcrossMultipleParents verifies that interfaces
// created under a first parent are cleaned up when a later parent fails.
func TestSetupMacvlans_CleanupAcrossMultipleParents(t *testing.T) {
	// eth1.0 will fail to be added.
	mock := newMockNetlinkOps()
	mock.addErrors["eth1.0"] = errors.New("kernel error")

	ifaces := []v2alpha1.MacvlanDeviceConfig{
		{ParentIfName: "eth0", Mode: "bridge", Count: 2},
		{ParentIfName: "eth1", Mode: "bridge", Count: 1},
	}

	links := []netlink.Link{
		parentLink("eth0", 1),
		parentLink("eth1", 2),
	}

	mgr := newTestManager(links, ifaces)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(ifaces)
	require.Error(t, err)

	// eth0.0 and eth0.1 were created before the error on eth1.0.
	require.Equal(t, []string{"eth0.0", "eth0.1", "eth1.0"}, mock.added)

	// Cleanup must include the two successfully created eth0 interfaces.
	require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.deleted)
}

// TestSetupMacvlans_CleanupOnMissingParent verifies that a missing parent
// interface is an error and that previously created interfaces are cleaned up.
func TestSetupMacvlans_CleanupOnMissingParent(t *testing.T) {
	mock := newMockNetlinkOps()

	ifaces := []v2alpha1.MacvlanDeviceConfig{
		{ParentIfName: "eth0", Mode: "bridge", Count: 2},
		// eth1 does not exist in the link list.
		{ParentIfName: "eth1", Mode: "bridge", Count: 1},
	}

	// Only eth0 is present.
	links := []netlink.Link{parentLink("eth0", 1)}

	mgr := newTestManager(links, ifaces)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(ifaces)
	require.Error(t, err)
	require.ErrorIs(t, err, errInterfaceNotFound)

	// eth0 sub-interfaces were created before the missing-parent error.
	require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.added)
	require.Equal(t, []string{"eth0.0", "eth0.1"}, mock.deleted)
}

// TestSetupMacvlans_SkipsExistingInterfaces verifies that sub-interfaces
// already present in the link map are skipped and not re-created.
func TestSetupMacvlans_SkipsExistingInterfaces(t *testing.T) {
	mock := newMockNetlinkOps()

	// eth0.0 already exists in the kernel.
	existingMacvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Name: "eth0.0", Index: 10, ParentIndex: 1, Flags: 1},
		Mode:      netlink.MACVLAN_MODE_BRIDGE,
	}

	ifaces := []v2alpha1.MacvlanDeviceConfig{
		{ParentIfName: "eth0", Mode: "bridge", Count: 2},
	}

	links := []netlink.Link{parentLink("eth0", 1), existingMacvlan}

	mgr := newTestManager(links, ifaces)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(ifaces)
	require.NoError(t, err)

	// Only eth0.1 should have been created (eth0.0 was skipped).
	require.Equal(t, []string{"eth0.1"}, mock.added)
	require.Empty(t, mock.deleted)
}

// TestSetupMacvlans_CleanupDelErrorsAreLogged verifies that a failure inside
// the cleanup (LinkDel) does not mask the original error returned to the caller.
func TestSetupMacvlans_CleanupDelErrorsAreLogged(t *testing.T) {
	mock := newMockNetlinkOps()

	linkAddErr := errors.New("kernel add error")
	linkDelErr := errors.New("kernel del error")

	mock.addErrors["eth0.1"] = linkAddErr
	mock.delErrors["eth0.0"] = linkDelErr

	ifaces := []v2alpha1.MacvlanDeviceConfig{
		{ParentIfName: "eth0", Mode: "bridge", Count: 2},
	}

	mgr := newTestManager([]netlink.Link{parentLink("eth0", 1)}, ifaces)
	installMockNetlinkOps(mgr, mock)

	err := mgr.setupMacvlans(ifaces)

	// The original add error must be returned; the del error during cleanup
	// is only logged and must not surface to the caller.
	require.Error(t, err)
	assert.ErrorContains(t, err, "eth0.1")
	assert.ErrorContains(t, err, "kernel add error")
	assert.NotErrorIs(t, err, linkDelErr, "cleanup errors must not propagate")

	// Cleanup was still attempted.
	require.Equal(t, []string{"eth0.0"}, mock.deleted)
}
