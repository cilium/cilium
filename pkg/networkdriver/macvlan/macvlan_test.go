// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package macvlan

import (
	"log/slog"
	"testing"

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

func TestMacvlanDevice_MarshalUnmarshal(t *testing.T) {
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
	require.NotNil(t, data)

	var restored MacvlanDevice
	err = restored.UnmarshalBinary(data)
	require.NoError(t, err)

	require.Equal(t, dev.Name, restored.Name)
	require.Equal(t, dev.ParentName, restored.ParentName)
	require.Equal(t, dev.KernelIfaceName, restored.KernelIfaceName)
	require.Equal(t, dev.HWAddr, restored.HWAddr)
	require.Equal(t, dev.MTU, restored.MTU)
	require.Equal(t, dev.Flags, restored.Flags)
	require.Equal(t, dev.Mode, restored.Mode)
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
	require.Equal(t, dev.Name, restoredDev.Name)
	require.Equal(t, dev.ParentName, restoredDev.ParentName)
	require.Equal(t, dev.KernelIfaceName, restoredDev.KernelIfaceName)
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
				Flags:       1, // UP
				MTU:         1500,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        "eth0.1",
				Index:       11,
				ParentIndex: 2,
				Flags:       1, // UP
				MTU:         1500,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
		// This one should be filtered out (down)
		&netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        "eth0.2",
				Index:       12,
				ParentIndex: 2,
				Flags:       0, // DOWN
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
	require.Len(t, devices, 2) // Only 2 up macvlan devices

	// Verify device names (dots replaced with dashes)
	names := make([]string, len(devices))
	kernelNames := make([]string, len(devices))
	for i, dev := range devices {
		names[i] = dev.IfName()
		kernelNames[i] = dev.KernelIfName()
	}
	require.Contains(t, names, "eth0-0")
	require.Contains(t, names, "eth0-1")
	require.NotContains(t, names, "eth0-2") // Down interface should be filtered

	// Kernel names should preserve the dot notation
	require.Contains(t, kernelNames, "eth0.0")
	require.Contains(t, kernelNames, "eth0.1")
}
