// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestResolveVLANFilterEntries(t *testing.T) {
	device := func(index int) *tables.Device {
		return &tables.Device{Index: index}
	}
	vlan := func(index, parentIndex, vlanID int) *netlink.Vlan {
		return &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Index:       index,
				ParentIndex: parentIndex,
			},
			VlanId: vlanID,
		}
	}

	tests := []struct {
		name          string
		nativeDevices []*tables.Device
		links         []netlink.Link
		bypass        []int
		expected      config.VLANFilter
		expectedError string
	}{
		{
			name:          "selected VLAN device",
			nativeDevices: []*tables.Device{device(10), device(11)},
			links:         []netlink.Link{vlan(11, 10, 100)},
			expected: config.VLANFilter{Entries: []config.VLANFilterEntry{
				{IfIndex: 10, VLAN: 100},
			}},
		},
		{
			name:          "explicitly allowed VLAN device",
			nativeDevices: []*tables.Device{device(10)},
			links:         []netlink.Link{vlan(11, 10, 100)},
			bypass:        []int{100},
			expected: config.VLANFilter{Entries: []config.VLANFilterEntry{
				{IfIndex: 10, VLAN: 100},
			}},
		},
		{
			name:          "selected parent alone does not allow VLAN",
			nativeDevices: []*tables.Device{device(10)},
			links:         []netlink.Link{vlan(11, 10, 100)},
			expected:      config.VLANFilter{Entries: []config.VLANFilterEntry{}},
		},
		{
			name:          "nonexistent explicitly allowed VLAN",
			nativeDevices: []*tables.Device{device(10)},
			bypass:        []int{100},
			expected:      config.VLANFilter{Entries: []config.VLANFilterEntry{}},
		},
		{
			name:          "VLAN on unselected parent",
			nativeDevices: []*tables.Device{device(20)},
			links:         []netlink.Link{vlan(11, 10, 100)},
			bypass:        []int{100},
			expected:      config.VLANFilter{Entries: []config.VLANFilterEntry{}},
		},
		{
			name:          "selected and explicitly allowed VLAN on unselected parent",
			nativeDevices: []*tables.Device{device(11)},
			links:         []netlink.Link{vlan(11, 10, 100)},
			bypass:        []int{100},
			expected:      config.VLANFilter{Entries: []config.VLANFilterEntry{}},
		},
		{
			name: "entries sorted by interface and VLAN ID",
			nativeDevices: []*tables.Device{
				device(10), device(11), device(12),
				device(20), device(21),
			},
			links: []netlink.Link{
				vlan(21, 20, 100),
				vlan(11, 10, 200),
				vlan(12, 10, 100),
			},
			expected: config.VLANFilter{Entries: []config.VLANFilterEntry{
				{IfIndex: 10, VLAN: 100},
				{IfIndex: 10, VLAN: 200},
				{IfIndex: 20, VLAN: 100},
			}},
		},
		{
			name: "too many entries",
			nativeDevices: []*tables.Device{
				device(10), device(11), device(12), device(13),
				device(14), device(15), device(16),
			},
			links: []netlink.Link{
				vlan(11, 10, 101), vlan(12, 10, 102),
				vlan(13, 10, 103), vlan(14, 10, 104),
				vlan(15, 10, 105), vlan(16, 10, 106),
			},
			expectedError: "too many VLAN filter entries: found 6, maximum supported is 5; use --vlan-bpf-bypass=0 to allow all VLANs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := resolveVLANFilterEntries(tt.nativeDevices, tt.links, tt.bypass)
			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestResolveVLANFiltersAllowAll(t *testing.T) {
	actual, err := resolveVLANFilters(nil, []int{0})
	require.NoError(t, err)
	assert.Equal(t, config.VLANFilter{AllowAll: true}, actual)
}
