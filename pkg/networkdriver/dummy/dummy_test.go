// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dummy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

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
