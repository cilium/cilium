// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sriov

import (
	"log/slog"
	"maps"
	"path"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	resourceapi "k8s.io/api/resource/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	testDataPath = "./testdata/"
)

func compareAttrs(t *testing.T, one, two map[resourceapi.QualifiedName]resourceapi.DeviceAttribute) {
	require.NotEmpty(t, one)
	require.ElementsMatch(t, slices.Collect(maps.Keys(one)), slices.Collect(maps.Keys(two)))

	for k, v := range one {
		require.NotEmpty(t, v.String())
		other := two[k]
		require.Equal(t, v.String(), other.String())
	}
}

func TestSriov(t *testing.T) {
	listLinkFunc := func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.GenericLink{
				LinkType: "device",
				LinkAttrs: netlink.LinkAttrs{
					Name:      "mypf",
					Vfs:       []netlink.VfInfo{{ID: 1}},
					ParentDev: "0000:02:00.0",
				},
			},
			&netlink.GenericLink{
				LinkType: "device",
				LinkAttrs: netlink.LinkAttrs{
					Name:      "myvf",
					ParentDev: "0000:02:00.1",
				},
			},
		}, nil
	}

	var mgr *SRIOVManager
	var err error

	t.Run("setup on startup", func(t *testing.T) {
		cfg := &v2alpha1.SRIOVDeviceManagerConfig{
			Enabled:           true,
			SysPciDevicesPath: testDataPath,
			Ifaces: []v2alpha1.SRIOVDeviceConfig{
				{IfName: "mypf", VfCount: 1},
			},
		}

		mgr, err = NewManager(slog.Default(), cfg, withNetlinkLister(listLinkFunc))
		require.NoError(t, err)

		// restore the file for subsequent tests
		require.NoError(t, writeVfs(path.Join(mgr.pciDevicesPath(), "0000:02:00.0"), 0))
	})

	t.Run("device parsing", func(t *testing.T) {
		mgr, err := NewManager(slog.Default(), &v2alpha1.SRIOVDeviceManagerConfig{
			Enabled:           true,
			SysPciDevicesPath: testDataPath,
		}, withNetlinkLister(listLinkFunc))
		require.NoError(t, err)

		byPCI, err := mgr.linkAttrsByPCIAddr()
		require.NoError(t, err)
		require.Contains(t, byPCI, PCIAddr("0000:02:00.1"))

		device, err := mgr.parseDevice("0000:02:00.1", byPCI)
		require.NoError(t, err)
		require.NotNil(t, device)

		expectedDevice := PciDevice{
			Addr:            "0000:02:00.1",
			PfName:          "mypf",
			Driver:          "mydriver",
			VfID:            1,
			KernelIfaceName: "myvf",
			DeviceID:        "mydeviceid",
			Vendor:          "myvendor",
		}

		require.Equal(t, expectedDevice, *device)
		compareAttrs(t, device.GetAttrs(), expectedDevice.GetAttrs())
	})
}

// TestPciDevice_Match covers the Match() method across all filter fields,
// including the no-kernel-interface (DPDK/vfio) case.
//
// Note: for SR-IOV devices, IfNames matches against the kernel interface name
// (e.g. "ens1f0v0"). Devices bound to userspace drivers (vfio-pci) have an
// empty KernelIfName and cannot be selected via IfNames; use PfNames or
// PCIAddrs instead.
func TestPciDevice_Match(t *testing.T) {
	// baseline is a typical SR-IOV VF with a kernel netdev.
	baseline := PciDevice{
		Addr:            "0000:03:00.1",
		Driver:          "mlx5_core",
		Vendor:          "0x15b3",
		DeviceID:        "0x1018",
		PfName:          "ens1f0",
		VfID:            0,
		KernelIfaceName: "ens1f0v0",
	}

	// noKernel is bound to a userspace driver and has no kernel netdev.
	noKernel := PciDevice{
		Addr:            "0000:03:00.1",
		Driver:          "vfio-pci",
		Vendor:          "0x15b3",
		DeviceID:        "0x1018",
		PfName:          "ens1f0",
		VfID:            0,
		KernelIfaceName: "",
	}

	tests := []struct {
		name   string
		dev    PciDevice
		filter v2alpha1.CiliumNetworkDriverDeviceFilter
		want   bool
	}{
		// ── deviceManagers ────────────────────────────────────────────────
		{
			name:   "empty filter matches",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{},
			want:   true,
		},
		{
			name:   "matching device manager",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"sr-iov"}},
			want:   true,
		},
		{
			name:   "non-matching device manager",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"dummy"}},
			want:   false,
		},

		// ── ifNames: matches the kernel interface name, not the synthetic PCI-derived name ──
		{
			name:   "ifNames matches kernel interface name",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"ens1f0v0"}},
			want:   true,
		},
		{
			name:   "ifNames with synthetic PCI name does not match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"0000-03-00-1"}},
			want:   false,
		},
		{
			name:   "ifNames non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0"}},
			want:   false,
		},
		{
			name:   "ifNames multiple candidates, kernel name present",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0", "ens1f0v0"}},
			want:   true,
		},

		// ── ifNames on device with no kernel interface (DPDK/vfio) ────────
		{
			name:   "ifNames does not match empty KernelIfName",
			dev:    noKernel,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"ens1f0v0"}},
			want:   false,
		},
		{
			name:   "pciAddrs matches device with no kernel interface",
			dev:    noKernel,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.1"}},
			want:   true,
		},

		// ── PCI-specific fields ───────────────────────────────────────────
		{
			name:   "pciAddrs exact match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.1"}},
			want:   true,
		},
		{
			name:   "pciAddrs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.0"}},
			want:   false,
		},
		{
			name:   "vendorIDs match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x15b3"}},
			want:   true,
		},
		{
			name:   "vendorIDs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x8086"}},
			want:   false,
		},
		{
			name:   "deviceIDs match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0x1018"}},
			want:   true,
		},
		{
			name:   "deviceIDs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0xdead"}},
			want:   false,
		},
		{
			name:   "drivers match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"mlx5_core"}},
			want:   true,
		},
		{
			name:   "drivers non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"vfio-pci"}},
			want:   false,
		},

		// ── pfNames: SR-IOV Physical Function filter ──────────────────────
		{
			name:   "pfNames matches PF name",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PfNames: []string{"ens1f0"}},
			want:   true,
		},
		{
			name:   "pfNames non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PfNames: []string{"ens2f0"}},
			want:   false,
		},

		// ── combinations ──────────────────────────────────────────────────
		{
			name: "deviceManager + pciAddr + vendor all match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"sr-iov"},
				PCIAddrs:       []string{"0000:03:00.1"},
				VendorIDs:      []string{"0x15b3"},
			},
			want: true,
		},
		{
			name: "deviceManager + pfNames + driver all match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"sr-iov"},
				PfNames:        []string{"ens1f0"},
				Drivers:        []string{"mlx5_core"},
			},
			want: true,
		},
		{
			name: "ifNames (kernel) + pciAddr both match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:  []string{"ens1f0v0"},
				PCIAddrs: []string{"0000:03:00.1"},
			},
			want: true,
		},
		{
			name: "ifNames matches kernel but vendor does not",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:   []string{"ens1f0v0"},
				VendorIDs: []string{"0x8086"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.dev.Match(tt.filter))
		})
	}
}
