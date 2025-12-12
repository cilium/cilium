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

	t.Run("test sriov setup on startup", func(t *testing.T) {
		cfg := &v2alpha1.SRIOVDeviceManagerConfig{
			Enabled:           true,
			SysPciDevicesPath: testDataPath,
			Ifaces: []v2alpha1.SRIOVDeviceConfig{
				{IfName: "mypf", VfCount: 1},
			},
		}

		mgr, err = NewManager(slog.Default(), cfg, withNetlinkLister(listLinkFunc))
		require.NoError(t, err)

		// now restore the file
		require.NoError(t, writeVfs(path.Join(mgr.pciDevicesPath(), "0000:02:00.0"), 0))
	})

	t.Run("test device parsing", func(t *testing.T) {

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
