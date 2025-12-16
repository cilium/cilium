package sriov

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	testDataPath = "./testdata/"
)

func TestSriov(t *testing.T) {
	t.Run("test device parsing", func(t *testing.T) {
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
			addr:         "0000:02:00.1",
			pfName:       "mypf",
			driver:       "mydriver",
			vfID:         1,
			kernelIfName: "myvf",
			deviceID:     "mydeviceid",
			vendor:       "myvendor",
		}
		require.Equal(t, expectedDevice, *device)
	})
}
