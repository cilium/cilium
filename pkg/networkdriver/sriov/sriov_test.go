package sriov

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
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
			SysPciDevicesPath: "./testdata/",
		}, withNetlinkLister(listLinkFunc))

		require.NoError(t, err)

		byPCI, err := mgr.linkAttrsByPCIAddr()
		require.NoError(t, err)
		require.NotEmpty(t, byPCI)
		device, err := mgr.parseDevice("0000:02:00.1", byPCI)
		require.NoError(t, err)
		require.NotNil(t, device)
		require.Equal(t, "mypf", device.pfName)
		require.Equal(t, "myvf", device.kernelIfName)
		require.Equal(t, "mydriver", device.driver)
		require.NotZero(t, device.vfID)
	})
}
