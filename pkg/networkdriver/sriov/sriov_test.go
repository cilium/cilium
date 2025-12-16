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
		mgr, err := NewManager(slog.Default(), &v2alpha1.SRIOVDeviceManagerConfig{
			Enabled:           true,
			SysPciDevicesPath: "./testdata/",
		})

		require.NoError(t, err)

		netlinkAttrs := map[string]netlink.LinkAttrs{
			"0000:02:00.1": netlink.LinkAttrs{Name: "myvf"},
			"0000:02:00.0": netlink.LinkAttrs{Name: "mypf", Vfs: []netlink.VfInfo{{ID: 1}}},
		}

		device, err := mgr.parseDevice("0000:02:00.1", netlinkAttrs)
		require.NoError(t, err)
		require.NotNil(t, device)
		require.Equal(t, "mypf", device.pfName)
		require.Equal(t, "myvf", device.kernelIfName)
		require.Equal(t, "mydriver", device.driver)
		require.NotZero(t, device.vfID)
	})
}
