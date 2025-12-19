package sriov

import (
	"log/slog"
	"path"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	resourceapi "k8s.io/api/resource/v1"
)

const (
	testDataPath = "./testdata/"
)

func compareAttrs(t *testing.T, one, two map[resourceapi.QualifiedName]resourceapi.DeviceAttribute) {
	require.NotEmpty(t, one)
	require.NotEmpty(t, two)

	for k, v := range one {
		other, ok := two[k]
		require.True(t, ok)
		require.NotEmpty(t, v.String())
		require.Equal(t, v.String(), other.String())
	}

	for k, v := range two {
		other, ok := one[k]
		require.True(t, ok)
		require.NotEmpty(t, v.String())
		require.Equal(t, v.String(), other.String())
	}
}

// TODO:
// - test sr-iov setup
// - test listdevices
// - filter matching logic
func TestSriov(t *testing.T) {
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

		mgr, err = NewManager(slog.Default(), cfg)
		require.NoError(t, err)

		// now restore the file
		require.NoError(t, writeVfs(path.Join(mgr.pciDevicesPath(), "0000:02:00.0"), 0))
	})

	t.Run("test device parsing", func(t *testing.T) {
		mgr, err = NewManager(slog.Default(), &v2alpha1.SRIOVDeviceManagerConfig{
			Enabled:           true,
			SysPciDevicesPath: testDataPath,
		})

		require.NoError(t, err)

		netlinkAttrs := map[string]netlink.LinkAttrs{
			"0000:02:00.1": netlink.LinkAttrs{Name: "myvf"},
			"0000:02:00.0": netlink.LinkAttrs{Name: "mypf", Vfs: []netlink.VfInfo{{ID: 1}}},
		}

		expectedDevice := PciDevice{
			addr:         "0000:02:00.1",
			pfName:       "mypf",
			driver:       "mydriver",
			vfID:         1,
			kernelIfName: "myvf",
			deviceID:     "mydeviceid",
			vendor:       "myvendor",
		}

		device, err := mgr.parseDevice("0000:02:00.1", netlinkAttrs)
		require.NoError(t, err)
		require.NotNil(t, device)
		require.Equal(t, expectedDevice.pfName, device.pfName)
		require.Equal(t, expectedDevice.kernelIfName, device.kernelIfName)
		require.Equal(t, expectedDevice.driver, device.driver)
		require.Equal(t, expectedDevice.vfID, device.vfID)
		compareAttrs(t, device.GetAttrs(), expectedDevice.GetAttrs())
	})
}
