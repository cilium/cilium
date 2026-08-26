// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package device

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	sysctlfake "github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedEnableForwarding(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	prevConfigEnableIPv4 := option.Config.EnableIPv4
	prevConfigEnableIPv6 := option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4 = prevConfigEnableIPv4
		option.Config.EnableIPv6 = prevConfigEnableIPv6
	})
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		ifName := "dummy"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
		}
		err := netlink.LinkAdd(dummy)
		require.NoError(t, err)

		err = EnableForwarding(logger, sysctl, dummy)
		require.NoError(t, err)

		enabledSettings := [][]string{
			{"net", "ipv6", "conf", ifName, "forwarding"},
			{"net", "ipv4", "conf", ifName, "forwarding"},
			{"net", "ipv4", "conf", ifName, "accept_local"},
		}
		disabledSettings := [][]string{
			{"net", "ipv4", "conf", ifName, "rp_filter"},
			{"net", "ipv4", "conf", ifName, "send_redirects"},
		}
		for _, setting := range enabledSettings {
			s, err := sysctl.Read(setting)
			require.NoError(t, err)
			require.Equal(t, "1", s)
		}
		for _, setting := range disabledSettings {
			s, err := sysctl.Read(setting)
			require.NoError(t, err)
			require.Equal(t, "0", s)
		}

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestPrivilegedSetupIPIPDevices(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)

	sysctl := &sysctlfake.Sysctl{}

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		err := SetupIPIPDevices(logger, sysctl, true, true, 1500)
		require.NoError(t, err)

		dev4, err := safenetlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.Equal(t, 1480, dev4.Attrs().MTU)

		dev6, err := safenetlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.Equal(t, 1452, dev6.Attrs().MTU)

		err = SetupIPIPDevices(logger, sysctl, false, false, 1500)
		require.NoError(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		err = SetupIPIPDevices(logger, sysctl, true, true, 1480)
		require.NoError(t, err)

		dev4, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.Equal(t, 1460, dev4.Attrs().MTU)

		dev6, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.Equal(t, 1432, dev6.Attrs().MTU)

		err = SetupIPIPDevices(logger, sysctl, false, false, 1480)
		require.NoError(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
