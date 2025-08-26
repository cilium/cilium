// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux && unparallel

package loader

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedSetupIPIPDevices(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	err := sysctl.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, 0)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := sysctl.WriteInt([]string{"net", "core", "fb_tunnels_only_for_init_net"}, 2)
		require.NoError(t, err)
	})

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		err := setupIPIPDevices(logger, sysctl, true, true, 1500)
		require.NoError(t, err)

		dev4, err := safenetlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.Equal(t, 1480, dev4.Attrs().MTU)

		dev6, err := safenetlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.Equal(t, 1452, dev6.Attrs().MTU)

		_, err = safenetlink.LinkByName("cilium_tunl")
		require.NoError(t, err)

		_, err = safenetlink.LinkByName("cilium_ip6tnl")
		require.NoError(t, err)

		_, err = safenetlink.LinkByName("tunl0")
		require.Error(t, err)

		_, err = safenetlink.LinkByName("ip6tnl0")
		require.Error(t, err)

		err = setupIPIPDevices(logger, sysctl, false, false, 1500)
		require.NoError(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		err = setupIPIPDevices(logger, sysctl, true, true, 1480)
		require.NoError(t, err)

		dev4, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.Equal(t, 1460, dev4.Attrs().MTU)

		dev6, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.Equal(t, 1432, dev6.Attrs().MTU)

		err = setupIPIPDevices(logger, sysctl, false, false, 1480)
		require.NoError(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = safenetlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
