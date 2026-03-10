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
