// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package initializer

import (
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedCheckNodePortAndEphemeralPortRanges(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	prevEphemeralPortRange, err := sysctl.Read([]string{"net", "ipv4", "ip_local_port_range"})
	require.NoError(t, err)
	prevReservedPortRanges, err := sysctl.Read([]string{"net", "ipv4", "ip_local_reserved_ports"})
	require.NoError(t, err)

	t.Cleanup(func() {
		err = sysctl.Write([]string{"net", "ipv4", "ip_local_port_range"}, prevEphemeralPortRange)
		require.NoError(t, err)
		err = sysctl.Write([]string{"net", "ipv4", "ip_local_reserved_ports"}, prevReservedPortRanges)
		require.NoError(t, err)
	})

	cases := []struct {
		npMin       uint16
		npMax       uint16
		epMin       uint16
		epMax       uint16
		resPorts    string
		autoProtect bool

		expResPorts string
		expErr      bool
		expErrMatch string
	}{
		{32000, 32999, 10000, 40000, "\n", true, "32000-32999", false, ""},
		{32000, 32999, 10000, 40000, "\n", false, "", true, ".* must not clash.*"},
		{32000, 32999, 10000, 40000, "32000-32500\n", true, "32000-32999", false, ""},
		{32000, 32999, 10000, 40000, "32000-33000\n", false, "32000-33000", false, ""},
		{32000, 32999, 33000, 40000, "\n", false, "", false, ""},
		{32000, 32999, 10000, 40000, "20000\n", true, "20000,32000-32999", false, ""},
		{32000, 32999, 10000, 20000, "\n", true, "", true, ".* after ephemeral.*"},
	}

	for _, test := range cases {
		var cfg loadbalancer.Config
		cfg.NodePortMin = test.npMin
		cfg.NodePortMax = test.npMax
		option.Config.EnableAutoProtectNodePortRange = test.autoProtect
		err := sysctl.Write([]string{"net", "ipv4", "ip_local_port_range"},
			fmt.Sprintf("%d %d", test.epMin, test.epMax))
		require.NoError(t, err)
		err = sysctl.Write([]string{"net", "ipv4", "ip_local_reserved_ports"}, test.resPorts)
		require.NoError(t, err)

		err = checkNodePortAndEphemeralPortRanges(cfg, sysctl)
		if test.expErr {
			require.Condition(t, errorMatch(err, test.expErrMatch))
		} else {
			require.NoError(t, err)
			resPorts, err := sysctl.Read([]string{"net", "ipv4", "ip_local_reserved_ports"})
			require.NoError(t, err)
			require.Equal(t, test.expResPorts, resPorts)
		}
	}
}
