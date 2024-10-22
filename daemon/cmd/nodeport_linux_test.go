// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type NodePortSuite struct {
	prevEphemeralPortRange string
	prevReservedPortRanges string
	sysctl                 sysctl.Sysctl
}

func setupNodePortSuite(tb testing.TB) *NodePortSuite {
	testutils.PrivilegedTest(tb)

	s := &NodePortSuite{}
	s.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	prevEphemeralPortRange, err := s.sysctl.Read([]string{"net", "ipv4", "ip_local_port_range"})
	require.Nil(tb, err)
	s.prevEphemeralPortRange = prevEphemeralPortRange
	prevReservedPortRanges, err := s.sysctl.Read([]string{"net", "ipv4", "ip_local_reserved_ports"})
	require.Nil(tb, err)
	s.prevReservedPortRanges = prevReservedPortRanges

	tb.Cleanup(func() {
		err = s.sysctl.Write([]string{"net", "ipv4", "ip_local_port_range"}, s.prevEphemeralPortRange)
		require.Nil(tb, err)
		err = s.sysctl.Write([]string{"net", "ipv4", "ip_local_reserved_ports"}, s.prevReservedPortRanges)
		require.Nil(tb, err)
	})

	return s
}

func TestCheckNodePortAndEphemeralPortRanges(t *testing.T) {
	s := setupNodePortSuite(t)

	cases := []struct {
		npMin       int
		npMax       int
		epMin       int
		epMax       int
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
		option.Config.NodePortMin = test.npMin
		option.Config.NodePortMax = test.npMax
		option.Config.EnableAutoProtectNodePortRange = test.autoProtect
		err := s.sysctl.Write([]string{"net", "ipv4", "ip_local_port_range"},
			fmt.Sprintf("%d %d", test.epMin, test.epMax))
		require.Nil(t, err)
		err = s.sysctl.Write([]string{"net", "ipv4", "ip_local_reserved_ports"}, test.resPorts)
		require.Nil(t, err)

		err = checkNodePortAndEphemeralPortRanges(s.sysctl)
		if test.expErr {
			require.Condition(t, errorMatch(err, test.expErrMatch))
		} else {
			require.Nil(t, err)
			resPorts, err := s.sysctl.Read([]string{"net", "ipv4", "ip_local_reserved_ports"})
			require.Nil(t, err)
			require.Equal(t, test.expResPorts, resPorts)
		}
	}
}
