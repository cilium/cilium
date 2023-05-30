// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"fmt"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestSetupDev(t *testing.T) {
	testutils.PrivilegedTest(t)

	prevConfigEnableIPv4 := option.Config.EnableIPv4
	prevConfigEnableIPv6 := option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4 = prevConfigEnableIPv4
		option.Config.EnableIPv6 = prevConfigEnableIPv6
	})
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	netnsName := "test-setup-dev"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		ifName := "dummy"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
		}
		err := netlink.LinkAdd(dummy)
		require.NoError(t, err)

		err = setupDev(dummy)
		require.NoError(t, err)

		enabledSettings := []string{
			fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName),
			fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName),
			fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName),
		}
		disabledSettings := []string{
			fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName),
			fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName),
		}
		for _, setting := range enabledSettings {
			s, err := sysctl.Read(setting)
			require.NoError(t, err)
			require.Equal(t, s, "1")
		}
		for _, setting := range disabledSettings {
			s, err := sysctl.Read(setting)
			require.NoError(t, err)
			require.Equal(t, s, "0")
		}

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}
