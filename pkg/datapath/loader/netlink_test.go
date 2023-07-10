// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/testutils"
)

func mustTCProgram(t *testing.T) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		t.Skipf("tc programs not supported: %s", err)
	}
	return p
}

func mustXDPProgram(t *testing.T) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		t.Skipf("xdp programs not supported: %s", err)
	}
	return p
}

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

		err = enableForwarding(dummy)
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

func TestAddHostDeviceAddr(t *testing.T) {
	testutils.PrivilegedTest(t)

	// test IP addresses
	testIPv4 := net.ParseIP("1.2.3.4")
	testIPv6 := net.ParseIP("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")

	netnsName := "test-internal-node-ips"
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

		err = addHostDeviceAddr(dummy, testIPv4, testIPv6)
		require.NoError(t, err)

		addrs, err := netlink.AddrList(dummy, netlink.FAMILY_ALL)
		require.NoError(t, err)

		var foundIPv4, foundIPv6 bool
		for _, addr := range addrs {
			if testIPv4.Equal(addr.IP) {
				foundIPv4 = true
			}
			if testIPv6.Equal(addr.IP) {
				foundIPv6 = true
			}
		}
		require.Equal(t, foundIPv4, true)
		require.Equal(t, foundIPv6, true)

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestAttachProgram(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-attach-program"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	t.Run("TC", func(t *testing.T) {
		netns0.Do(func(_ ns.NetNS) error {
			ifName := "dummy0"
			dummy := &netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: ifName,
				},
			}
			err := netlink.LinkAdd(dummy)
			require.NoError(t, err)

			prog := mustTCProgram(t)

			err = attachProgram(dummy, prog, "test", directionToParent(dirEgress), 0)
			require.NoError(t, err)

			filters, err := netlink.FilterList(dummy, directionToParent(dirEgress))
			require.NoError(t, err)
			require.NotEmpty(t, filters)

			err = netlink.LinkDel(dummy)
			require.NoError(t, err)

			return nil
		})

	})

	t.Run("XDP", func(t *testing.T) {
		netns0.Do(func(_ ns.NetNS) error {
			veth := &netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
				PeerName:  "veth1",
			}
			err := netlink.LinkAdd(veth)
			require.NoError(t, err)

			prog := mustXDPProgram(t)

			err = attachProgram(veth, prog, "test", 0, xdpModeToFlag(option.XDPModeLinkDriver))
			require.NoError(t, err)

			link, err := netlink.LinkByName("veth0")
			require.NoError(t, err)
			require.NotNil(t, link.Attrs().Xdp)
			require.True(t, link.Attrs().Xdp.Attached)

			err = netlink.LinkDel(veth)
			require.NoError(t, err)

			return nil
		})

	})

}

func TestRemoveTCPrograms(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-remove-programs"
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

		prog := mustTCProgram(t)

		err = attachProgram(dummy, prog, "test", directionToParent(dirEgress), 0)
		require.NoError(t, err)

		err = RemoveTCFilters(dummy.Attrs().Name, directionToParent(dirEgress))
		require.NoError(t, err)

		filters, err := netlink.FilterList(dummy, directionToParent(dirEgress))
		require.NoError(t, err)
		require.Empty(t, filters)

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestSetupIPIPDevices(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-setup-ipip-devs"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		err := setupIPIPDevices(true, true)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)

		_, err = netlink.LinkByName("cilium_tunl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("cilium_ip6tnl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("tunl0")
		require.Error(t, err)

		_, err = netlink.LinkByName("ip6tnl0")
		require.Error(t, err)

		err = setupIPIPDevices(false, false)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
