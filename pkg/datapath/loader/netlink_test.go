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
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
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
	t.Cleanup(func() {
		p.Close()
	})
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
	t.Cleanup(func() {
		p.Close()
	})
	return p
}

func TestSetupDev(t *testing.T) {
	testutils.PrivilegedTest(t)

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

		err = enableForwarding(sysctl, dummy)
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

func TestSetupTunnelDevice(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	mtu := 1500

	t.Run("Geneve", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*netlink.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, geneve.Dport, defaults.TunnelPortGeneve)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu)
			require.NoError(t, err)

			err = setupTunnelDevice(sysctl, tunnel.Geneve, 12345, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*netlink.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, geneve.Dport, 12345)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu-1)
			require.NoError(t, err)

			link, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, mtu-1, link.Attrs().MTU)

			return nil
		})
	})

	t.Run("Vxlan", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, vxlan.Port, defaults.TunnelPortVXLAN)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, mtu)
			require.NoError(t, err)

			err = setupTunnelDevice(sysctl, tunnel.VXLAN, 12345, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, vxlan.Port, 12345)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, mtu-1)
			require.NoError(t, err)

			link, err = netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, mtu-1, link.Attrs().MTU)

			return nil
		})
	})

	t.Run("EnableSwitchDisable", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			// Start with a Geneve tunnel.
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Switch to vxlan mode.
			err = setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Switch back to Geneve.
			err = setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Disable tunneling.
			err = setupTunnelDevice(sysctl, tunnel.Disabled, 0, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)

			return nil
		})
	})
}

func TestAddHostDeviceAddr(t *testing.T) {
	testutils.PrivilegedTest(t)

	// test IP addresses
	testIPv4 := net.ParseIP("1.2.3.4")
	testIPv6 := net.ParseIP("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")

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

func TestAttachRemoveTCProgram(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		ifName := "dummy0"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: ifName,
			},
		}
		err := netlink.LinkAdd(dummy)
		require.NoError(t, err)

		prog := mustTCProgram(t)

		bpffs := testutils.TempBPFFS(t)
		err = attachTCProgram(dummy, prog, "test", bpffsDeviceLinksDir(bpffs, dummy), directionToParent(dirEgress))
		require.NoError(t, err)

		filters, err := netlink.FilterList(dummy, directionToParent(dirEgress))
		require.NoError(t, err)
		require.NotEmpty(t, filters)

		err = removeTCFilters(dummy.Attrs().Name, directionToParent(dirEgress))
		require.NoError(t, err)

		filters, err = netlink.FilterList(dummy, directionToParent(dirEgress))
		require.NoError(t, err)
		require.Empty(t, filters)

		err = netlink.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestSetupIPIPDevices(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		err := setupIPIPDevices(sysctl, true, true)
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

		err = setupIPIPDevices(sysctl, false, false)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
