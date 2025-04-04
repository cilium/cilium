// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
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

// lo accesses the default loopback interface present in the current netns.
var lo = &netlink.GenericLink{
	LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1},
	LinkType:  "loopback",
}

func mustXDPProgram(t *testing.T, name string) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Name: name,
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

func TestSetupTunnelDevice(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	mtu := 1500

	t.Run("Geneve", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*netlink.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, defaults.TunnelPortGeneve, geneve.Dport)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu)
			require.NoError(t, err)

			err = setupTunnelDevice(sysctl, tunnel.Geneve, 12345, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*netlink.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, 12345, geneve.Dport)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu-1)
			require.NoError(t, err)

			link, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, mtu-1, link.Attrs().MTU)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("Vxlan", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, defaults.TunnelPortVXLAN, vxlan.Port)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu)
			require.NoError(t, err)

			err = setupTunnelDevice(sysctl, tunnel.VXLAN, 12345, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, 12345, vxlan.Port)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu-1)
			require.NoError(t, err)

			link, err = netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, mtu-1, link.Attrs().MTU)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanSrcPortRange", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			srcMin := uint16(1000)
			srcMax := uint16(2000)

			err := setupTunnelDevice(sysctl, tunnel.VXLAN, 4567, srcMin, srcMax, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, 4567, vxlan.Port)
			require.EqualValues(t, srcMin, vxlan.PortLow)
			require.EqualValues(t, srcMax, vxlan.PortHigh)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanSrcPortRangeExistingDev", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			srcMin := uint16(1000)
			srcMax := uint16(2000)

			err := setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu)
			require.NoError(t, err)

			link, err := netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.EqualValues(t, 0, vxlan.PortLow)
			require.EqualValues(t, 0, vxlan.PortHigh)

			err = setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, srcMin, srcMax, mtu)
			require.NoError(t, err)

			link, err = netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// On existing device the port range should not change.
			vxlan, ok = link.(*netlink.Vxlan)
			require.True(t, ok)
			require.EqualValues(t, 0, vxlan.PortLow)
			require.EqualValues(t, 0, vxlan.PortHigh)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("EnableSwitchDisable", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			// Start with a Geneve tunnel.
			err := setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Switch to vxlan mode.
			err = setupTunnelDevice(sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Switch back to Geneve.
			err = setupTunnelDevice(sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = netlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Disable tunneling.
			err = setupTunnelDevice(sysctl, tunnel.Disabled, 0, 0, 0, mtu)
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
		require.True(t, foundIPv4)
		require.True(t, foundIPv6)

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
		err := setupIPIPDevices(sysctl, true, true, 1500)
		require.NoError(t, err)

		dev4, err := netlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.EqualValues(t, dev4.Attrs().MTU, 1480)

		dev6, err := netlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.EqualValues(t, dev6.Attrs().MTU, 1452)

		_, err = netlink.LinkByName("cilium_tunl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("cilium_ip6tnl")
		require.NoError(t, err)

		_, err = netlink.LinkByName("tunl0")
		require.Error(t, err)

		_, err = netlink.LinkByName("ip6tnl0")
		require.Error(t, err)

		err = setupIPIPDevices(sysctl, false, false, 1500)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		err = setupIPIPDevices(sysctl, true, true, 1480)
		require.NoError(t, err)

		dev4, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.NoError(t, err)
		require.EqualValues(t, dev4.Attrs().MTU, 1460)

		dev6, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.NoError(t, err)
		require.EqualValues(t, dev6.Attrs().MTU, 1432)

		err = setupIPIPDevices(sysctl, false, false, 1480)
		require.NoError(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv4Device)
		require.Error(t, err)

		_, err = netlink.LinkByName(defaults.IPIPv6Device)
		require.Error(t, err)

		return nil
	})
}
