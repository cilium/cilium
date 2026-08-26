// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	fakebigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
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

// TestPrivilegedSetupBaseDeviceIPv6NotTentative checks that the IPv6 link-local
// addresses of the base devices are usable as soon as setupBaseDevice returns.
// Bringing a link up before turning ARP off leaves the kernel-generated
// link-local tentative for as long as duplicate address detection takes, and
// the kernel does not notify subscribers about tentative addresses, so the
// devices table stays without an IPv6 address for cilium_net and the from-proxy
// routes cannot be installed.
func TestPrivilegedSetupBaseDeviceIPv6NotTentative(t *testing.T) {
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
		_, _, err := setupBaseDevice(logger, sysctl, 1500)
		require.NoError(t, err)

		for _, devName := range []string{defaults.HostDevice, defaults.SecondHostDevice} {
			link, err := safenetlink.LinkByName(devName)
			require.NoError(t, err)

			require.NotZero(t, link.Attrs().RawFlags&unix.IFF_NOARP,
				"%s should have ARP off", devName)

			// The kernel adds the link-local from a workqueue, so wait for it
			// to show up and assert on the flags it is created with. With ARP
			// off it is created permanent, otherwise it starts out tentative.
			// Polled inline because the network namespace is per-thread, so
			// the wait cannot run on another goroutine.
			var addrs []netlink.Addr
			for range 5000 {
				addrs, err = safenetlink.AddrList(link, netlink.FAMILY_V6)
				require.NoError(t, err)
				if len(addrs) > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			require.NotEmpty(t, addrs, "%s should get an IPv6 link-local address", devName)

			for _, addr := range addrs {
				require.Zero(t, addr.Flags&unix.IFA_F_TENTATIVE,
					"%s address %s was created tentative, duplicate address detection was not skipped", devName, addr.IP)
				require.Zero(t, addr.Flags&unix.IFA_F_DADFAILED,
					"%s address %s failed duplicate address detection", devName, addr.IP)
			}
		}

		return nil
	})
}

func TestPrivilegedSetupTunnelDevice(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	mtu := 1500

	t.Run("Geneve", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*netlink.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.Equal(t, defaults.TunnelPortGeneve, geneve.Dport)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			err = setupTunnelDevice(logger, sysctl, tunnel.Geneve, 12345, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.GeneveDevice)
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
			err := setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu-1, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err = safenetlink.LinkByName(defaults.GeneveDevice)
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
			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
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
			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, 12345, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.Equal(t, 12345, vxlan.Port)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanConflictWithExternallyManagedDevice", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			externallyMangedVxlan := &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: "extManagedVxlan",
				},
				Port: int(defaults.TunnelPortVXLAN),
			}
			err := netlink.LinkAdd(externallyMangedVxlan)
			require.NoError(t, err)

			err = netlink.LinkSetUp(externallyMangedVxlan)
			require.NoError(t, err)

			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.Error(t, err)

			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, 12345, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.Equal(t, 12345, vxlan.Port)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu-1, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err = safenetlink.LinkByName(defaults.VxlanDevice)
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

			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, 4567, srcMin, srcMax, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.Equal(t, 4567, vxlan.Port)
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

			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*netlink.Vxlan)
			require.True(t, ok)
			require.Equal(t, 0, vxlan.PortLow)
			require.Equal(t, 0, vxlan.PortHigh)

			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, srcMin, srcMax, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)

			link, err = safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// On existing device the port range should not change.
			vxlan, ok = link.(*netlink.Vxlan)
			require.True(t, ok)
			require.Equal(t, 0, vxlan.PortLow)
			require.Equal(t, 0, vxlan.PortHigh)

			err = netlink.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("EnableSwitchDisable", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			// Start with a Geneve tunnel.
			err := setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Switch to vxlan mode.
			err = setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)
			_, err = safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Switch back to Geneve.
			err = setupTunnelDevice(logger, sysctl, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Disable tunneling.
			err = setupTunnelDevice(logger, sysctl, tunnel.Disabled, 0, 0, 0, mtu, &fakebigtcp.Config{})
			require.NoError(t, err)
			_, err = safenetlink.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)
			_, err = safenetlink.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)

			return nil
		})
	})
}

func TestPrivilegedAddHostDeviceAddr(t *testing.T) {
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

		addrs, err := safenetlink.AddrList(dummy, netlink.FAMILY_ALL)
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
