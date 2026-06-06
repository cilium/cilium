// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	fakebigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/fake"
	bigtcptypes "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/types"
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

func TestPrivilegedSetupDev(t *testing.T) {
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

		err = enableForwarding(logger, sysctl, dummy)
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

	t.Run("VxlanBigTCPClampsGSOToTSO", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			bc := &bigTCPStub{groV4: 196608, gsoV4: 196608, groV6: 196608, gsoV6: 196608}
			err := setupTunnelDevice(logger, sysctl, tunnel.VXLAN, defaults.TunnelPortVXLAN, 0, 0, mtu, bc)
			require.NoError(t, err)

			link, err := safenetlink.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			if gso := int(link.Attrs().GSOMaxSize); gso != 0 {
				require.LessOrEqual(t, gso, bigtcptypes.GROGSOLegacyMaxSize)
			}

			require.NoError(t, netlink.LinkDel(link))
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

// bigTCPStub is a test stand-in for bigtcp.Config that returns arbitrary
// GSO/GRO max sizes, used to exercise the tunnel GSO clamping logic.
type bigTCPStub struct {
	groV4, gsoV4, groV6, gsoV6 int
}

func (c *bigTCPStub) IsIPv4Enabled() bool    { return c.gsoV4 != 0 }
func (c *bigTCPStub) IsIPv6Enabled() bool    { return c.gsoV6 != 0 }
func (c *bigTCPStub) GetGROIPv4MaxSize() int { return c.groV4 }
func (c *bigTCPStub) GetGSOIPv4MaxSize() int { return c.gsoV4 }
func (c *bigTCPStub) GetGROIPv6MaxSize() int { return c.groV6 }
func (c *bigTCPStub) GetGSOIPv6MaxSize() int { return c.gsoV6 }

func TestTunnelGSOMaxSize(t *testing.T) {
	tests := []struct {
		name       string
		requested  int
		tsoMaxSize int
		want       int
	}{
		{
			name:       "high-tso NIC, legacy tunnel ceiling: clamp down",
			requested:  196608,
			tsoMaxSize: bigtcptypes.GROGSOLegacyMaxSize,
			want:       bigtcptypes.GROGSOLegacyMaxSize,
		},
		{
			name:       "tso not reported (old kernel): fall back to legacy limit",
			requested:  196608,
			tsoMaxSize: 0,
			want:       bigtcptypes.GROGSOLegacyMaxSize,
		},
		{
			name:       "tunnel supports BIG TCP: no clamp",
			requested:  196608,
			tsoMaxSize: 524280,
			want:       196608,
		},
		{
			name:       "requested already below tso: unchanged",
			requested:  bigtcptypes.GROGSOLegacyMaxSize,
			tsoMaxSize: 524280,
			want:       bigtcptypes.GROGSOLegacyMaxSize,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tunnelGSOMaxSize(tt.requested, tt.tsoMaxSize))
		})
	}
}
