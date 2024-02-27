// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"fmt"
	"net"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils/netns"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type fakeMTU struct {
	mtu int
}

func (f *fakeMTU) GetDeviceMTU() int {
	return f.mtu
}

func (f *fakeMTU) GetRoutePostEncryptMTU() int {
	return f.mtu
}

func (f *fakeMTU) GetRouteMTU() int {
	return f.mtu
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

	orch := newOrchestrator(orchestratorParams{
		Netlink: newRealNetlink(),
		Logger:  logging.DefaultLogger,
		Sysctl:  sysctl,
		Mtu: &fakeMTU{
			mtu: 1500,
		},
	})

	ns.Do(func() error {
		ifName := "dummy"
		dummy := &vnl.Dummy{
			LinkAttrs: vnl.LinkAttrs{
				Name: ifName,
			},
		}
		err := vnl.LinkAdd(dummy)
		require.NoError(t, err)

		err = orch.enableForwarding(dummy)
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

		err = vnl.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}

func TestSetupTunnelDevice(t *testing.T) {
	testutils.PrivilegedTest(t)

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	orch := newOrchestrator(orchestratorParams{
		Netlink: newRealNetlink(),
		Logger:  logging.DefaultLogger,
		Sysctl:  sysctl,
		Mtu: &fakeMTU{
			mtu: 1500,
		},
	})

	t.Run("Geneve", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*vnl.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, geneve.Dport, defaults.TunnelPortGeneve)

			err = vnl.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)

			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, 12345))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			geneve, ok := link.(*vnl.Geneve)
			require.True(t, ok)
			require.True(t, geneve.FlowBased)
			require.EqualValues(t, geneve.Dport, 12345)

			err = vnl.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("GeneveModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			orch.params.Mtu = &fakeMTU{
				mtu: 1499,
			}
			defer func() {
				orch.params.Mtu = &fakeMTU{
					mtu: 1500,
				}
			}()

			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)

			link, err = vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, 1499, link.Attrs().MTU)

			return nil
		})
	})

	t.Run("Vxlan", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, defaults.TunnelPortVXLAN))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*vnl.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, vxlan.Port, defaults.TunnelPortVXLAN)

			err = vnl.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyPort", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, defaults.TunnelPortVXLAN))
			require.NoError(t, err)

			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, 12345))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			vxlan, ok := link.(*vnl.Vxlan)
			require.True(t, ok)
			require.True(t, vxlan.FlowBased)
			require.EqualValues(t, vxlan.Port, 12345)

			err = vnl.LinkDel(link)
			require.NoError(t, err)

			return nil
		})
	})

	t.Run("VxlanModifyMTU", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, defaults.TunnelPortVXLAN))
			require.NoError(t, err)

			link, err := vnl.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Ensure the ifindex does not change when specifying a different MTU.
			ifindex := link.Attrs().Index

			orch.params.Mtu = &fakeMTU{
				mtu: 1499,
			}
			defer func() {
				orch.params.Mtu = &fakeMTU{
					mtu: 1500,
				}
			}()

			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, defaults.TunnelPortVXLAN))
			require.NoError(t, err)

			link, err = vnl.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			require.Equal(t, ifindex, link.Attrs().Index, "ifindex must not change when changing MTU")
			require.Equal(t, 1499, link.Attrs().MTU)

			return nil
		})
	})

	t.Run("EnableSwitchDisable", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			// Start with a Geneve tunnel.
			err := orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Switch to vxlan mode.
			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.VXLAN, defaults.TunnelPortVXLAN))
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.GeneveDevice)
			require.Error(t, err)
			_, err = vnl.LinkByName(defaults.VxlanDevice)
			require.NoError(t, err)

			// Switch back to Geneve.
			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Geneve, defaults.TunnelPortGeneve))
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.GeneveDevice)
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)

			// Disable tunneling.
			err = orch.setupTunnelDevice(tunnel.NewTestConfig(tunnel.Disabled, 0))
			require.NoError(t, err)
			_, err = vnl.LinkByName(defaults.VxlanDevice)
			require.Error(t, err)
			_, err = vnl.LinkByName(defaults.GeneveDevice)
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

	sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	orch := newOrchestrator(orchestratorParams{
		Netlink: newRealNetlink(),
		Logger:  logging.DefaultLogger,
		Sysctl:  sysctl,
		Mtu: &fakeMTU{
			mtu: 1500,
		},
	})

	ns.Do(func() error {
		ifName := "dummy"
		dummy := &vnl.Dummy{
			LinkAttrs: vnl.LinkAttrs{
				Name: ifName,
			},
		}
		err := vnl.LinkAdd(dummy)
		require.NoError(t, err)

		err = orch.addHostDeviceAddr(dummy, testIPv4, testIPv6)
		require.NoError(t, err)

		addrs, err := vnl.AddrList(dummy, vnl.FAMILY_ALL)
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

		err = vnl.LinkDel(dummy)
		require.NoError(t, err)

		return nil
	})
}
