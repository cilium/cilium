// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
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

// TestPrivilegedSetupBaseDeviceARPOffBeforeUp checks that setupBaseDevice turns
// ARP off on cilium_host and cilium_net before it brings them up. The kernel runs
// duplicate address detection on the EUI-64 link-local of a veth end that comes
// up with ARP still on, and withholds that address from netlink subscribers until
// detection finishes. The from-proxy routes take cilium_net's link-local as their
// nexthop, so cilium-agent cannot install them until it appears.
//
// The test reads the RTM_NEWLINK stream, where the kernel emits one notification
// per flag change. Address dumps cannot show the ordering: ipv6_add_addr() sets
// IFA_F_TENTATIVE on every link-local and the addrconf workqueue clears it later.
func TestPrivilegedSetupBaseDeviceARPOffBeforeUp(t *testing.T) {
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
		// Subscribe first: the socket only sees notifications sent after it opens.
		updates := make(chan netlink.LinkUpdate, 128)
		done := make(chan struct{})
		defer close(done)
		require.NoError(t, netlink.LinkSubscribe(updates, done))

		_, _, err := setupBaseDevice(logger, sysctl, 1500)
		require.NoError(t, err)

		// setupBaseDevice has returned, so the socket already holds its updates.
		remaining := []string{defaults.HostDevice, defaults.SecondHostDevice}
		for len(remaining) > 0 {
			var update netlink.LinkUpdate
			var ok bool
			select {
			case update, ok = <-updates:
				require.True(t, ok, "link subscription ended before %v were brought up", remaining)
			case <-time.After(time.Minute):
				require.FailNow(t, "timeout", "no link up notification for %v", remaining)
			}

			i := slices.Index(remaining, update.Attrs().Name)
			if i < 0 || update.Header.Type != unix.RTM_NEWLINK ||
				update.IfInfomsg.Flags&unix.IFF_UP == 0 {
				continue
			}

			require.NotZero(t, update.IfInfomsg.Flags&unix.IFF_NOARP,
				"%s was brought up with ARP on, the kernel runs duplicate address detection on its link-local",
				update.Attrs().Name)
			remaining = slices.Delete(remaining, i, i+1)
		}

		return nil
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
