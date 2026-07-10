// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !darwin

package node

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
)

func setUpSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)
}

func TestPrivilegedFirstGlobalV4Addr(t *testing.T) {
	setUpSuite(t)

	testCases := []struct {
		name           string
		ipsOnInterface []string
		preferredIP    string
		want           string
	}{
		{
			name:           "public IP preferred by default",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			want:           "21.0.0.1",
		},
		{
			name:           "prefer public IP over preferred IP",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			preferredIP:    "192.168.0.1",
			want:           "21.0.0.1",
		},
		{
			name:           "primary IP preferred by default",
			ipsOnInterface: []string{"192.168.0.2", "192.168.0.1"},
			want:           "192.168.0.2",
		},
		{
			name:           "preferred IP if defined",
			ipsOnInterface: []string{"192.168.0.2", "192.168.0.1"},
			preferredIP:    "192.168.0.1",
			want:           "192.168.0.1",
		},
	}
	const ifName = "dummy_iface"
	for _, tc := range testCases {
		err := setupDummyDevice(ifName, tc.ipsOnInterface...)
		require.NoError(t, err)

		got, err := FirstGlobalV4Addr(ifName, net.ParseIP(tc.preferredIP))
		require.NoError(t, err)
		require.Equal(t, tc.want, got.String())
		removeDevice(ifName)
	}
}

func TestAddrUsableAsNodeIP(t *testing.T) {
	testCases := []struct {
		name          string
		addr          netlink.Addr
		isPreferredIP bool
		ipsToExclude  []net.IP
		linkScopeMax  int
		ipLen         int
		want          bool
	}{
		{
			name:         "plain IPv4 is usable",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_UNIVERSE)},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        4,
			want:         true,
		},
		{
			name:         "tentative IPv6 is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}, Scope: int(unix.RT_SCOPE_UNIVERSE), Flags: unix.IFA_F_TENTATIVE},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        16,
			want:         false,
		},
		{
			name:         "dadfailed IPv6 is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)}, Scope: int(unix.RT_SCOPE_UNIVERSE), Flags: unix.IFA_F_DADFAILED},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        16,
			want:         false,
		},
		{
			name:         "tentative and dadfailed combined is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::3"), Mask: net.CIDRMask(64, 128)}, Scope: int(unix.RT_SCOPE_UNIVERSE), Flags: unix.IFA_F_TENTATIVE | unix.IFA_F_DADFAILED},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        16,
			want:         false,
		},
		{
			name:          "secondary IPv4 is rejected unless preferred",
			addr:          netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_UNIVERSE), Flags: unix.IFA_F_SECONDARY},
			isPreferredIP: false,
			linkScopeMax:  int(unix.RT_SCOPE_UNIVERSE),
			ipLen:         4,
			want:          false,
		},
		{
			name:          "secondary IPv4 is accepted when it is the preferred IP",
			addr:          netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_UNIVERSE), Flags: unix.IFA_F_SECONDARY},
			isPreferredIP: true,
			linkScopeMax:  int(unix.RT_SCOPE_UNIVERSE),
			ipLen:         4,
			want:          true,
		},
		{
			name:         "address narrower than allowed scope is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_HOST)},
			linkScopeMax: int(unix.RT_SCOPE_SITE),
			ipLen:        4,
			want:         false,
		},
		{
			name:         "excluded address is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_UNIVERSE)},
			ipsToExclude: []net.IP{net.ParseIP("10.0.0.1")},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        4,
			want:         false,
		},
		{
			name:         "address shorter than required ipLen is rejected",
			addr:         netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1").To4(), Mask: net.CIDRMask(24, 32)}, Scope: int(unix.RT_SCOPE_UNIVERSE)},
			linkScopeMax: int(unix.RT_SCOPE_UNIVERSE),
			ipLen:        16,
			want:         false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := addrUsableAsNodeIP(tc.addr, tc.isPreferredIP, tc.ipsToExclude, tc.linkScopeMax, tc.ipLen)
			require.Equal(t, tc.want, got)
		})
	}
}

func setupDummyDevice(name string, ips ...string) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("netlink.LinkAdd failed: %w", err)
	}

	if err := netlink.LinkSetUp(dummy); err != nil {
		removeDevice(name)
		return fmt.Errorf("netlink.LinkSetUp failed: %w", err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			removeDevice(name)
			return fmt.Errorf("invalid ipv4 IP : %v", ipStr)
		}
		ipnet := &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		addr := &netlink.Addr{IPNet: ipnet}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			removeDevice(name)
			return err
		}
	}

	return nil
}

func removeDevice(name string) {
	l, err := safenetlink.LinkByName(name)
	if err == nil {
		netlink.LinkDel(l)
	}
}
