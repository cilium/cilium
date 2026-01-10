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

		got, err := firstGlobalV4Addr(ifName, net.ParseIP(tc.preferredIP))
		require.NoError(t, err)
		require.Equal(t, tc.want, got.String())
		removeDevice(ifName)
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
