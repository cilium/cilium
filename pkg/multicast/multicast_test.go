// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestGroupOps(t *testing.T) {
	logger := hivetest.Logger(t)
	ifs, err := netlink.LinkList()
	require.NoError(t, err)

	if len(ifs) == 0 {
		t.Skip("no interfaces to test")
	}

	ifc := ifs[0]
	maddr := randMaddr()

	// Join Group
	err = JoinGroup(logger, ifc.Attrs().Name, maddr)
	require.NoError(t, err)

	// maddr in group
	inGroup, err := IsInGroup(ifc.Attrs().Name, maddr)
	require.NoError(t, err)
	require.True(t, inGroup)

	// LeaveGroup
	err = LeaveGroup(logger, ifc.Attrs().Name, maddr)
	require.NoError(t, err)

	// maddr not in group
	inGroup, err = IsInGroup(ifc.Attrs().Name, maddr)
	require.NoError(t, err)
	require.False(t, inGroup)
}

func TestSolicitedNodeMaddr(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{
			ip:       "f00d:abcd:ef01::abcd",
			expected: "ff02::1:ff00:abcd",
		},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.ip)
		got := Address(ip).SolicitedNodeMaddr().String()
		require.Equal(t, test.expected, got)
	}

}

func randMaddr() netip.Addr {
	maddr := make([]byte, 16)
	rand.Read(maddr[13:])
	return Address(netip.AddrFrom16(*(*[16]byte)(maddr))).SolicitedNodeMaddr()
}

func TestMcastKey(t *testing.T) {
	tests := []struct {
		ipv6 string
		key  int32
	}{
		{
			ipv6: "f00d::",
			key:  0x0,
		},
		{
			ipv6: "f00d::1000",
			key:  0x1000,
		},
		{
			ipv6: "f00d::11:1000",
			key:  0x111000,
		},
		{
			ipv6: "f00d::aa:aaaa",
			key:  0xaaaaaa,
		},
		{
			ipv6: "f00d::ff:ffff",
			key:  0xffffff,
		},
		{
			ipv6: "f00d::11ff:ffff",
			key:  0xffffff,
		},
	}

	for _, test := range tests {
		ipv6 := netip.MustParseAddr(test.ipv6)
		require.Equal(t, test.key, Address(ipv6).Key())
	}
}
