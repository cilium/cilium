// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcastmanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestAddRemoveEndpoint(t *testing.T) {
	ifaces, err := netlink.LinkList()
	require.Nil(t, err)

	if len(ifaces) == 0 {
		t.Skip("no interfaces to test")
	}

	mgr := New(ifaces[0].Attrs().Name)

	// Add first endpoint
	mgr.AddAddress(netip.MustParseAddr("f00d::1234"))

	require.Len(t, mgr.state, 1)
	_, ok := mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.Equal(t, true, ok)

	// Add another endpoint that shares the same maddr
	mgr.AddAddress(netip.MustParseAddr("f00d:aabb::1234"))

	require.Len(t, mgr.state, 1)

	// Remove the first endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d::1234"))

	require.Len(t, mgr.state, 1)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.Equal(t, true, ok)

	// Remove the second endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d:aabb::1234"))

	require.Len(t, mgr.state, 0)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.Equal(t, false, ok)
}

func TestAddRemoveNil(t *testing.T) {
	ifaces, err := netlink.LinkList()
	require.Nil(t, err)

	if len(ifaces) == 0 {
		t.Skip("no interfaces to test")
	}

	var (
		iface = ifaces[0]
		mgr   = New(iface.Attrs().Name)
	)

	mgr.AddAddress(netip.Addr{})
	require.Len(t, mgr.state, 0)
	mgr.RemoveAddress(netip.Addr{})
	require.Len(t, mgr.state, 0)
}
