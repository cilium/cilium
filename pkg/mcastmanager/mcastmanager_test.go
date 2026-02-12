// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcastmanager

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestAddRemoveEndpoint(t *testing.T) {
	logger := hivetest.Logger(t)
	ifaces, err := netlink.LinkList()
	require.NoError(t, err)

	if len(ifaces) == 0 {
		t.Skip("no interfaces to test")
	}

	mgr := New(logger, ifaces[0].Attrs().Name)

	// Add first endpoint
	mgr.AddAddress(netip.MustParseAddr("f00d::1234"))

	require.Len(t, mgr.state, 1)
	_, ok := mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.True(t, ok)

	// Add another endpoint that shares the same maddr
	mgr.AddAddress(netip.MustParseAddr("f00d:aabb::1234"))

	require.Len(t, mgr.state, 1)

	// Remove the first endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d::1234"))

	require.Len(t, mgr.state, 1)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.True(t, ok)

	// Remove the second endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d:aabb::1234"))

	require.Empty(t, mgr.state)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	require.False(t, ok)
}

func TestAddRemoveNil(t *testing.T) {
	logger := hivetest.Logger(t)
	ifaces, err := netlink.LinkList()
	require.NoError(t, err)

	if len(ifaces) == 0 {
		t.Skip("no interfaces to test")
	}

	var (
		iface = ifaces[0]
		mgr   = New(logger, iface.Attrs().Name)
	)

	mgr.AddAddress(netip.Addr{})
	require.Empty(t, mgr.state)
	mgr.RemoveAddress(netip.Addr{})
	require.Empty(t, mgr.state)
}
