// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
)

// TestPrivilegedDefaultRouteHookOnlyUpdatesCiliumLinks verifies that
// defaultRouteHook only sets the MTU on veth interfaces that were created
// by Cilium (identified via the cilium_cni altname), and leaves interfaces
// created by other CNI plugins untouched.
func TestPrivilegedDefaultRouteHookOnlyUpdatesCiliumLinks(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		initMTU = 1500
		newMTU  = 1400
	)

	// Create a Cilium-managed veth pair (host side: cilium-h, peer side: cilium-p).
	ciliumVeth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   "test-cilium-h",
			TxQLen: 1000,
		},
		PeerName: "test-cilium-p",
	}
	require.NoError(t, netlink.LinkAdd(ciliumVeth))
	defer netlink.LinkDel(ciliumVeth)

	// Set initial MTU on the cilium peer.
	ciliumPeer, err := safenetlink.LinkByName("test-cilium-p")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetMTU(ciliumPeer, initMTU))

	// Mark the peer as Cilium-owned by adding the altname.
	require.NoError(t, netlink.LinkAddAltName(ciliumPeer, connector.CniAltName("test-cilium-p")))

	// Create a plain veth pair NOT owned by Cilium (simulates another CNI plugin).
	otherVeth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   "test-other-h",
			TxQLen: 1000,
		},
		PeerName:         "test-other-p",
		PeerHardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	require.NoError(t, netlink.LinkAdd(otherVeth))
	defer netlink.LinkDel(otherVeth)

	otherPeer, err := safenetlink.LinkByName("test-other-p")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetMTU(otherPeer, initMTU))
	// No altname set — this is not a Cilium interface.

	// Build a minimal RouteMTU list that defaultRouteHook will use.
	routeMTUs := []RouteMTU{
		{
			Prefix:    DefaultPrefixV4,
			DeviceMTU: newMTU,
			RouteMTU:  newMTU,
		},
	}

	// Run the hook.
	err = defaultRouteHook(routeMTUs)
	require.NoError(t, err)

	// The Cilium peer's MTU should have been updated.
	updatedCiliumPeer, err := safenetlink.LinkByName("test-cilium-p")
	require.NoError(t, err)
	require.Equal(t, newMTU, updatedCiliumPeer.Attrs().MTU,
		"expected Cilium-managed peer MTU to be updated to %d", newMTU)

	// The other CNI plugin's peer MTU should be unchanged.
	updatedOtherPeer, err := safenetlink.LinkByName("test-other-p")
	require.NoError(t, err)
	require.Equal(t, initMTU, updatedOtherPeer.Attrs().MTU,
		"expected non-Cilium peer MTU to remain at %d", initMTU)
}
