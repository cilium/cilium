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
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedDefaultRouteHookOnlyUpdatesCiliumLinks verifies that
// defaultRouteHook only updates the MTU of links with the CiliumCNIAltName
// altname, leaving other veth links untouched.
func TestPrivilegedDefaultRouteHookOnlyUpdatesCiliumLinks(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		newMTU  = 1400
		initMTU = 1500
	)

	routeMTUs := []RouteMTU{
		{
			Prefix:    DefaultPrefixV4,
			DeviceMTU: newMTU,
			RouteMTU:  newMTU,
		},
	}

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		// Create the Cilium-managed veth pair (with altname).
		ciliumVeth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: "cilium0",
				MTU:  initMTU,
			},
			PeerName: "cilium0peer",
		}
		require.NoError(t, netlink.LinkAdd(ciliumVeth))

		ciliumPeer, err := safenetlink.LinkByName("cilium0peer")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkAddAltName(ciliumPeer, connector.CniAltName("cilium0peer")))

		// Create a non-Cilium veth pair (without altname) — simulates Multus.
		otherVeth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: "other0",
				MTU:  initMTU,
			},
			PeerName: "other0peer",
		}
		require.NoError(t, netlink.LinkAdd(otherVeth))

		// Add a default IPv4 route on the Cilium-managed peer so the hook
		// has a route to update.
		require.NoError(t, netlink.LinkSetUp(ciliumPeer))
		require.NoError(t, netlink.RouteAdd(&netlink.Route{
			LinkIndex: ciliumPeer.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Family:    netlink.FAMILY_V4,
		}))

		// Run the hook.
		require.NoError(t, defaultRouteHook(routeMTUs))

		// Re-query MTUs.
		updatedCiliumPeer, err := safenetlink.LinkByName("cilium0peer")
		require.NoError(t, err)
		updatedOtherPeer, err := safenetlink.LinkByName("other0peer")
		require.NoError(t, err)

		require.Equal(t, newMTU, updatedCiliumPeer.Attrs().MTU,
			"cilium0peer MTU should have been updated by defaultRouteHook")
		require.Equal(t, initMTU, updatedOtherPeer.Attrs().MTU,
			"other0peer MTU should not have been changed by defaultRouteHook")

		return nil
	}))
}
