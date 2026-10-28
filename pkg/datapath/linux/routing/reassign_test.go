// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedReconcileAfterENIReassignment covers an endpoint IP that is
// reused on a different ENI of the same node while the egress rule of its
// previous owner was never deleted (missed CNI DEL, interrupted teardown). With
// ENI IPAM this happens when the operator releases an excess IP and later
// assigns it to another ENI of the same instance.
//
// Configure (the CNI path) is additive, so both rules coexist and the kernel
// keeps evaluating the older one first. Endpoint reconciliation must leave a
// single egress rule for the current ENI, and the endpoint's traffic must leave
// through that ENI.
func TestPrivilegedReconcileAfterENIReassignment(t *testing.T) {
	setupLinuxRoutingSuite(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		const gateway = "192.168.2.1"
		macA := mac.MustParseMAC("00:11:22:33:44:01")
		macB := mac.MustParseMAC("00:11:22:33:44:02")
		ip := netip.MustParseAddr("192.168.2.123")
		apiServer := net.ParseIP("10.96.0.1")

		eniA := createNamedDummyDevice(t, "eni-a", macA)
		eniB := createNamedDummyDevice(t, "eni-b", macB)

		infoA, err := NewRoutingInfo(gateway, macA, "1")
		require.NoError(t, err)
		infoB, err := NewRoutingInfo(gateway, macB, "2")
		require.NoError(t, err)

		tableA := linux_defaults.RouteTableInterfacesOffset + 1
		tableB := linux_defaults.RouteTableInterfacesOffset + 2

		egressTables := func() []int {
			rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
				Priority: linux_defaults.RulePriorityEgressv2,
				From:     netipx.AddrIPNet(ip),
			})
			require.NoError(t, err)
			tables := make([]int, 0, len(rules))
			for _, r := range rules {
				tables = append(tables, r.Table)
			}
			return tables
		}
		egressLink := func() int {
			routes, err := netlink.RouteGetWithOptions(apiServer, &netlink.RouteGetOptions{
				SrcAddr: ip.AsSlice(),
				Iif:     "lo",
			})
			require.NoError(t, err)
			require.Len(t, routes, 1)
			return routes[0].LinkIndex
		}

		// Previous owner of the IP on ENI A. Its teardown never runs.
		require.NoError(t, infoA.Configure(ip, false))

		// The IP comes back on ENI B and a new endpoint is configured with it.
		require.NoError(t, infoB.Configure(ip, false))
		require.Equal(t, []int{tableA, tableB}, egressTables(),
			"the additive CNI path leaves the stale rule in place")
		require.Equal(t, eniA.Attrs().Index, egressLink(),
			"before reconciliation the stale rule wins")

		// Endpoint reconciliation removes the stale rule.
		require.NoError(t, infoB.ReconcileEndpointRules(ip, false))
		require.Equal(t, []int{tableB}, egressTables())
		require.Equal(t, eniB.Attrs().Index, egressLink(),
			"traffic from %s must leave via %s", ip, eniB.Attrs().Name)

		// Reconciliation is idempotent.
		require.NoError(t, infoB.ReconcileEndpointRules(ip, false))
		require.Equal(t, []int{tableB}, egressTables())
		return nil
	})
}

func createNamedDummyDevice(t *testing.T, name string, hw mac.MAC) netlink.Link {
	t.Helper()
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, HardwareAddr: hw.HardwareAddr()}}
	require.NoError(t, netlink.LinkAdd(dummy))
	link, err := safenetlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(link))
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	return link
}
