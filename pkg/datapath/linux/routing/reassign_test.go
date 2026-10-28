// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedConfigureAfterENIReassignment covers an endpoint IP that is
// reused on a different interface of the same node while the egress rules of
// its previous owner were never deleted (missed CNI DEL, interrupted teardown).
// With ENI IPAM this happens when the operator releases an excess IP and later
// assigns it to another ENI of the same instance.
//
// The new endpoint must end up with egress rules for its current interface
// only. Otherwise the kernel keeps evaluating the older rules first (same
// priority, inserted earlier), and the endpoint's traffic leaves through an
// interface that does not own the source IP.
func TestPrivilegedConfigureAfterENIReassignment(t *testing.T) {
	setupLinuxRoutingSuite(t)

	const gateway = "192.168.2.1"
	vpcCIDRs := []string{"192.168.0.0/16", "192.170.0.0/16"}

	type config struct {
		ipamMode   string
		masquerade bool
		cidrs      []string
	}
	for _, tc := range []struct {
		name string
		// previous configures the stale owner on the first interface, current
		// the new owner on the second one.
		previous, current config
		// dst is a destination the endpoint's egress rules select.
		dst string
		// wantRules is the number of egress rules expected for the endpoint.
		wantRules int
	}{
		{
			name:      "eni",
			previous:  config{ipamOption.IPAMENI, false, nil},
			current:   config{ipamOption.IPAMENI, false, nil},
			dst:       "10.96.0.1",
			wantRules: 1,
		},
		{
			name:      "eni-masquerade",
			previous:  config{ipamOption.IPAMENI, true, vpcCIDRs},
			current:   config{ipamOption.IPAMENI, true, vpcCIDRs},
			dst:       "192.170.0.10",
			wantRules: 2,
		},
		{
			name:      "eni-masquerade-zero-cidr",
			previous:  config{ipamOption.IPAMENI, true, []string{"0.0.0.0/0"}},
			current:   config{ipamOption.IPAMENI, true, []string{"0.0.0.0/0"}},
			dst:       "10.96.0.1",
			wantRules: 1,
		},
		{
			name:      "azure-masquerade",
			previous:  config{ipamOption.IPAMAzure, true, vpcCIDRs},
			current:   config{ipamOption.IPAMAzure, true, vpcCIDRs},
			dst:       "192.170.0.10",
			wantRules: 2,
		},
		{
			name:      "eni-previous-catch-all-now-masquerade",
			previous:  config{ipamOption.IPAMENI, false, nil},
			current:   config{ipamOption.IPAMENI, true, vpcCIDRs},
			dst:       "192.170.0.10",
			wantRules: 2,
		},
		{
			name:      "eni-previous-masquerade-now-catch-all",
			previous:  config{ipamOption.IPAMENI, true, vpcCIDRs},
			current:   config{ipamOption.IPAMENI, false, nil},
			dst:       "192.170.0.10",
			wantRules: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := netns.NewNetNS(t)
			ns.Do(func() error {
				logger := hivetest.Logger(t)
				ip := netip.MustParseAddr("192.168.2.123")

				ifaceA := createNamedDummyDevice(t, "iface-a", "00:11:22:33:44:01")
				ifaceB := createNamedDummyDevice(t, "iface-b", "00:11:22:33:44:02")

				infoA, err := NewRoutingInfo(logger, gateway, tc.previous.cidrs, "00:11:22:33:44:01", "1",
					tc.previous.ipamMode, tc.previous.masquerade)
				require.NoError(t, err)
				infoB, err := NewRoutingInfo(logger, gateway, tc.current.cidrs, "00:11:22:33:44:02", "2",
					tc.current.ipamMode, tc.current.masquerade)
				require.NoError(t, err)

				// Previous owner of the IP on the first interface. Its teardown
				// never runs.
				require.NoError(t, infoA.Configure(ip.AsSlice(), 1500, false))

				// The IP comes back on the second interface and a new endpoint
				// is configured with it.
				require.NoError(t, infoB.Configure(ip.AsSlice(), 1500, false))

				egressPriority := linux_defaults.RulePriorityEgressv2
				wantTable := linux_defaults.RouteTableInterfacesOffset + 2
				if infoB.useCompatEgressPriority() {
					egressPriority = linux_defaults.RulePriorityEgress
					wantTable = ifaceB.Attrs().Index
				}

				var tables []int
				for _, priority := range []int{linux_defaults.RulePriorityEgress, linux_defaults.RulePriorityEgressv2} {
					rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
						Priority: priority,
						From:     netipx.AddrIPNet(ip),
					})
					require.NoError(t, err)
					for _, r := range rules {
						require.Equal(t, egressPriority, r.Priority, "unexpected egress rule %s", r)
						tables = append(tables, r.Table)
					}
				}
				require.Len(t, tables, tc.wantRules, "egress rules for %s: tables %v", ip, tables)
				require.Equal(t, []int{wantTable}, slices.Compact(slices.Sorted(slices.Values(tables))),
					"egress rules must point at the current interface's table only")

				// The kernel must route the endpoint's traffic out of its
				// current interface.
				routes, err := netlink.RouteGetWithOptions(net.ParseIP(tc.dst), &netlink.RouteGetOptions{
					SrcAddr: ip.AsSlice(),
					Iif:     "lo",
				})
				require.NoError(t, err)
				require.Len(t, routes, 1)
				require.Equal(t, ifaceB.Attrs().Index, routes[0].LinkIndex,
					"traffic from %s to %s must leave via %s, not %s", ip, tc.dst, ifaceB.Attrs().Name, ifaceA.Attrs().Name)
				return nil
			})
		})
	}
}

func createNamedDummyDevice(t *testing.T, name, macAddr string) netlink.Link {
	t.Helper()
	hw, err := net.ParseMAC(macAddr)
	require.NoError(t, err)
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, HardwareAddr: hw}}
	require.NoError(t, netlink.LinkAdd(dummy))
	link, err := safenetlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(link))
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	return link
}
