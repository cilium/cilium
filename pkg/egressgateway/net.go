// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

var zeroIPv4Net = &net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)}

func getIfaceFirstIPv4Address(ifaceName string) (netip.Prefix, int, error) {
	dev, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return netip.Prefix{}, 0, err
	}

	addrs, err := netlink.AddrList(dev, netlink.FAMILY_V4)
	if err != nil {
		return netip.Prefix{}, 0, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			if prefix, ok := netipx.FromStdIPNet(addr.IPNet); ok {
				return prefix, dev.Attrs().Index, nil
			}
		}
	}

	return netip.Prefix{}, 0, fmt.Errorf("no IPv4 address assigned to interface")
}

func getIfaceWithIPv4Address(ip netip.Addr) (string, int, netip.Prefix, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", 0, netip.Prefix{}, err
	}

	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return "", 0, netip.Prefix{}, err
		}

		for _, addr := range addrs {
			if addr.IP.Equal(ip.AsSlice()) {
				if prefix, ok := netipx.FromStdIPNet(addr.IPNet); ok {
					return l.Attrs().Name, l.Attrs().Index, prefix, nil
				}
			}
		}
	}

	return "", 0, netip.Prefix{}, fmt.Errorf("no interface with %s IPv4 assigned to", ip)
}

// egressGatewayRoutingTableIdx returns the index of the routing table that
// should be used to install the egress gateway routing rules for a given
// interface
func egressGatewayRoutingTableIdx(ifaceIdx int) int {
	return linux_defaults.RouteTableEgressGatewayInterfacesOffset + ifaceIdx
}

// listEgressIpRules returns a slice with all the IP rules installed by egress
// gateway.
//
// Moreover, since the netlink library will report all 0.0.0.0/0 destinations as
// nil, this function will rewrite them to the 0.0.0.0/0 net.IPNet object to
// simplify the comparison with other IPNet objects
func listEgressIpRules() ([]netlink.Rule, error) {
	filter := route.Rule{
		Priority: linux_defaults.RulePriorityEgressGateway,
	}

	rules, err := route.ListRules(netlink.FAMILY_V4, &filter)
	if err != nil {
		return nil, err
	}

	for i := range rules {
		if rules[i].Dst == nil {
			rules[i].Dst = zeroIPv4Net
		}
	}

	return rules, nil
}

func addEgressIpRule(endpointIP netip.Addr, dstCIDR netip.Prefix, egressIP netip.Addr, ifaceIndex int) error {
	routingTableIdx := egressGatewayRoutingTableIdx(ifaceIndex)

	ipRule := route.Rule{
		Priority: linux_defaults.RulePriorityEgressGateway,
		From:     &net.IPNet{IP: endpointIP.AsSlice(), Mask: net.CIDRMask(32, 32)},
		To:       netipx.PrefixIPNet(dstCIDR),
		Table:    routingTableIdx,
		Protocol: linux_defaults.RTProto,
	}

	return route.ReplaceRule(ipRule)
}

func getFirstIPInHostRange(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid prefix %v", prefix)
	}

	if prefix.IsSingleIP() {
		return prefix.Addr(), nil
	}

	nextIP := prefix.Addr().Next()
	// If no addresses are available, the zero address is returned.
	if nextIP.Compare(GatewayNotFoundIPv4) == 0 {
		return netip.Addr{}, fmt.Errorf("no available IPs for prefix %v", prefix)
	}

	return nextIP, nil
}

func addEgressIpRoutes(egressIP netip.Prefix, ifaceIndex int) error {
	routingTableIdx := egressGatewayRoutingTableIdx(ifaceIndex)

	// The gateway for a subnet and VPC should always be the first IP of the
	// host address range.
	eniGatewayIP, err := getFirstIPInHostRange(egressIP)
	if err != nil {
		return fmt.Errorf("unable to get first IP from egress prefix %v: %w", egressIP, err)
	}

	// Nexthop route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: ifaceIndex,
		Dst:       &net.IPNet{IP: eniGatewayIP.AsSlice(), Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     routingTableIdx,
		Protocol:  linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %w", err)
	}

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: ifaceIndex,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:     routingTableIdx,
		Gw:        eniGatewayIP.AsSlice(),
		Protocol:  linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %w", err)
	}

	return nil
}

func deleteIpRule(ipRule netlink.Rule) {
	logger := log.WithFields(logrus.Fields{})

	logger.Debug("Removing IP rule")
	route.DeleteRule(netlink.FAMILY_V4,
		route.Rule{
			Priority: linux_defaults.RulePriorityEgressGateway,
			From:     ipRule.Src,
			To:       ipRule.Dst,
			Table:    ipRule.Table,
			Protocol: linux_defaults.RTProto,
		})
}

func deleteIpRouteTable(tableIndex int) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: tableIndex}, uint64(netlink.RT_FILTER_TABLE))
	if err != nil {
		log.WithError(err).Error("Cannot list IP routes")
		return
	}

	for _, route := range routes {
		deleteIpRoute(route)
	}
}

func deleteIpRoute(ipRoute netlink.Route) {
	logger := log.WithFields(logrus.Fields{})

	logger.Debug("Removing IP route")

	netlink.RouteDel(&ipRoute)
}
