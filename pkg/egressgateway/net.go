// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

var zeroIPv4Net = &net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)}

func getIfaceFirstIPv4Address(ifaceName string) (net.IPNet, int, error) {
	dev, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return net.IPNet{}, 0, err
	}

	addrs, err := netlink.AddrList(dev, netlink.FAMILY_V4)
	if err != nil {
		return net.IPNet{}, 0, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			return *addr.IPNet, dev.Attrs().Index, nil
		}
	}

	return net.IPNet{}, 0, fmt.Errorf("no IPv4 address assigned to interface")
}

func getIfaceWithIPv4Address(ip net.IP) (string, int, net.IPMask, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", 0, nil, err
	}

	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return "", 0, nil, err
		}

		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return l.Attrs().Name, l.Attrs().Index, addr.Mask, nil
			}
		}
	}

	return "", 0, nil, fmt.Errorf("no interface with %s IPv4 assigned to", ip)
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

	return listFilteredEgressIpRules(&filter)
}

func listEgressIpRulesForRoutingTable(RoutingTableIdx int) ([]netlink.Rule, error) {
	filter := route.Rule{
		Priority: linux_defaults.RulePriorityEgressGateway,
		Table:    RoutingTableIdx,
	}

	return listFilteredEgressIpRules(&filter)
}

func listFilteredEgressIpRules(filter *route.Rule) ([]netlink.Rule, error) {
	rules, err := route.ListRules(netlink.FAMILY_V4, filter)
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

func newEgressIpRule(endpointIP net.IP, dstCIDR *net.IPNet, routingTableIdx int) *netlink.Rule {
	rule := netlink.NewRule()

	rule.Family = netlink.FAMILY_V4
	rule.Table = routingTableIdx
	rule.Priority = linux_defaults.RulePriorityEgressGateway
	rule.Src = &net.IPNet{IP: endpointIP, Mask: net.CIDRMask(32, 32)}
	rule.Dst = dstCIDR
	rule.Protocol = linux_defaults.RTProto

	return rule
}

func egressIPRuleMatches(ipRule *netlink.Rule, endpointIP net.IP, dstCIDR *net.IPNet) bool {
	ipRuleMaskSize, _ := ipRule.Dst.Mask.Size()
	dstCIDRMaskSize, _ := dstCIDR.Mask.Size()

	// We already filtered for .Family, .Priority and .Table
	return ipRule.Src.IP.Equal(endpointIP) &&
		ipRuleMaskSize == dstCIDRMaskSize &&
		ipRule.Dst.IP.Equal(dstCIDR.IP)
}

func getFirstIPInHostRange(ip net.IPNet) net.IP {
	out := make(net.IP, net.IPv4len)
	copy(out, ip.IP.To4())
	out = out.Mask(ip.Mask)
	out[3] += 1

	return out
}

func addEgressIpRoutes(gwc *gatewayConfig) error {
	routingTableIdx := egressGatewayRoutingTableIdx(gwc.ifaceIndex)

	// The gateway for a subnet and VPC should always be the first IP of the
	// host address range.
	eniGatewayIP := getFirstIPInHostRange(gwc.egressIP)

	IpRoute := route.Route{
		Prefix:  net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Nexthop: &eniGatewayIP,
		Device:  gwc.ifaceName,
		Proto:   linux_defaults.RTProto,
		Table:   routingTableIdx,
	}

	return route.Upsert(IpRoute)
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

func deleteIpRoute(ipRoute netlink.Route) {
	logger := log.WithFields(logrus.Fields{})

	logger.Debug("Removing IP route")

	netlink.RouteDel(&ipRoute)
}
