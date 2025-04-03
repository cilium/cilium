// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// Configure sets up the rules and routes needed when running in ENI or
// Azure IPAM mode.
// These rules and routes direct egress traffic out of the interface and
// ingress traffic back to the endpoint (`ip`). The compat flag controls which
// egress priority to consider when deleting the egress rules (see
// option.Config.EgressMultiHomeIPRuleCompat).
//
// ip: The endpoint IP address to direct traffic out / from interface.
// info: The interface routing info used to create rules and routes.
// mtu: The interface MTU.
// compat: Whether to use the compat egress priority or not.
// host: Whether the IP is a host IP and needs to be routed via the 'local' table
func (info *RoutingInfo) Configure(ip net.IP, mtu int, compat bool, host bool) error {
	if ip == nil || (ip.To4() == nil && ip.To16() == nil) {
		info.logger.Warn(
			"Unable to configure rules and routes because IP is not a valid IP address",
			logfields.IPAddr, ip,
		)
		return errors.New("IP not compatible")
	}

	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	var ipWithMask net.IPNet
	var replaceRule func(route.Rule) error

	if ip.To4() != nil {
		replaceRule = route.ReplaceRule
		ipWithMask = net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	} else {
		replaceRule = route.ReplaceRuleIPv6
		ipWithMask = net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		}
	}

	// Ingress rule. This rule is not installed for the cilium_host IP, because
	// the cilium_host IP is a local IP and therefore must be routed via the
	// 'local' table instead of 'main'.
	if !host {
		// On ingress, route all traffic to the endpoint IP via the main routing
		// table. Egress rules are created in a per-ENI routing table.
		if err := replaceRule(route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       &ipWithMask,
			Table:    route.MainTable,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %w", err)
		}
	}

	var egressPriority, tableID int
	if compat {
		egressPriority = linux_defaults.RulePriorityEgress
		tableID = ifindex
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
		tableID = computeTableIDFromIfaceNumber(info.InterfaceNumber)
	}

	// The condition here should mirror the condition in Delete.
	if info.Masquerade && info.IpamMode == ipamOption.IPAMENI {
		// Lookup a VPC specific table for all traffic from an endpoint to the
		// CIDR configured for the VPC on which the endpoint has the IP on.
		// ReplaceRule function doesn't handle all zeros cidr and return `file exists` error,
		// so we need to normalize the rule to cidr here and in Delete
		for _, cidr := range info.CIDRs {
			if err := replaceRule(route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				To:       normalizeRuleToCIDR(&cidr),
				Table:    tableID,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %w", err)
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		if err := replaceRule(route.Rule{
			Priority: egressPriority,
			From:     &ipWithMask,
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %w", err)
		}
	}

	return info.installRoutes(ifindex, tableID)
}

func (info *RoutingInfo) ReconcileGatewayRoutes(mtu int, compat bool, rx statedb.ReadTxn, routes statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	set := statedb.NewWatchSet()

	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return set, fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	var tableID int
	if compat {
		tableID = ifindex
	} else {
		tableID = computeTableIDFromIfaceNumber(info.InterfaceNumber)
	}

	// Get the desired routes.
	gwRoutes := info.gatewayRoutes(ifindex, tableID)
	for _, r := range gwRoutes {
		// See if they already exist.
		cidr, _ := r.Dst.Mask.Size()
		_, _, watch, found := routes.GetWatch(rx, tables.RouteIDIndex.Query(tables.RouteID{
			Table:     tables.RouteTable(r.Table),
			LinkIndex: r.LinkIndex,
			Dst:       netip.PrefixFrom(netipx.MustFromStdIP(r.Dst.IP), cidr),
		}))

		if found {
			// If a route already exist, just add it to the watch
			set.Add(watch)
		} else {
			// Since we cannot watch a non-existent route, we need to watch the
			// table instead.
			_, watch = routes.AllWatch(rx)
			set.Add(watch)

			// If the route doesn't exist, add it.
			if err := netlink.RouteReplace(r); err != nil {
				return set, fmt.Errorf("unable to add L2 nexthop route: %w", err)
			}
		}
	}

	return set, nil
}

func (info *RoutingInfo) gatewayRoutes(ifindex, tableID int) []*netlink.Route {
	if info.Gateway.To4() != nil {
		return []*netlink.Route{
			// Nexthop route to the VPC or subnet gateway
			//
			// Note: This is a /32 route to avoid any L2. The endpoint does no L2
			// either.
			{
				LinkIndex: ifindex,
				Dst:       &net.IPNet{IP: info.Gateway, Mask: net.CIDRMask(32, 32)},
				Scope:     netlink.SCOPE_LINK,
				Table:     tableID,
				Protocol:  linux_defaults.RTProto,
			},

			// Default route to the VPC or subnet gateway
			{
				Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Table:    tableID,
				Gw:       info.Gateway,
				Protocol: linux_defaults.RTProto,
			},
		}
	}

	// IPv6 routes
	return []*netlink.Route{
		{
			LinkIndex: ifindex,
			Dst:       &net.IPNet{IP: info.Gateway, Mask: net.CIDRMask(128, 128)},
			Scope:     netlink.SCOPE_LINK,
			Table:     tableID,
			Protocol:  linux_defaults.RTProto,
		},

		{
			Dst:      &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:    tableID,
			Gw:       info.Gateway,
			Protocol: linux_defaults.RTProto,
		},
	}

}

func (info *RoutingInfo) installRoutes(ifindex, tableID int) error {
	routes := info.gatewayRoutes(ifindex, tableID)

	for _, r := range routes {
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("unable to add L2 nexthop route: %w", err)
		}
	}

	return nil
}

// Delete removes the ingress and egress rules that control traffic for
// endpoints. Note that the routes referenced by the rules are not deleted as
// they can be reused when another endpoint is created on the same node. The
// compat flag controls which egress priority to consider when deleting the
// egress rules (see option.Config.EgressMultiHomeIPRuleCompat).
//
// Note that one or more IPs may share the same route table, as identified by
// the interface number of the corresponding device. This function only removes
// the ingress and egress rules to disconnect the per-ENI egress routes from a
// specific local IP, and does not remove the corresponding route table as
// other IPs may still be using that table.
//
// The search for both the ingress & egress rule corresponding to this IP is a
// best-effort based on the respective priority that Cilium uses, which we
// assume full control over. The search for the ingress rule is more likely to
// succeed (albeit very rarely that egress deletion fails) because we are able
// to perform a narrower search on the rule because we know it references the
// main routing table. Due to multiple routing CIDRs, there might be more than
// one egress rule. Deletion of any rule only proceeds if the rule matches
// the IP & priority. If more than one rule matches, then deletion is skipped.
func Delete(logger *slog.Logger, ip netip.Addr, compat bool) error {
	if !ip.Is4() && !ip.Is6() && !ip.IsValid() {
		logger.Warn(
			"Unable to delete rules because IP is not a valid IP address",
			logfields.IPAddr, ip,
		)
		return errors.New("IP not compatible")
	}

	ipWithMask := netipx.AddrIPNet(ip)
	var deleteRuleFn func(*slog.Logger, route.Rule) error

	if ip.Is4() {
		deleteRuleFn = deleteRuleIPv4
	} else {
		deleteRuleFn = deleteRuleIPv6
	}

	// Ingress rules
	ingress := route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       ipWithMask,
		Table:    route.MainTable,
	}

	if err := deleteRuleFn(logger, ingress); err != nil {
		return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %w", ipWithMask.String(), err)
	}
	logger.Debug("Deleted ingress rule",
		logfields.Rule, ingress,
		logfields.IPAddr, ipWithMask,
	)

	priority := linux_defaults.RulePriorityEgressv2
	if compat {
		priority = linux_defaults.RulePriorityEgress
	}

	// Egress rules
	// The condition here should mirror the conditions in Configure.
	info := node.GetRouterInfo()
	if info != nil && option.Config.EnableIPv4Masquerade && option.Config.IPAM == ipamOption.IPAMENI {
		ipCIDRs := info.GetCIDRs()
		cidrs := make([]*net.IPNet, 0, len(ipCIDRs))
		for i := range ipCIDRs {
			cidrs = append(cidrs, &ipCIDRs[i])
		}
		// Coalesce CIDRs into minimum set needed for route rules
		// This code here mirrors interfaceAdd() in cilium-cni/interface.go
		// and must be kept in sync when modified
		ipv4RoutingCIDRs, ipv6RoutingCIDRs := iputil.CoalesceCIDRs(cidrs)
		for _, cidr := range ipv4RoutingCIDRs {
			egress := route.Rule{
				Priority: priority,
				From:     ipWithMask,
				To:       normalizeRuleToCIDR(cidr),
			}
			if err := deleteRuleIPv4(logger, egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
			}
			logger.Debug("Deleted egress rule",
				logfields.Rule, egress,
				logfields.IPAddr, ipWithMask,
			)
		}
		for _, cidr := range ipv6RoutingCIDRs {
			egress := route.Rule{
				Priority: priority,
				From:     ipWithMask,
				To:       normalizeRuleToCIDR(cidr),
			}
			if err := deleteRuleIPv6(logger, egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
			}
			logger.Debug("Deleted egress rule",
				logfields.Rule, egress,
				logfields.IPAddr, ipWithMask,
			)
		}
	} else {
		egress := route.Rule{
			Priority: priority,
			From:     ipWithMask,
		}
		if err := deleteRuleFn(logger, egress); err != nil {
			return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
		}
		logger.Debug("Deleted egress rule",
			logfields.Rule, egress,
			logfields.IPAddr, ipWithMask,
		)
	}

	if option.Config.EnableUnreachableRoutes {
		// Replace route to old IP with an unreachable route. This will
		//   - trigger ICMP error messages for clients attempting to connect to the stale IP
		//   - avoid hitting rp_filter and getting Martian packet warning
		// When the IP is reused, the unreachable route will be replaced to target the new pod veth
		// In CRD-based IPAM, when an IP is unassigned from the CiliumNode, we delete this route
		// to avoid blackholing traffic to this IP if it gets reassigned to another node
		if err := netlink.RouteReplace(&netlink.Route{
			Dst:      ipWithMask,
			Table:    route.MainTable,
			Type:     unix.RTN_UNREACHABLE,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to add unreachable route for ip %s: %w", ipWithMask.String(), err)
		}
	}

	return nil
}

func deleteRuleIPv4(logger *slog.Logger, r route.Rule) error {
	return deleteRule(logger, r, netlink.FAMILY_V4)
}

func deleteRuleIPv6(logger *slog.Logger, r route.Rule) error {
	return deleteRule(logger, r, netlink.FAMILY_V6)
}

func deleteRule(logger *slog.Logger, r route.Rule, family int) error {
	rules, err := route.ListRules(family, &r)
	if err != nil {
		return err
	}

	length := len(rules)
	switch {
	case length > 1:
		logger.Warn(
			"Found too many rules matching, skipping deletion",
			logfields.Candidates, rules,
			logfields.Rule, r,
		)
		return errors.New("unexpected number of rules found to delete")
	case length == 1:
		return route.DeleteRule(family, r)
	}

	logger.Warn(
		"No rule matching found",
		logfields.Rule, r,
	)

	return errors.New("no rule found to delete")
}

// retrieveIfIndexFromMAC finds the corresponding device index (ifindex) for a
// given MAC address, excluding Linux slave devices. This is useful for
// creating rules and routes in order to specify the table. When the ifindex is
// found, the device is brought up and its MTU is set.
func retrieveIfIndexFromMAC(mac mac.MAC, mtu int) (int, error) {
	var link netlink.Link

	links, err := safenetlink.LinkList()
	if err != nil {
		return -1, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, l := range links {
		// Linux slave devices have the same MAC address as their master
		// device, but we want the master device.
		if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}
		if l.Attrs().HardwareAddr.String() == mac.String() {
			if link != nil {
				return -1, fmt.Errorf("several interfaces found with MAC %s: %s and %s", mac, link.Attrs().Name, l.Attrs().Name)
			}
			link = l
		}
	}

	if link == nil {
		return -1, fmt.Errorf("interface with MAC %s not found", mac)
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return -1, fmt.Errorf("unable to change MTU of link %s to %d: %w", link.Attrs().Name, mtu, err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return -1, fmt.Errorf("unable to up link %s: %w", link.Attrs().Name, err)
	}

	return link.Attrs().Index, nil
}

// computeTableIDFromIfaceNumber returns a computed per-ENI route table ID for the given
// ENI interface number.
func computeTableIDFromIfaceNumber(num int) int {
	return linux_defaults.RouteTableInterfacesOffset + num
}

// normalizeRuleToCIDR returns nil when passed cidr is zeroes only cidr
func normalizeRuleToCIDR(cidr *net.IPNet) *net.IPNet {
	if cidr.IP.IsUnspecified() {
		return nil
	}
	return cidr
}
