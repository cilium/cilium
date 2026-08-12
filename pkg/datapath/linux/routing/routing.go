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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// useCompatEgressPriority determines whether to use the new or old style egress rule.
func (info *RoutingInfo) useCompatEgressPriority() bool {
	return info.compatEgressPriority
}

// Configure sets up the rules and routes that direct egress traffic out of the
// interface and ingress traffic back to the endpoint (ip).
//
// ip: The endpoint IP address to direct traffic out / from interface.
// info: The interface routing info used to create rules and routes.
// host: Whether the IP is a host IP and needs to be routed via the 'local' table
func (info *RoutingInfo) Configure(ip netip.Addr, host bool) error {
	if !ip.IsValid() {
		return fmt.Errorf("unable to install endpoint rules: invalid endpoint IP address %s", ip)
	}

	ifindex, err := info.prepareInterface()
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	ipWithMask := netipx.AddrIPNet(ip)

	var replaceRule func(route.Rule) error
	if ip.Is4() {
		replaceRule = route.ReplaceRule
	} else {
		replaceRule = route.ReplaceRuleIPv6
	}

	// Ingress rule. This rule is not installed for the cilium_host IP, because
	// the cilium_host IP is a local IP and therefore must be routed via the
	// 'local' table instead of 'main'.
	if !host {
		// On ingress, route all traffic to the endpoint IP via the main routing
		// table. Egress rules are created in a per-ENI routing table.
		if err := replaceRule(route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       ipWithMask,
			Table:    route.MainTable,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %w", err)
		}
	}

	var egressPriority, ifaceNum, tableID int
	if info.useCompatEgressPriority() {
		egressPriority = linux_defaults.RulePriorityEgress
		ifaceNum = ifindex
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
		ifaceNum = info.InterfaceNumber
	}
	tableID = computeTableIDFromIfaceNumber(info.useCompatEgressPriority(), ifaceNum)

	// Install an unconditional rule so all traffic from the endpoint
	// (including external/internet traffic) is routed through the correct ENI.
	// A previous implementation scoped rules to the VPC CIDRs, which let
	// external traffic fall through to the default routing table and be routed
	// via the wrong interface, resulting in drops.
	// See https://github.com/cilium/cilium/issues/45137.
	if err := replaceRule(route.Rule{
		Priority: egressPriority,
		From:     ipWithMask,
		Table:    tableID,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %w", err)
	}

	return info.installRoutes(ifindex, tableID)
}

func (info *RoutingInfo) ReconcileGatewayRoutes(rx statedb.ReadTxn, routes statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	set := statedb.NewWatchSet()

	ifindex, err := info.prepareInterface()
	if err != nil {
		return set, fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	var ifaceNum, tableID int
	if info.useCompatEgressPriority() {
		ifaceNum = ifindex
	} else {
		ifaceNum = info.InterfaceNumber
	}
	tableID = computeTableIDFromIfaceNumber(info.useCompatEgressPriority(), ifaceNum)

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
	defaultIpv6Route := &netlink.Route{
		Dst:      &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Table:    tableID,
		Gw:       info.Gateway,
		Protocol: linux_defaults.RTProto,
	}

	// Only set LinkIndex for link-local gateways. The kernel needs the interface
	// index to route to link-local addresses since they're not tied to a specific
	// interface
	if info.Gateway.IsLinkLocalUnicast() {
		defaultIpv6Route.LinkIndex = ifindex
	}

	return []*netlink.Route{
		{
			LinkIndex: ifindex,
			Dst:       &net.IPNet{IP: info.Gateway, Mask: net.CIDRMask(128, 128)},
			Scope:     netlink.SCOPE_LINK,
			Table:     tableID,
			Protocol:  linux_defaults.RTProto,
		},
		defaultIpv6Route,
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
// they can be reused when another endpoint is created on the same node.
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
// one egress rule. Deletion only proceeds for unmarked Cilium rules matching
// the IP and one of the known priority/table schemes. Missing rules are treated
// as already deleted, and all matching rules are removed to avoid leaving stale
// rules.
func Delete(logger *slog.Logger, ip netip.Addr) error {
	if err := deleteEndpointRulesIfExists(logger, ip); err != nil {
		return err
	}

	if option.Config.EnableUnreachableRoutes {
		ipWithMask := netipx.AddrIPNet(ip)

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

// DeleteRulesIfExists removes Cilium endpoint routing rules for ip without
// installing an unreachable route. It is intended for rollback of a partially
// completed endpoint setup and for asynchronous rule reconciliation.
func DeleteRulesIfExists(logger *slog.Logger, ip netip.Addr) error {
	return deleteEndpointRulesIfExists(logger, ip)
}

func deleteEndpointRulesIfExists(logger *slog.Logger, ip netip.Addr) error {
	if !ip.IsValid() {
		logger.Warn(
			"Unable to delete rules because IP is not a valid IP address",
			logfields.IPAddr, ip,
		)
		return errors.New("IP not compatible")
	}

	family := netlink.FAMILY_V6
	if ip.Is4() {
		family = netlink.FAMILY_V4
	}
	ipWithMask := netipx.AddrIPNet(ip)

	var errs []error
	ingressRules, err := route.ListRules(family, &route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       ipWithMask,
		Table:    route.MainTable,
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("list ingress rules for %s: %w", ip, err))
	}

	for _, rule := range ingressRules {
		if !isCiliumEndpointIngressRule(rule) {
			continue
		}
		deleted, err := deleteRuleIfExists(&rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("delete ingress rule for %s: %w", ip, err))
			continue
		}
		if deleted {
			logger.Debug("Deleted endpoint ingress rule",
				logfields.Rule, rule,
				logfields.IPAddr, ip,
			)
		}
	}

	egressRules, err := route.ListRules(family, &route.Rule{
		From: ipWithMask,
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("list egress rules for %s: %w", ip, err))
	}
	for _, rule := range egressRules {
		if !isCiliumEndpointEgressRule(rule) {
			continue
		}
		deleted, err := deleteRuleIfExists(&rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("delete egress rule for %s: %w", ip, err))
			continue
		}
		if deleted {
			logger.Debug("Deleted endpoint egress rule",
				logfields.Rule, rule,
				logfields.IPAddr, ip,
			)
		}
	}

	return errors.Join(errs...)
}

// GCOrphanRules removes Cilium endpoint policy-routing rules left behind when
// endpoint teardown was missed or interrupted, for example by a CNI or agent
// crash. A recognized rule is removed only when shouldCollect confirms that
// its endpoint address is no longer in use.
func GCOrphanRules(logger *slog.Logger, shouldCollect func(netip.Addr) bool) error {
	var errs []error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := route.ListRules(family, nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for _, rule := range rules {
			var network *net.IPNet

			switch {
			// Cilium endpoint ingress rules in the main table.
			case isCiliumEndpointIngressRule(rule):
				network = rule.Dst
			// Cilium endpoint egress rules from current and legacy schemes.
			case isCiliumEndpointEgressRule(rule):
				network = rule.Src
			}
			if network == nil {
				continue
			}

			prefix, ok := netipx.FromStdIPNet(network)
			// Endpoint rules select one pod IP; preserve subnet-wide prefixes.
			if !ok || prefix.Bits() != prefix.Addr().BitLen() {
				continue
			}
			addr := prefix.Addr()

			if shouldCollect != nil && !shouldCollect(addr) {
				continue
			}

			deleted, err := deleteRuleIfExists(&rule)
			if err != nil {
				errs = append(errs, fmt.Errorf("delete orphan rule for %s: %w", addr, err))
				continue
			}

			if deleted {
				logger.Info("Deleted orphan endpoint routing rule",
					logfields.Rule, rule,
					logfields.IPAddr, addr,
				)
			}
		}
	}
	return errors.Join(errs...)
}

func isCiliumEndpointIngressRule(rule netlink.Rule) bool {
	return rule.Dst != nil &&
		rule.Priority == linux_defaults.RulePriorityIngress &&
		rule.Table == route.MainTable &&
		rule.Mark == 0 &&
		rule.Mask == nil &&
		rule.Protocol == linux_defaults.RTProto
}

func isCiliumEndpointEgressRule(rule netlink.Rule) bool {
	// Endpoint egress rules are unmarked Cilium-owned source rules.
	if rule.Src == nil ||
		rule.Protocol != linux_defaults.RTProto ||
		rule.Mark != 0 ||
		rule.Mask != nil {
		return false
	}

	switch rule.Priority {
	case linux_defaults.RulePriorityEgress:
		// Legacy rules and current Azure rules may use any non-reserved table.
		return isNonReservedTable(rule.Table)
	case linux_defaults.RulePriorityEgressv2:
		// Current ENI and AlibabaCloud rules use Cilium's interface-number table range.
		return isCiliumInterfaceRouteTable(rule.Table)
	default:
		return false
	}
}

func deleteRuleIfExists(rule *netlink.Rule) (bool, error) {
	err := netlink.RuleDel(rule)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ESRCH):
		return false, nil
	default:
		return false, err
	}
}

func isCiliumInterfaceRouteTable(table int) bool {
	return table >= computeTableIDFromIfaceNumber(false, 0) && table < unix.RT_TABLE_DEFAULT
}

func isNonReservedTable(table int) bool {
	switch table {
	case unix.RT_TABLE_UNSPEC, unix.RT_TABLE_DEFAULT, unix.RT_TABLE_MAIN, unix.RT_TABLE_LOCAL:
		return false
	default:
		return true
	}
}

// retrieveLinkFromMAC finds the corresponding device for a MAC address,
// excluding Linux slave devices.
func retrieveLinkFromMAC(mac mac.MAC) (netlink.Link, error) {
	var link netlink.Link

	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, l := range links {
		// Linux slave devices have the same MAC address as their master
		// device, but we want the master device.
		if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
			continue
		}
		if l.Attrs().HardwareAddr.String() == mac.String() {
			if link != nil {
				return nil, fmt.Errorf("several interfaces found with MAC %s: %s and %s", mac, link.Attrs().Name, l.Attrs().Name)
			}
			link = l
		}
	}

	if link == nil {
		return nil, fmt.Errorf("interface with MAC %s not found", mac)
	}
	return link, nil
}

// prepareInterface resolves the interface and applies any explicitly requested
// link configuration.
func (info *RoutingInfo) prepareInterface() (int, error) {
	link, err := retrieveLinkFromMAC(info.MasterIfMAC)
	if err != nil {
		return -1, err
	}

	if info.mtu != nil {
		if err = netlink.LinkSetMTU(link, *info.mtu); err != nil {
			return -1, fmt.Errorf("unable to change MTU of link %s to %d: %w", link.Attrs().Name, *info.mtu, err)
		}
	}
	if info.linkState != nil {
		if *info.linkState {
			err = netlink.LinkSetUp(link)
		} else {
			err = netlink.LinkSetDown(link)
		}
		if err != nil {
			return -1, fmt.Errorf("unable to set link %s up state to %t: %w", link.Attrs().Name, *info.linkState, err)
		}
	}

	return link.Attrs().Index, nil
}

// computeTableIDFromIfaceNumber returns a computed per-interface route table
// ID for the given routing interface number.
func computeTableIDFromIfaceNumber(compat bool, num int) int {
	if compat {
		return num
	}
	return linux_defaults.RouteTableInterfacesOffset + num
}
