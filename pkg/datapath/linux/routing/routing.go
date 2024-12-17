// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "linux-routing")
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
func (info *RoutingInfo) Configure(ip, ipv6 net.IP, mtu int, compat bool, host bool) error {
	ipv4Enabled := ip != nil
	ipv6Enabled := ipv6 != nil
	if ipv4Enabled && ip.To4() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to configure rules and routes because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}
	if ipv6Enabled && ipv6.To16() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ipv6,
		}).Warning("Unable to configure rules and routes because IP is not an IPv6 address")
		return errors.New("IPv6 not compatible")
	}

	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	var ipWithMask, ipv6WithMask net.IPNet
	if ipv4Enabled {
		ipWithMask = net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}
	if ipv6Enabled {
		ipv6WithMask = net.IPNet{
			IP:   ipv6,
			Mask: net.CIDRMask(128, 128),
		}
	}

	// Ingress rule. This rule is not installed for the cilium_host IP, because
	// the cilium_host IP is a local IP and therefore must be routed via the
	// 'local' table instead of 'main'.
	if !host {
		// On ingress, route all traffic to the endpoint IP via the main routing
		// table. Egress rules are created in a per-ENI routing table.
		if ipv4Enabled {
			if err := route.ReplaceRule(route.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				To:       &ipWithMask,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %w", err)
			}
		}
		if ipv6Enabled {
			if err := route.ReplaceRuleIPv6(route.Rule{
				Priority: linux_defaults.RulePriorityIngress,
				To:       &ipv6WithMask,
				Table:    route.MainTable,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %w", err)
			}
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
		if ipv4Enabled {
			for _, cidr := range info.IPv4CIDRs {
				if err := route.ReplaceRule(route.Rule{
					Priority: egressPriority,
					From:     &ipWithMask,
					To:       normalizeRuleToCIDR(&cidr),
					Table:    tableID,
					Protocol: linux_defaults.RTProto,
				}); err != nil {
					return fmt.Errorf("unable to install ip rule: %w", err)
				}
			}
		}
		if ipv6Enabled {
			for _, cidr := range info.IPv6CIDRs {
				if err := route.ReplaceRuleIPv6(route.Rule{
					Priority: egressPriority,
					From:     &ipv6WithMask,
					To:       normalizeRuleToCIDR(&cidr),
					Table:    tableID,
					Protocol: linux_defaults.RTProto,
				}); err != nil {
					return fmt.Errorf("unable to install ip rule: %w", err)
				}
			}
		}

	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		if ipv4Enabled {
			if err := route.ReplaceRule(route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				Table:    tableID,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %w", err)
			}
		}
		if ipv6Enabled {
			if err := route.ReplaceRuleIPv6(route.Rule{
				Priority: egressPriority,
				From:     &ipv6WithMask,
				Table:    tableID,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %w", err)
			}
		}
	}

	// Nexthop route to the VPC or subnet gateway
	//
	// Note: This is a /32 route to avoid any L2. The endpoint does no L2
	// either.
	if ipv4Enabled {
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: ifindex,
			Dst:       &net.IPNet{IP: info.IPv4Gateway, Mask: net.CIDRMask(32, 32)},
			Scope:     netlink.SCOPE_LINK,
			Table:     tableID,
			Protocol:  linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to add L2 nexthop route: %w", err)
		}
	}
	if ipv6Enabled {
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: ifindex,
			Dst:       &net.IPNet{IP: info.IPv6Gateway, Mask: net.CIDRMask(128, 128)},
			Scope:     netlink.SCOPE_LINK,
			Table:     tableID,
			Protocol:  linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to add L2 nexthop route: %w", err)
		}
	}

	// Default route to the VPC or subnet gateway
	if ipv4Enabled {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Table:    tableID,
			Gw:       info.IPv4Gateway,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to add L2 nexthop route: %w", err)
		}
	}
	if ipv6Enabled {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst:      &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:    tableID,
			Gw:       info.IPv6Gateway,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
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
func Delete(ip, ipv6 netip.Addr, compat bool) error {
	ipv4Enabled := ip.IsValid() && ip.Is4()
	ipv6Enabled := ip.IsValid()
	if ipv4Enabled && !ip.Is4() {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to delete rules because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}
	if ipv6Enabled && !ipv6.Is6() {
		log.WithFields(logrus.Fields{
			"endpointIP": ipv6,
		}).Warning("Unable to delete rules because IP is not an IPv6 address")
		return errors.New("IPv6 not compatible")
	}

	var ipWithMask, ipv6WithMask *net.IPNet
	if ipv4Enabled {
		ipWithMask = netipx.AddrIPNet(ip)
	}
	if ipv6Enabled {
		ipv6WithMask = netipx.AddrIPNet(ipv6)
	}

	scopedLog := log.WithFields(logrus.Fields{
		"ip":   ipWithMask.String(),
		"ipv6": ipv6WithMask.String(),
	})

	// Ingress rules
	if ipv4Enabled {
		ingress := route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       ipWithMask,
			Table:    route.MainTable,
		}
		if err := deleteRuleIPv4(ingress); err != nil {
			return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %w", ipWithMask.String(), err)
		}
		scopedLog.WithField("rule", ingress).Debug("Deleted ingress rule")
	}
	if ipv6Enabled {
		ingress := route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       ipv6WithMask,
			Table:    route.MainTable,
		}
		if err := deleteRuleIPv6(ingress); err != nil {
			return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %w", ipv6WithMask.String(), err)
		}
		scopedLog.WithField("rule", ingress).Debug("Deleted ingress rule")
	}

	priority := linux_defaults.RulePriorityEgressv2
	if compat {
		priority = linux_defaults.RulePriorityEgress
	}

	// Egress rules
	// The condition here should mirror the conditions in Configure.
	info := node.GetRouterInfo()
	if info != nil && option.Config.EnableIPv4Masquerade && option.Config.IPAM == ipamOption.IPAMENI {
		ipv4CIDRs := info.GetIPv4CIDRs()
		ipv6CIDRs := info.GetIPv6CIDRs()
		cidrs := make([]*net.IPNet, 0, len(ipv4CIDRs)+len(ipv6CIDRs))
		for i := range ipv4CIDRs {
			cidrs = append(cidrs, &ipv4CIDRs[i])
		}
		for i := range ipv6CIDRs {
			cidrs = append(cidrs, &ipv6CIDRs[i])
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
			if err := deleteRuleIPv4(egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
			}
			scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
		}
		for _, cidr := range ipv6RoutingCIDRs {
			egress := route.Rule{
				Priority: priority,
				From:     ipv6WithMask,
				To:       normalizeRuleToCIDR(cidr),
			}
			if err := deleteRuleIPv6(egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipv6WithMask.String(), err)
			}
			scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
		}
	} else {
		if ipv4Enabled {
			egress := route.Rule{
				Priority: priority,
				From:     ipWithMask,
			}
			if err := deleteRuleIPv4(egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
			}
			scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
		}
		if ipv6Enabled {
			egress := route.Rule{
				Priority: priority,
				From:     ipv6WithMask,
			}
			if err := deleteRuleIPv6(egress); err != nil {
				return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipv6WithMask.String(), err)
			}
			scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
		}
	}

	if option.Config.EnableUnreachableRoutes {
		// Replace route to old IP with an unreachable route. This will
		//   - trigger ICMP error messages for clients attempting to connect to the stale IP
		//   - avoid hitting rp_filter and getting Martian packet warning
		// When the IP is reused, the unreachable route will be replaced to target the new pod veth
		// In CRD-based IPAM, when an IP is unassigned from the CiliumNode, we delete this route
		// to avoid blackholing traffic to this IP if it gets reassigned to another node
		if ipv4Enabled {
			if err := netlink.RouteReplace(&netlink.Route{
				Dst:      ipWithMask,
				Table:    route.MainTable,
				Type:     unix.RTN_UNREACHABLE,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to add unreachable route for ip %s: %w", ipWithMask.String(), err)
			}
		}
		if ipv6Enabled {
			if err := netlink.RouteReplace(&netlink.Route{
				Dst:      ipv6WithMask,
				Table:    route.MainTable,
				Type:     unix.RTN_UNREACHABLE,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to add unreachable route for ip %s: %w", ipv6WithMask.String(), err)
			}
		}
	}

	return nil
}

func deleteRuleIPv4(r route.Rule) error {
	return deleteRule(r, netlink.FAMILY_V4)
}

func deleteRuleIPv6(r route.Rule) error {
	return deleteRule(r, netlink.FAMILY_V6)
}

func deleteRule(r route.Rule, family int) error {
	rules, err := route.ListRules(family, &r)
	if err != nil {
		return err
	}

	length := len(rules)
	switch {
	case length > 1:
		log.WithFields(logrus.Fields{
			"candidates": rules,
			"rule":       r,
		}).Warning("Found too many rules matching, skipping deletion")
		return errors.New("unexpected number of rules found to delete")
	case length == 1:
		return route.DeleteRule(family, r)
	}

	log.WithFields(logrus.Fields{
		"rule": r,
	}).Warning("No rule matching found")

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
