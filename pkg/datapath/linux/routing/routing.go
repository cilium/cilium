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
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
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
func (info *RoutingInfo) Configure(ip net.IP, mtu int, compat bool, host bool) error {
	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
	}

	// Determine IP mask based on whether `ip` is IPv4 or IPv6
	var mask net.IPMask
	isV4 := true
	switch {
	case ip.To4() != nil:
		mask = net.CIDRMask(32, 32)
	case ip.To16() != nil:
		mask = net.CIDRMask(128, 128)
		isV4 = false
	default:
		return fmt.Errorf("IP %v is neither IPv4 nor IPv6", ip)
	}

	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	// Ingress rule. This rule is not installed for the cilium_host IP, because
	// the cilium_host IP is a local IP and therefore must be routed via the
	// 'local' table instead of 'main'.
	if !host {
		// On ingress, route all traffic to the endpoint IP via the main routing
		// table. Egress rules are created in a per-ENI routing table.
		rule := route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       &ipWithMask,
			Table:    route.MainTable,
			Protocol: linux_defaults.RTProto,
		}
		if isV4 {
			if err := route.ReplaceRule(rule); err != nil {
				return fmt.Errorf("unable to install ipv4 rule: %w", err)
			}
		} else {
			if err := route.ReplaceRuleIPv6(rule); err != nil {
				return fmt.Errorf("unable to install ipv6 rule: %w", err)
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
		rule := route.Rule{
			Priority: egressPriority,
			From:     &ipWithMask,
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		}
		if isV4 {
			for _, cidr := range info.IPv4CIDRs {
				rule.To = &cidr
				if err := route.ReplaceRule(rule); err != nil {
					return fmt.Errorf("unable to install ipv4 rule: %w", err)
				}
			}
		} else {
			for _, cidr := range info.IPv6CIDRs {
				rule.To = &cidr
				if err := route.ReplaceRuleIPv6(rule); err != nil {
					return fmt.Errorf("unable to install ipv6 rule: %w", err)
				}
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		rule := route.Rule{
			Priority: egressPriority,
			From:     &ipWithMask,
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		}

		if isV4 {
			if err := route.ReplaceRule(rule); err != nil {
				return fmt.Errorf("unable to install ipv4 rule: %w", err)
			}
		} else {
			if err := route.ReplaceRuleIPv6(rule); err != nil {
				return fmt.Errorf("unable to install ipv6 rule: %w", err)
			}
		}
	}

	// Nexthop route to the VPC or subnet gateway
	//
	// Note: This is a /32 or /128 route to avoid any L2. The endpoint does no L2
	// either.
	nhRoute := &netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: info.IPv4Gateway, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     tableID,
		Protocol:  linux_defaults.RTProto,
	}

	fam := "ipv4"
	if !isV4 {
		nhRoute.Dst = &net.IPNet{IP: info.IPv6Gateway, Mask: net.CIDRMask(128, 128)}
		fam = "ipv6"
	}

	if err := netlink.RouteReplace(nhRoute); err != nil {
		return fmt.Errorf("unable to add L2 %s nexthop route: %w", fam, err)
	}

	// Default route to the VPC or subnet gateway
	defRoute := &netlink.Route{
		Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:    tableID,
		Gw:       info.IPv4Gateway,
		Protocol: linux_defaults.RTProto,
	}

	if !isV4 {
		defRoute.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		defRoute.Gw = info.IPv6Gateway
	}

	if err := netlink.RouteReplace(defRoute); err != nil {
		return fmt.Errorf("unable to add %s default route: %w", fam, err)
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
func Delete(ip netip.Addr, compat bool) error {
	isV4 := true
	if ip.Is6() {
		isV4 = false
	}

	ipWithMask := iputil.AddrToIPNet(ip)

	scopedLog := log.WithFields(logrus.Fields{
		"ip": ipWithMask.String(),
	})

	// Ingress rules
	ingress := route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       ipWithMask,
		Table:    route.MainTable,
	}
	if err := deleteRule(ingress); err != nil {
		return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %w", ipWithMask.String(), err)
	}

	scopedLog.WithField("rule", ingress).Debug("Deleted ingress rule")

	priority := linux_defaults.RulePriorityEgressv2
	if compat {
		priority = linux_defaults.RulePriorityEgress
	}

	// Egress rules
	// The condition here should mirror the conditions in Configure.
	info := node.GetRouterInfo()
	routerCIDRs := info.GetIPv4CIDRs()
	masqEnabled := option.Config.EnableIPv4Masquerade
	if !isV4 {
		routerCIDRs = info.GetIPv6CIDRs()
		masqEnabled = option.Config.EnableIPv6Masquerade
	}
	if info != nil && masqEnabled && option.Config.IPAM == ipamOption.IPAMENI {
		cidrs := make([]*net.IPNet, 0, len(routerCIDRs))
		for i := range routerCIDRs {
			cidrs = append(cidrs, &routerCIDRs[i])
		}
		// Coalesce CIDRs into minimum set needed for route rules
		// This code here mirrors interfaceAdd() in cilium-cni/interface.go
		// and must be kept in sync when modified
		routingCIDRs, v6RoutingCIDRs := iputil.CoalesceCIDRs(cidrs)
		if isV4 {
			for _, cidr := range routingCIDRs {
				egress := route.Rule{
					Priority: priority,
					From:     ipWithMask,
					To:       cidr,
				}
				if err := deleteRule(egress); err != nil {
					return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
				}
				scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
			}
		} else {
			for _, cidr := range v6RoutingCIDRs {
				egress := route.Rule{
					Priority: priority,
					From:     ipWithMask,
					To:       cidr,
				}
				if err := deleteRule(egress); err != nil {
					return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
				}
				scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
			}
		}
	} else {
		egress := route.Rule{
			Priority: priority,
			From:     ipWithMask,
		}
		if err := deleteRule(egress); err != nil {
			return fmt.Errorf("unable to delete egress rule with ip %s: %w", ipWithMask.String(), err)
		}
		scopedLog.WithField(logfields.Rule, egress).Debug("Deleted egress rule")
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

func deleteRule(r route.Rule) error {
	var family int
	// Determine if the rule is for IPv4 or IPv6
	if r.To == nil || r.To.IP.To4() != nil {
		family = netlink.FAMILY_V4
	} else if r.To.IP.To16() != nil {
		family = netlink.FAMILY_V6
	} else {
		return errors.New("invalid IP address in rule")
	}

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

	links, err := netlink.LinkList()
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
