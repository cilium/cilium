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
func (info *RoutingInfo) Configure(ip net.IP, mtu int, compat bool) error {
	if ip.To4() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to configure rules and routes because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}

	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %s", err)
	}

	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}

	// On ingress, route all traffic to the endpoint IP via the main routing
	// table. Egress rules are created in a per-ENI routing table.
	if err := route.ReplaceRule(route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       &ipWithMask,
		Table:    route.MainTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %s", err)
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
		for _, cidr := range info.IPv4CIDRs {
			if err := route.ReplaceRule(route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				To:       &cidr,
				Table:    tableID,
				Protocol: linux_defaults.RTProto,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %s", err)
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		if err := route.ReplaceRule(route.Rule{
			Priority: egressPriority,
			From:     &ipWithMask,
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %s", err)
		}
	}

	// Nexthop route to the VPC or subnet gateway
	//
	// Note: This is a /32 route to avoid any L2. The endpoint does no L2
	// either.
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: info.IPv4Gateway, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     tableID,
		Protocol:  linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:    tableID,
		Gw:       info.IPv4Gateway,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
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
	if !ip.Is4() {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to delete rules because IP is not an IPv4 address")
		return errors.New("IP not compatible")
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
		return fmt.Errorf("unable to delete ingress rule from main table with ip %s: %v", ipWithMask.String(), err)
	}

	scopedLog.WithField("rule", ingress).Debug("Deleted ingress rule")

	priority := linux_defaults.RulePriorityEgressv2
	if compat {
		priority = linux_defaults.RulePriorityEgress
	}

	// Egress rules
	// The condition here should mirror the conditions in Configure.
	info := node.GetRouterInfo()
	if info != nil && option.Config.EnableIPv4Masquerade && option.Config.IPAM == ipamOption.IPAMENI {
		ipv4CIDRs := info.GetIPv4CIDRs()
		cidrs := make([]*net.IPNet, 0, len(ipv4CIDRs))
		for i := range ipv4CIDRs {
			cidrs = append(cidrs, &ipv4CIDRs[i])
		}
		// Coalesce CIDRs into minimum set needed for route rules
		// This code here mirrors interfaceAdd() in cilium-cni/interface.go
		// and must be kept in sync when modified
		routingCIDRs, _ := iputil.CoalesceCIDRs(cidrs)
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

// SetupRules installs routing rules based on the passed attributes. It accounts
// for option.Config.EgressMultiHomeIPRuleCompat while configuring the rules.
func SetupRules(from, to *net.IPNet, mac string, ifaceNum int) error {
	var (
		prio    int
		tableId int
	)

	if option.Config.EgressMultiHomeIPRuleCompat {
		prio = linux_defaults.RulePriorityEgress
		ifindex, err := retrieveIfaceIdxFromMAC(mac)
		if err != nil {
			return fmt.Errorf("unable to find ifindex for interface MAC: %w", err)
		}
		tableId = ifindex
	} else {
		prio = linux_defaults.RulePriorityEgressv2
		tableId = computeTableIDFromIfaceNumber(ifaceNum)
	}
	return route.ReplaceRule(route.Rule{
		Priority: prio,
		From:     from,
		To:       to,
		Table:    tableId,
		Protocol: linux_defaults.RTProto,
	})
}

// RetrieveIfaceNameFromMAC finds the corresponding device name for a
// given MAC address.
func RetrieveIfaceNameFromMAC(mac string) (string, error) {
	iface, err := retrieveIfaceFromMAC(mac)
	if err != nil {
		err = fmt.Errorf("failed to get iface name with MAC %w", err)
		return "", err
	}
	return iface.Attrs().Name, nil
}

func deleteRule(r route.Rule) error {
	rules, err := route.ListRules(netlink.FAMILY_V4, &r)
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
		return route.DeleteRule(netlink.FAMILY_V4, r)
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

// retrieveIfaceIdxFromMAC finds the corresponding interface index for a
// given MAC address.
// It returns -1 as the index for error conditions.
func retrieveIfaceIdxFromMAC(mac string) (int, error) {
	iface, err := retrieveIfaceFromMAC(mac)
	if err != nil {
		err = fmt.Errorf("failed to get iface index with MAC %w", err)
		return -1, err
	}
	return iface.Attrs().Index, nil
}

// retrieveIfaceFromFromMAC finds the corresponding interface for a
// given MAC address.
func retrieveIfaceFromMAC(mac string) (link netlink.Link, err error) {
	var links []netlink.Link

	links, err = netlink.LinkList()
	if err != nil {
		err = fmt.Errorf("unable to list interfaces: %w", err)
		return
	}
	for _, l := range links {
		if l.Attrs().HardwareAddr.String() == mac {
			link = l
			return
		}
	}

	err = fmt.Errorf("interface with MAC not found")
	return
}
