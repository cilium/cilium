// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

var (
	// Routing rule for traffic to proxy.
	toProxyRule = route.Rule{
		// Cilium bumps the default catch-all pref 0 routing rule that points at
		// table 255 to pref 100 during startup, to create space to insert its own
		// rules between 0-99.
		Priority: linux_defaults.RulePriorityToProxyIngress,
		Mark:     linux_defaults.MagicMarkIsToProxy,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableToProxy,
		Protocol: linux_defaults.RTProto,
	}

	// Default IPv4 route for local delivery.
	route4 = route.Route{
		Table:  linux_defaults.RouteTableToProxy,
		Type:   route.RTN_LOCAL,
		Local:  net.IPv4zero,
		Device: "lo",
		Proto:  linux_defaults.RTProto,
	}

	// Default IPv6 route for local delivery.
	route6 = route.Route{
		Table:  linux_defaults.RouteTableToProxy,
		Type:   route.RTN_LOCAL,
		Local:  net.IPv6zero,
		Device: "lo",
		Proto:  linux_defaults.RTProto,
	}
)

// installToProxyRoutesIPv4 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installToProxyRoutesIPv4() error {
	if err := route.Upsert(route4); err != nil {
		return fmt.Errorf("inserting ipv4 proxy route %v: %w", route4, err)
	}
	if err := route.ReplaceRule(toProxyRule); err != nil {
		return fmt.Errorf("inserting ipv4 proxy routing rule %v: %w", toProxyRule, err)
	}

	return nil
}

// removeToProxyRoutesIPv4 ensures routes and rules for proxy traffic are removed.
func removeToProxyRoutesIPv4() error {
	if err := route.DeleteRule(netlink.FAMILY_V4, toProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 proxy routing rule: %w", err)
	}
	if err := route.DeleteRouteTable(linux_defaults.RouteTableToProxy, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("removing ipv4 proxy route table: %w", err)
	}

	return nil
}

// installToProxyRoutesIPv6 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installToProxyRoutesIPv6() error {
	if err := route.Upsert(route6); err != nil {
		return fmt.Errorf("inserting ipv6 proxy route %v: %w", route6, err)
	}
	if err := route.ReplaceRuleIPv6(toProxyRule); err != nil {
		return fmt.Errorf("inserting ipv6 proxy routing rule %v: %w", toProxyRule, err)
	}

	return nil
}

// removeToProxyRoutesIPv6 ensures routes and rules for proxy traffic are removed.
func removeToProxyRoutesIPv6() error {
	if err := route.DeleteRule(netlink.FAMILY_V6, toProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 proxy routing rule: %w", err)
		}
	}
	if err := route.DeleteRouteTable(linux_defaults.RouteTableToProxy, netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("removing ipv6 proxy route table: %w", err)
	}

	return nil
}

var (
	// Routing rule for traffic from ingress proxy.
	fromIngressProxyRule = route.Rule{
		Priority: linux_defaults.RulePriorityFromProxy,
		Mark:     linux_defaults.MagicMarkIngress,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableFromProxy,
		Protocol: linux_defaults.RTProto,
	}

	// Routing rule for traffic from egress proxy.
	fromEgressProxyRule = route.Rule{
		Priority: linux_defaults.RulePriorityFromProxy,
		Mark:     linux_defaults.MagicMarkEgress,
		Mask:     linux_defaults.MagicMarkHostMask,
		Table:    linux_defaults.RouteTableFromProxy,
		Protocol: linux_defaults.RTProto,
	}
)

// installFromProxyRoutesIPv4 configures routes and rules needed to redirect ingress
// packets from the proxy.
func installFromProxyRoutesIPv4(ipv4 net.IP, device string, fromIngressProxy, fromEgressProxy bool) error {
	fromProxyToCiliumHostRoute4 := route.Route{
		Table: linux_defaults.RouteTableFromProxy,
		Prefix: net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(32, 32),
		},
		Device: device,
		Type:   route.RTN_LOCAL,
		Proto:  linux_defaults.RTProto,
	}
	fromProxyDefaultRoute4 := route.Route{
		Table:   linux_defaults.RouteTableFromProxy,
		Nexthop: &ipv4,
		Device:  device,
		Proto:   linux_defaults.RTProto,
	}

	if fromIngressProxy {
		if err := route.ReplaceRule(fromIngressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv4 from ingress proxy routing rule %v: %w", fromIngressProxyRule, err)
		}
	}
	if fromEgressProxy {
		if err := route.ReplaceRule(fromEgressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv4 from egress proxy routing rule %v: %w", fromEgressProxyRule, err)
		}
	}
	if err := route.Upsert(fromProxyToCiliumHostRoute4); err != nil {
		return fmt.Errorf("inserting ipv4 from proxy to cilium_host route %v: %w", fromProxyToCiliumHostRoute4, err)
	}
	if err := route.Upsert(fromProxyDefaultRoute4); err != nil {
		return fmt.Errorf("inserting ipv4 from proxy default route %v: %w", fromProxyDefaultRoute4, err)
	}

	return nil
}

// removeFromProxyRoutesIPv4 ensures routes and rules for traffic from the proxy are removed.
func removeFromProxyRoutesIPv4() error {
	if err := route.DeleteRule(netlink.FAMILY_V4, fromIngressProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 from ingress proxy routing rule: %w", err)
	}
	if err := route.DeleteRule(netlink.FAMILY_V4, fromEgressProxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 from egress proxy routing rule: %w", err)
	}
	if err := route.DeleteRouteTable(linux_defaults.RouteTableFromProxy, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("removing ipv4 from proxy route table: %w", err)
	}

	return nil
}

// installFromProxyRoutesIPv6 configures routes and rules needed to redirect ingress
// packets from the proxy.
func installFromProxyRoutesIPv6(ipv6 net.IP, device string, fromIngressProxy, fromEgressProxy bool) error {
	fromProxyToCiliumHostRoute6 := route.Route{
		Table: linux_defaults.RouteTableFromProxy,
		Prefix: net.IPNet{
			IP:   ipv6,
			Mask: net.CIDRMask(128, 128),
		},
		Device: device,
		Proto:  linux_defaults.RTProto,
	}

	fromProxyDefaultRoute6 := route.Route{
		Table:   linux_defaults.RouteTableFromProxy,
		Nexthop: &ipv6,
		Device:  device,
		Proto:   linux_defaults.RTProto,
	}

	if fromIngressProxy {
		if err := route.ReplaceRuleIPv6(fromIngressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv6 from ingress proxy routing rule %v: %w", fromIngressProxyRule, err)
		}
	}
	if fromEgressProxy {
		if err := route.ReplaceRuleIPv6(fromEgressProxyRule); err != nil {
			return fmt.Errorf("inserting ipv6 from egress proxy routing rule %v: %w", fromEgressProxyRule, err)
		}
	}
	if err := route.Upsert(fromProxyToCiliumHostRoute6); err != nil {
		return fmt.Errorf("inserting ipv6 from proxy to cilium_host route %v: %w", fromProxyToCiliumHostRoute6, err)
	}
	if err := route.Upsert(fromProxyDefaultRoute6); err != nil {
		return fmt.Errorf("inserting ipv6 from proxy default route %v: %w", fromProxyDefaultRoute6, err)
	}

	return nil
}

// removeFromProxyRoutesIPv6 ensures routes and rules for traffic from the proxy are removed.
func removeFromProxyRoutesIPv6() error {
	if err := route.DeleteRule(netlink.FAMILY_V6, fromIngressProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 from ingress proxy routing rule: %w", err)
		}
	}
	if err := route.DeleteRule(netlink.FAMILY_V6, fromEgressProxyRule); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return fmt.Errorf("removing ipv6 from egress proxy routing rule: %w", err)
		}
	}
	if err := route.DeleteRouteTable(linux_defaults.RouteTableFromProxy, netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("removing ipv6 from proxy route table: %w", err)
	}

	return nil
}
