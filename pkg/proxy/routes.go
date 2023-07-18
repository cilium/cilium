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

const (
	// Mark/mask set by the bpf datapath to denote packets destined to the proxy.
	tproxyMark = 0x200
	tproxyMask = 0xf00

	// Routing table for redirecting packets to the proxy through the local stack.
	proxyRoutingTable = 2004
)

var (
	// Routing rule for traffic to proxy.
	tproxyRule = route.Rule{
		// Cilium bumps the default catch-all pref 0 routing rule that points at
		// table 255 to pref 100 during startup, to create space to insert its own
		// rules between 0-99.
		Priority: linux_defaults.RulePriorityProxyIngress,
		Mark:     tproxyMark,
		Mask:     tproxyMask,
		Table:    proxyRoutingTable,
	}

	// Default IPv4 route for local delivery.
	route4 = route.Route{
		Table:  proxyRoutingTable,
		Type:   route.RTN_LOCAL,
		Local:  net.IPv4zero,
		Device: "lo",
		Proto:  linux_defaults.RTProto}

	// Default IPv6 route for local delivery.
	route6 = route.Route{
		Table:  proxyRoutingTable,
		Type:   route.RTN_LOCAL,
		Local:  net.IPv6zero,
		Device: "lo",
		Proto:  linux_defaults.RTProto,
	}
)

// installRoutesIPv4 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installRoutesIPv4() error {
	if err := route.Upsert(route4); err != nil {
		return fmt.Errorf("inserting ipv4 proxy route %v: %w", route4, err)
	}
	if err := route.ReplaceRule(tproxyRule); err != nil {
		return fmt.Errorf("inserting ipv4 proxy routing rule %v: %w", tproxyRule, err)
	}

	return nil
}

// removeRoutesIPv4 ensures routes and rules for proxy traffic are removed.
func removeRoutesIPv4() error {
	if err := route.DeleteRule(netlink.FAMILY_V4, tproxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv4 proxy routing rule: %w", err)
	}
	if err := route.DeleteRouteTable(proxyRoutingTable, netlink.FAMILY_V4); err != nil {
		return fmt.Errorf("removing ipv4 proxy route table: %w", err)
	}

	return nil
}

// installRoutesIPv6 configures routes and rules needed to redirect ingress
// packets to the proxy.
func installRoutesIPv6() error {
	if err := route.Upsert(route6); err != nil {
		return fmt.Errorf("inserting ipv6 proxy route %v: %w", route6, err)
	}
	if err := route.ReplaceRuleIPv6(tproxyRule); err != nil {
		return fmt.Errorf("inserting ipv6 proxy routing rule %v: %w", tproxyRule, err)
	}

	return nil
}

// removeRoutesIPv6 ensures routes and rules for proxy traffic are removed.
func removeRoutesIPv6() error {
	if err := route.DeleteRule(netlink.FAMILY_V6, tproxyRule); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("removing ipv6 proxy routing rule: %w", err)
	}
	if err := route.DeleteRouteTable(proxyRoutingTable, netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("removing ipv6 proxy route table: %w", err)
	}

	return nil
}
