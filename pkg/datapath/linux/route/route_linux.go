// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package route

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// RouteReplaceMaxTries is the number of attempts the route will be
	// attempted to be added or updated in case the kernel returns an error
	RouteReplaceMaxTries = 10

	// RouteReplaceRetryInterval is the interval in which
	// RouteReplaceMaxTries attempts are attempted
	RouteReplaceRetryInterval = 100 * time.Millisecond

	// RTN_LOCAL is a route type used to indicate packet should be "routed"
	// locally and passed up the stack. Is used by IPSec to force encrypted
	// packets to pass through XFRM layer.
	RTN_LOCAL = 0x2

	// MainTable is Linux's default routing table
	MainTable = 254

	// EncryptRouteProtocol for Encryption specific routes
	EncryptRouteProtocol = 192
)

// getNetlinkRoute returns the route configuration as netlink.Route
func (r *Route) getNetlinkRoute() netlink.Route {
	rt := netlink.Route{
		Dst:      &r.Prefix,
		Src:      r.Local,
		MTU:      r.MTU,
		Priority: r.Priority,
		Protocol: netlink.RouteProtocol(r.Proto),
		Table:    r.Table,
		Type:     r.Type,
	}

	if r.Nexthop != nil {
		rt.Gw = *r.Nexthop
	}

	if r.Scope != netlink.SCOPE_UNIVERSE {
		rt.Scope = r.Scope
	} else if r.Scope == netlink.SCOPE_UNIVERSE && r.Type == RTN_LOCAL {
		rt.Scope = netlink.SCOPE_HOST
	}

	return rt
}

// getNexthopAsIPNet returns the nexthop of the route as IPNet
func (r *Route) getNexthopAsIPNet() *net.IPNet {
	if r.Nexthop == nil {
		return nil
	}

	if r.Nexthop.To4() != nil {
		return &net.IPNet{IP: *r.Nexthop, Mask: net.CIDRMask(32, 32)}
	}

	return &net.IPNet{IP: *r.Nexthop, Mask: net.CIDRMask(128, 128)}
}

func ipFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}

	return netlink.FAMILY_V4
}

// Lookup attempts to find the linux route based on the route specification.
// If the route exists, the route is returned, otherwise an error is returned.
func Lookup(route Route) (*Route, error) {
	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return nil, fmt.Errorf("unable to find interface '%s' of route: %w", route.Device, err)
	}

	routeSpec := route.getNetlinkRoute()
	routeSpec.LinkIndex = link.Attrs().Index

	nlRoute := lookup(&routeSpec)
	if nlRoute == nil {
		return nil, nil
	}

	result := &Route{
		Local:   nlRoute.Src,
		Device:  link.Attrs().Name,
		MTU:     nlRoute.MTU,
		Scope:   nlRoute.Scope,
		Nexthop: &nlRoute.Gw,
	}

	if nlRoute.Dst != nil {
		result.Prefix = *nlRoute.Dst
	}

	return result, nil
}

// lookup finds a particular route as specified by the filter which points
// to the specified device. The filter route can have the following fields set:
//   - Dst
//   - LinkIndex
//   - Scope
//   - Gw
func lookup(route *netlink.Route) *netlink.Route {
	var filter uint64
	if route.Dst != nil {
		filter |= netlink.RT_FILTER_DST
	}
	if route.Table != 0 {
		filter |= netlink.RT_FILTER_TABLE
	}
	if route.Scope != 0 {
		filter |= netlink.RT_FILTER_SCOPE
	}
	if route.Gw != nil {
		filter |= netlink.RT_FILTER_GW
	}
	if route.LinkIndex != 0 {
		filter |= netlink.RT_FILTER_OIF
	}

	routes, err := netlink.RouteListFiltered(ipFamily(route.Dst.IP), route, filter)
	if err != nil {
		return nil
	}

	for _, r := range routes {
		if r.Dst != nil && route.Dst == nil {
			continue
		}

		if route.Dst != nil && r.Dst == nil {
			continue
		}

		if route.Table != 0 && route.Table != r.Table {
			continue
		}

		aMaskLen, aMaskBits := r.Dst.Mask.Size()
		bMaskLen, bMaskBits := route.Dst.Mask.Size()
		if r.Scope == route.Scope &&
			aMaskLen == bMaskLen && aMaskBits == bMaskBits &&
			r.Dst.IP.Equal(route.Dst.IP) && r.Gw.Equal(route.Gw) {
			return &r
		}
	}

	return nil
}

func createNexthopRoute(route Route, link netlink.Link, routerNet *net.IPNet) *netlink.Route {
	// This is the L2 route which makes router IP available behind the
	// interface.
	rt := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       routerNet,
		Table:     route.Table,
		Protocol:  linux_defaults.RTProto,
	}

	// Known issue: scope for IPv6 routes is not propagated correctly. If
	// we set the scope here, lookup() will be unable to identify the route
	// again and we will continuously re-add the route
	if routerNet.IP.To4() != nil {
		rt.Scope = netlink.SCOPE_LINK
	}

	return rt
}

// replaceNexthopRoute verifies that the L2 route for the router IP which is
// used as nexthop for all node routes is properly installed. If unavailable or
// incorrect, it will be replaced with the proper L2 route.
func replaceNexthopRoute(route Route, link netlink.Link, routerNet *net.IPNet) (bool, error) {
	if err := netlink.RouteReplace(createNexthopRoute(route, link, routerNet)); err != nil {
		return false, fmt.Errorf("unable to add L2 nexthop route: %w", err)
	}

	return true, nil
}

// deleteNexthopRoute deletes
func deleteNexthopRoute(route Route, link netlink.Link, routerNet *net.IPNet) error {
	if err := netlink.RouteDel(createNexthopRoute(route, link, routerNet)); err != nil {
		return fmt.Errorf("unable to delete L2 nexthop route: %w", err)
	}

	return nil
}

// Upsert adds or updates a Linux kernel route. The route described can be in
// the following two forms:
//
// direct:
//
//	prefix dev foo
//
// nexthop:
//
//	prefix via nexthop dev foo
//
// If a nexthop route is specified, this function will check whether a direct
// route to the nexthop exists and add if required. This means that the
// following two routes will exist afterwards:
//
//	nexthop dev foo
//	prefix via nexthop dev foo
//
// Due to a bug in the Linux kernel, the prefix route is attempted to be
// updated RouteReplaceMaxTries with an interval of RouteReplaceRetryInterval.
// This is a workaround for a race condition in which the direct route to the
// nexthop is not available immediately and the prefix route can fail with
// EINVAL if the Netlink calls are issued in short order.
//
// An error is returned if the route can not be added or updated.
func Upsert(route Route) error {
	var nexthopRouteCreated bool

	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("unable to lookup interface %s: %w", route.Device, err)
	}

	// Can't add local routes to an interface that's down ('lo' in new netns).
	if link.Attrs().OperState == netlink.OperDown {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("unable to set interface up: %w", err)
		}
	}

	routerNet := route.getNexthopAsIPNet()
	if routerNet != nil {
		if _, err := replaceNexthopRoute(route, link, routerNet); err != nil {
			return fmt.Errorf("unable to add nexthop route: %w", err)
		}

		nexthopRouteCreated = true
	}

	routeSpec := route.getNetlinkRoute()
	routeSpec.LinkIndex = link.Attrs().Index

	err = fmt.Errorf("routeReplace not called yet")

	// Workaround: See description of this function
	for i := 0; err != nil && i < RouteReplaceMaxTries; i++ {
		err = netlink.RouteReplace(&routeSpec)
		if err == nil {
			break
		}
		time.Sleep(RouteReplaceRetryInterval)
	}

	if err != nil {
		if nexthopRouteCreated {
			if err2 := deleteNexthopRoute(route, link, routerNet); err2 != nil {
				// TODO: If this fails, we may want to add some retry logic.
				log.WithError(err2).
					Errorf("unable to clean up nexthop route following failure to replace route")
			}
		}
		return err
	}

	return nil
}

// Delete deletes a Linux route. An error is returned if the route does not
// exist or if the route could not be deleted.
func Delete(route Route) error {
	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("unable to lookup interface %s: %w", route.Device, err)
	}

	// Deletion of routes with Nexthop or Local set fails for IPv6.
	// Therefore do not use getNetlinkRoute().
	routeSpec := netlink.Route{
		Dst:       &route.Prefix,
		LinkIndex: link.Attrs().Index,
		Table:     route.Table,
	}

	// Scope can only be specified for IPv4
	if route.Prefix.IP.To4() != nil {
		routeSpec.Scope = route.Scope
	}

	if err := netlink.RouteDel(&routeSpec); err != nil {
		return err
	}

	return nil
}

// Rule is the specification of an IP routing rule
type Rule struct {
	// Priority is the routing rule priority
	Priority int

	// Mark is the skb mark that needs to match
	Mark int

	// Mask is the mask to apply to the skb mark before matching the Mark
	// field
	Mask int

	// From is the source address selector
	From *net.IPNet

	// To is the destination address selector
	To *net.IPNet

	// Table is the routing table to look up if the rule matches
	Table int

	// Protocol is the routing rule protocol (e.g. proto unspec/kernel)
	Protocol uint8
}

// String returns the string representation of a Rule (adhering to the Stringer
// interface).
func (r Rule) String() string {
	var (
		str  string
		from string
		to   string
	)

	str += fmt.Sprintf("%d: ", r.Priority)

	if r.From != nil {
		from = r.From.String()
	} else {
		from = "all"
	}

	if r.To != nil {
		to = r.To.String()
	} else {
		to = "all"
	}

	if r.Table == unix.RT_TABLE_MAIN {
		str += fmt.Sprintf("from %s to %s lookup main", from, to)
	} else {
		str += fmt.Sprintf("from %s to %s lookup %d", from, to, r.Table)
	}

	if r.Mark != 0 {
		str += fmt.Sprintf(" mark 0x%x mask 0x%x", r.Mark, r.Mask)
	}

	str += fmt.Sprintf(" proto %s", netlink.RouteProtocol(r.Protocol))

	return str
}

func lookupRule(spec Rule, family int) (bool, error) {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if spec.Priority != 0 && spec.Priority != r.Priority {
			continue
		}

		if spec.From != nil && (r.Src == nil || r.Src.String() != spec.From.String()) {
			continue
		}

		if spec.To != nil && (r.Dst == nil || r.Dst.String() != spec.To.String()) {
			continue
		}

		if spec.Mark != 0 && r.Mark != spec.Mark {
			continue
		}

		if spec.Protocol != 0 && r.Protocol != spec.Protocol {
			continue
		}

		if spec.Mask != 0 && r.Mask != spec.Mask {
			continue
		}

		if r.Table == spec.Table {
			return true, nil
		}
	}
	return false, nil
}

// ListRules will list IP routing rules on Linux, filtered by `filter`. When
// `filter` is nil, this function will return all rules, "unfiltered". This
// function is meant to replicate the behavior of `ip rule list`.
func ListRules(family int, filter *Rule) ([]netlink.Rule, error) {
	var nlFilter netlink.Rule
	var mask uint64

	if filter != nil {
		if filter.From != nil {
			mask |= netlink.RT_FILTER_SRC
			nlFilter.Src = filter.From
		}
		if filter.To != nil {
			mask |= netlink.RT_FILTER_DST
			nlFilter.Dst = filter.To
		}
		if filter.Table != 0 {
			mask |= netlink.RT_FILTER_TABLE
			nlFilter.Table = filter.Table
		}
		if filter.Priority != 0 {
			mask |= netlink.RT_FILTER_PRIORITY
			nlFilter.Priority = filter.Priority
		}
		if filter.Mark != 0 {
			mask |= netlink.RT_FILTER_MARK
			nlFilter.Mark = filter.Mark
		}
		if filter.Mask != 0 {
			mask |= netlink.RT_FILTER_MASK
			nlFilter.Mask = filter.Mask
		}

		nlFilter.Priority = filter.Priority
		nlFilter.Mark = filter.Mark
		nlFilter.Mask = filter.Mask
		nlFilter.Src = filter.From
		nlFilter.Dst = filter.To
		nlFilter.Table = filter.Table
	}
	return netlink.RuleListFiltered(family, &nlFilter, mask)
}

// ReplaceRule add or replace rule in the routing table using a mark to indicate
// table. Used with BPF datapath to set mark and direct packets to route table.
func ReplaceRule(spec Rule) error {
	return replaceRule(spec, netlink.FAMILY_V4)
}

// ReplaceRuleIPv6 add or replace IPv6 rule in the routing table using a mark to
// indicate table.
func ReplaceRuleIPv6(spec Rule) error {
	return replaceRule(spec, netlink.FAMILY_V6)
}

func replaceRule(spec Rule, family int) error {
	exists, err := lookupRule(spec, family)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	rule := netlink.NewRule()
	rule.Mark = spec.Mark
	rule.Mask = spec.Mask
	rule.Table = spec.Table
	rule.Family = family
	rule.Priority = spec.Priority
	rule.Src = spec.From
	rule.Dst = spec.To
	rule.Protocol = spec.Protocol
	return netlink.RuleAdd(rule)
}

// DeleteRule delete a mark based rule from the routing table.
func DeleteRule(family int, spec Rule) error {
	rule := netlink.NewRule()
	rule.Mark = spec.Mark
	rule.Mask = spec.Mask
	rule.Table = spec.Table
	rule.Priority = spec.Priority
	rule.Src = spec.From
	rule.Dst = spec.To
	rule.Family = family
	rule.Protocol = spec.Protocol
	return netlink.RuleDel(rule)
}

func lookupDefaultRoute(family int) (netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return netlink.Route{}, fmt.Errorf("Unable to list direct routes: %w", err)
	}

	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority < routes[j].Priority
	})

	switch {
	case len(routes) == 0:
		return netlink.Route{}, fmt.Errorf("Default route not found for family %d", family)
	case len(routes) > 1 && routes[0].Priority == routes[1].Priority:
		return netlink.Route{}, fmt.Errorf("Found multiple default routes with the same priority: %v vs %v", routes[0], routes[1])
	}

	log.Debugf("Found default route on node %v", routes[0])
	return routes[0], nil
}

func DeleteRouteTable(table, family int) error {
	var routeErr error

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("Unable to list table %d routes: %w", table, err)
	}

	routeErr = nil
	for _, route := range routes {
		err := netlink.RouteDel(&route)
		if err != nil {
			routeErr = fmt.Errorf("%w: Failed to delete route: %w", routeErr, err)
		}
	}
	return routeErr
}

// NodeDeviceWithDefaultRoute returns the node's device which handles the
// default route in the current namespace
func NodeDeviceWithDefaultRoute(enableIPv4, enableIPv6 bool) (netlink.Link, error) {
	linkIndex := 0
	if enableIPv4 {
		route, err := lookupDefaultRoute(netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		linkIndex = route.LinkIndex
	}
	if enableIPv6 {
		route, err := lookupDefaultRoute(netlink.FAMILY_V6)
		if err != nil {
			return nil, err
		}
		if linkIndex != 0 && linkIndex != route.LinkIndex {
			return nil, fmt.Errorf("IPv4/IPv6 have different link indices")
		}
		linkIndex = route.LinkIndex
	}
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return nil, err
	}
	return link, nil
}
