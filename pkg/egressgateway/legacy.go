// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/route"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// deleteStaielIPRulesAndRoutes cleans up any stale IP rules and routes from previous Cilium versions which still use
// those to steer egress gateway traffic to the correct interface. This logic can be removed in v1.16.
func deleteStaleIPRulesAndRoutes() error {
	const (
		// RouteTableEgressGatewayInterfacesOffset is the offset for the per-ENI egress gateway routing tables.
		// Each ENI interface will have its own table starting with this offset. It is 300 because it is highly
		// unlikely to collide with the main routing table which is between 253-255. See ip-route(8).
		routeTableEgressGatewayInterfacesOffset = 300

		// RulePriorityEgressGateway is the priority used in IP routes added by the manager. This value was
		// picked as it's lower than the ones used by Cilium (RulePriorityEgressv2 = 111) or the AWS CNI (10) to
		// install the IP rules for routing EP traffic to the correct ENI interface
		rulePriorityEgressGateway = 8
	)

	// first delete all IP rules matching the egress gateway priority (rulePriorityEgressGateway)
	rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
		Priority: rulePriorityEgressGateway,
	})
	if err != nil {
		return fmt.Errorf("cannot list IP rules: %w", err)
	}

	for _, rule := range rules {
		log.Debugf("deleting IP rule %+v", rule)
		if err := netlink.RuleDel(&rule); err != nil {
			return fmt.Errorf("cannot delete IP rule: %w", err)
		}
	}

	// then delete all IP routes matching an egress gateway table associated with a network interface
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("cannot list IP links: %w", err)
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("cannot list IP routes: %w", err)
	}

nextRoute:
	for _, route := range routes {
	nextLink:
		for _, link := range links {
			if route.Table != routeTableEgressGatewayInterfacesOffset+link.Attrs().Index {
				continue nextLink
			}

			log.Debugf("deleting IP route %+v", route)
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("cannot delete IP route: %w", err)
			}

			continue nextRoute
		}
	}

	return nil
}
