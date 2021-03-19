// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linuxrouting

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"

	"github.com/vishvananda/netlink"
)

// ComputeRulesAndRoutesOptions are options for ENIRulesAndRoutes.
type ComputeRulesAndRoutesOptions struct {
	EgressMultiHomeIPRuleCompat bool
	EnableIPv4Masquerade        bool
}

// ComputeRulesAndRoutes returns the rules and routes required to configure an
// interface.
func ComputeRulesAndRoutes(
	ips []net.IP,
	ipNets []net.IPNet,
	netlinkInterfaceIndex int,
	eniNumber int,
	gateway net.IP,
	options ComputeRulesAndRoutesOptions,
) (rules []*route.Rule, routes []*netlink.Route) {
	var egressPriority int
	if options.EgressMultiHomeIPRuleCompat {
		egressPriority = linux_defaults.RulePriorityEgress
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
	}

	var tableID int
	if options.EgressMultiHomeIPRuleCompat {
		tableID = netlinkInterfaceIndex
	} else {
		tableID = computeTableIDFromIfaceNumber(eniNumber)
	}

	for _, ip := range ips {
		ipWithMask := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}

		// On ingress, route all traffic to the endpoint IP via the main
		// routing table. Egress rules are created in a per-ENI routing
		// table.
		ingressRule := &route.Rule{
			Priority: linux_defaults.RulePriorityIngress,
			To:       &ipWithMask,
			Table:    route.MainTable,
		}
		rules = append(rules, ingressRule)

		if options.EnableIPv4Masquerade {
			// Lookup a VPC specific table for all traffic from an endpoint
			// to the CIDR configured for the VPC on which the endpoint has
			// the IP on.
			egressRules := make([]*route.Rule, 0, len(ipNets))
			for i := range ipNets {
				egressRule := &route.Rule{
					Priority: egressPriority,
					From:     &ipWithMask,
					To:       &ipNets[i],
					Table:    tableID,
				}
				egressRules = append(egressRules, egressRule)
			}
			rules = append(rules, egressRules...)
		} else {
			// Lookup a VPC specific table for all traffic from an endpoint.
			egressRule := &route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				Table:    tableID,
			}
			rules = append(rules, egressRule)
		}
	}

	// Nexthop route to the VPC or subnet gateway. Note: This is a /32 route
	// to avoid any L2. The endpoint does no L2 either.
	nexthopRoute := &netlink.Route{
		LinkIndex: netlinkInterfaceIndex,
		Dst: &net.IPNet{
			IP:   gateway,
			Mask: net.CIDRMask(32, 32),
		},
		Scope: netlink.SCOPE_LINK,
		Table: tableID,
	}
	routes = append(routes, nexthopRoute)

	// Default route to the VPC or subnet gateway.
	defaultRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Table: tableID,
		Gw:    gateway,
	}
	routes = append(routes, defaultRoute)

	return
}
