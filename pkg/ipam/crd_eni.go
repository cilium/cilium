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

package ipam

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
)

var errNotAnIPv4Address = errors.New("not an IPv4 address")

func updateENIRulesAndRoutes(oldNode, newNode *ciliumv2.CiliumNode) error {
	log.WithField("old", oldNode).WithField("new", newNode).Info("!!! updateENIRulesAndRoutes") // FIXME remove debug code

	addedResources, removedResources := diffResources(oldNode, newNode)

	// Configure new interfaces.
	macToNetlinkInterfaceIndex := make(map[string]int)
	for _, addedResource := range addedResources {
		eni := newNode.Status.ENI.ENIs[addedResource]
		mac, err := mac.ParseMAC(eni.MAC)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Resource:  addedResource,
				logfields.Interface: eni.Number,
				logfields.MACAddr:   eni.MAC,
			}).Error("Failed to parse MAC address")
			continue
		}
		// mtu := n.nodeConfig.MtuConfig.GetDeviceMTU()
		mtu := 1500 // FIXME pass in real MTU
		netlinkInterfaceIndex, err := linuxrouting.RetrieveIfIndexFromMAC(mac, mtu)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Resource:  addedResource,
				logfields.Interface: eni.Number,
				logfields.MACAddr:   eni.MAC,
			}).Error("Failed to configure interface")
		} else {
			macToNetlinkInterfaceIndex[eni.MAC] = netlinkInterfaceIndex
		}
	}

	// Ignore removed interfaces for now.
	_ = removedResources

	options := ciliumNodeENIRulesAndRoutesOptions{
		EgressMultiHomeIPRuleCompat: option.Config.EgressMultiHomeIPRuleCompat,
		EnableIPv4Masquerade:        option.Config.EnableIPv4Masquerade,
	}
	oldRules, oldRoutes := ciliumNodeENIRulesAndRoutes(oldNode, macToNetlinkInterfaceIndex, options)
	newRules, newRoutes := ciliumNodeENIRulesAndRoutes(newNode, macToNetlinkInterfaceIndex, options)
	addedRules, removedRules := diffRules(oldRules, newRules)
	addedRoutes, removedRoutes := diffRoutes(oldRoutes, newRoutes)

	log.WithFields(logrus.Fields{ // FIXME remove debug code
		"addedRules":    addedRules,
		"removedRules":  removedRules,
		"addedRoutes":   addedRoutes,
		"removedRoutes": removedRoutes,
	}).Info("!!!! EXTRACTED DIFF")

	// Add and remove rules and routes. This has to succeed so we retry
	// multiple times.
	maxRetries := 3
	rulesToAdd, rulesToRemove := addedRules, removedRules
	routesToAdd, routesToRemove := addedRoutes, removedRoutes
	var failedAddRules, failedRemoveRules []*route.Rule
	var failedAddRoutes, failedRemoveRoutes []*netlink.Route
	for retry := 0; retry < maxRetries; retry++ {
		for _, rule := range rulesToAdd {
			if err := route.ReplaceRule(*rule); err != nil {
				log.WithError(err).WithField(logfields.Rule, rule).Errorf("Failed to add routing rule in ENI IPAM mode")
				failedAddRules = append(failedAddRules, rule)
			}
		}

		for _, rule := range rulesToRemove {
			if err := route.DeleteRule(*rule); err != nil {
				log.WithError(err).WithField(logfields.Rule, rule).Errorf("Failed to delete routing rule in ENI IPAM mode")
				failedRemoveRules = append(failedRemoveRules, rule)
			}
		}

		for _, route := range routesToAdd {
			if err := netlink.RouteReplace(route); err != nil {
				log.WithError(err).WithField(logfields.Route, route).Errorf("Failed to add L2 nexthop route in ENI IPAM mode")
				failedAddRoutes = append(failedAddRoutes, route)
			}
		}

		for _, route := range routesToRemove {
			if err := netlink.RouteDel(route); err != nil {
				log.WithError(err).WithField(logfields.Route, route).Errorf("Failed to remove L2 nexthop route in ENI IPAM mode")
				failedRemoveRoutes = append(failedRemoveRoutes, route)
			}
		}

		// If there were no failues, then we are done.
		if len(failedAddRules)+len(failedRemoveRules)+len(failedAddRoutes)+len(failedRemoveRoutes) == 0 {
			break
		}

		// Otherwise, retry with the failures and clear the list of failures.
		rulesToAdd, failedAddRules = failedAddRules, nil
		rulesToRemove, failedRemoveRules = failedRemoveRules, nil
		routesToAdd, failedAddRoutes = failedAddRoutes, nil
		routesToRemove, failedRemoveRoutes = failedRemoveRoutes, nil
	}

	// If there were still failures after retrying, then return an error.
	if failures := len(failedAddRules) + len(failedRemoveRules) + len(failedAddRoutes) + len(failedRemoveRoutes); failures > 0 {
		return fmt.Errorf("adding and removing %d rules and routes failed after %d retries", failures, maxRetries)
	}

	return nil
}

func diffResources(old, new *ciliumv2.CiliumNode) (added, removed []string) {
	for newResource := range new.Status.ENI.ENIs {
		if _, ok := old.Status.ENI.ENIs[newResource]; !ok {
			added = append(added, newResource)
		}
	}

	for oldResource := range old.Status.ENI.ENIs {
		if _, ok := new.Status.ENI.ENIs[oldResource]; !ok {
			removed = append(removed, oldResource)
		}
	}

	return
}

// diffRules returns a list of added and removed rules between old and new.
//
// TODO this could be a lot more efficient, it makes a lot of calls to
// route.Rule.String() which could be a lot faster. As the order of rules is
// deterministic, we could also consider using a proper diff algorithm.
func diffRules(old, new []*route.Rule) (added, removed []*route.Rule) {
	newRuleSet := ruleSet(new)
	for _, oldRule := range old {
		if _, ok := newRuleSet[oldRule.String()]; !ok {
			removed = append(removed, oldRule)
		}
	}

	oldRuleSet := ruleSet(old)
	for _, newRule := range new {
		if _, ok := oldRuleSet[newRule.String()]; !ok {
			added = append(added, newRule)
		}
	}

	return
}

func ruleSet(rules []*route.Rule) map[string]struct{} {
	ruleSet := make(map[string]struct{})
	for _, rule := range rules {
		ruleSet[rule.String()] = struct{}{}
	}
	return ruleSet
}

func diffRoutes(old, new []*netlink.Route) (added, removed []*netlink.Route) {
	newRouteSet := routeSet(new)
	for _, oldRoute := range old {
		if _, ok := newRouteSet[oldRoute.String()]; !ok {
			removed = append(removed, oldRoute)
		}
	}

	oldRouteSet := routeSet(old)
	for _, newRoute := range new {
		if _, ok := oldRouteSet[newRoute.String()]; !ok {
			added = append(added, newRoute)
		}
	}

	return
}

func routeSet(routes []*netlink.Route) map[string]struct{} {
	routeSet := make(map[string]struct{})
	for _, route := range routes {
		routeSet[route.String()] = struct{}{}
	}
	return routeSet
}

type ciliumNodeENIRulesAndRoutesOptions struct {
	EgressMultiHomeIPRuleCompat bool
	EnableIPv4Masquerade        bool
}

// ciliumNodeENIRulesAndRoutes returns the rules and routes required to configure
func ciliumNodeENIRulesAndRoutes(node *ciliumv2.CiliumNode, macToNetlinkInterfaceIndex map[string]int, options ciliumNodeENIRulesAndRoutesOptions) (rules []*route.Rule, routes []*netlink.Route) {
	// Extract the used IPs by ENI from node.Status.IPAM.Used.
	ipsByResource := make(map[string][]net.IP)
	firstInterfaceIndex := *node.Spec.ENI.FirstInterfaceIndex
	for address, allocationIP := range node.Status.IPAM.Used {
		resource := allocationIP.Resource
		eni, ok := node.Status.ENI.ENIs[resource]
		if !ok {
			log.WithField(logfields.Resource, resource).Warning("Ignoring unknown resource")
			continue
		}
		if eni.Number < firstInterfaceIndex {
			continue
		}
		ip := net.ParseIP(address)
		if ip == nil {
			log.WithField(logfields.IPAddr, address).Warning("Ignoring non-IPv4 address")
			continue
		}
		ipsByResource[resource] = append(ipsByResource[resource], ip)
	}

	// Sort ENIs and IPs so the order of rules and routes is deterministic.
	resourcesByNumber := make([]string, 0, len(ipsByResource))
	for eni, ips := range ipsByResource {
		resourcesByNumber = append(resourcesByNumber, eni)
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) < 0
		})
	}
	sort.Slice(resourcesByNumber, func(i, j int) bool {
		return node.Status.ENI.ENIs[resourcesByNumber[i]].Number < node.Status.ENI.ENIs[resourcesByNumber[j]].Number
	})

	var egressPriority int
	if options.EgressMultiHomeIPRuleCompat {
		egressPriority = linux_defaults.RulePriorityEgress
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
	}

	for _, resource := range resourcesByNumber {
		eni := node.Status.ENI.ENIs[resource]

		netlinkInterfaceIndex, ok := macToNetlinkInterfaceIndex[eni.MAC]
		if !ok {
			log.WithFields(logrus.Fields{
				logfields.Resource: resource,
				logfields.MACAddr:  eni.MAC,
			}).Warning("Failed to retrieve netlink interface index")
			continue
		}

		gateway, err := subnetGatewayAddress(eni.Subnet)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Resource: resource,
				logfields.CIDR:     eni.Subnet,
			}).Warning("Failed to determine gateway address")
			continue
		}

		cidrs := make([]*cidr.CIDR, 0, len(eni.VPC.CIDRs))
		for _, cidrStr := range eni.VPC.CIDRs {
			cidr, err := cidr.ParseCIDR(cidrStr)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.Resource: resource,
					logfields.CIDR:     cidrStr,
				}).Warning("Failed to parse CIDR")
				continue
			}
			cidrs = append(cidrs, cidr)
		}

		var tableID int
		if options.EgressMultiHomeIPRuleCompat {
			tableID = netlinkInterfaceIndex
		} else {
			tableID = linuxrouting.ComputeTableIDFromIfaceNumber(eni.Number)
		}

		// Generate rules for each IPs.
		for _, ip := range ipsByResource[resource] {
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
				egressRules := make([]*route.Rule, 0, len(cidrs))
				for _, cidr := range cidrs {
					egressRule := &route.Rule{
						Priority: egressPriority,
						From:     &ipWithMask,
						To:       cidr.IPNet,
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

		// Generate routes.

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
	}

	return
}

// subnetGatewayAddress returns the address of the subnet's gateway.
func subnetGatewayAddress(subnet eniTypes.AwsSubnet) (net.IP, error) {
	subnetIP, _, err := net.ParseCIDR(subnet.CIDR)
	if err != nil {
		return nil, err
	}

	if subnetIP.To4() == nil {
		return nil, errNotAnIPv4Address
	}

	// The gateway for a subnet and VPC is always x.x.x.1, see
	// https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html.
	subnetIP[len(subnetIP)-1]++

	return subnetIP, nil
}
