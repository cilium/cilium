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
	"time"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var errNotAnIPv4Address = errors.New("not an IPv4 address")

type linkMap map[string]netlink.Link // by MAC addr

func updateENIRulesAndRoutes(oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration) error {
	eniByName := newNode.Status.ENI.ENIs
	expectedENIByMac := make(map[string]string)
	firstInterfaceIndex := *newNode.Spec.ENI.FirstInterfaceIndex
	for name, eni := range eniByName {
		if eni.Number < firstInterfaceIndex {
			continue
		}
		expectedENIByMac[eni.MAC] = name
	}

	// Wait for the interfaces to be attached to the local node
	eniLinkByMac, err := waitForNetlinkDevices(expectedENIByMac)
	if err != nil {
		attachedENIByMac := make(map[string]string, len(eniLinkByMac))
		for mac, link := range eniLinkByMac {
			attachedENIByMac[mac] = link.Attrs().Name
		}

		log.WithError(err).WithFields(logrus.Fields{
			logfields.AttachedENIs: attachedENIByMac,
			logfields.ExpectedENIs: expectedENIByMac,
		}).Warning("Timed out waiting for ENIs to be attached")
		return err
	}

	addedResources, removedResources := diffResources(oldNode, newNode)

	// Configure new interfaces.
	for _, addedResource := range addedResources {
		eni := newNode.Status.ENI.ENIs[addedResource]
		if eni.Number < firstInterfaceIndex {
			continue
		}

		err = configureENINetlinkDevice(eniLinkByMac[eni.MAC], eni.IP, eni.Subnet.CIDR, mtuConfig.GetDeviceMTU())
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Resource:  addedResource,
				logfields.Interface: eni.Number,
				logfields.MACAddr:   eni.MAC,
			}).Error("Failed to set primary IP address of ENI interface")
		}
	}

	// Ignore removed interfaces for now.
	_ = removedResources

	options := linuxrouting.ComputeRulesAndRoutesOptions{
		EgressMultiHomeIPRuleCompat: option.Config.EgressMultiHomeIPRuleCompat,
		EnableIPv4Masquerade:        option.Config.EnableIPv4Masquerade,
	}
	oldRules, oldRoutes := ciliumNodeENIRulesAndRoutes(oldNode, eniLinkByMac, options)
	newRules, newRoutes := ciliumNodeENIRulesAndRoutes(newNode, eniLinkByMac, options)
	addedRules, removedRules := diffRules(oldRules, newRules)
	addedRoutes, removedRoutes := diffRoutes(oldRoutes, newRoutes)

	// Add and remove rules and routes. This has to succeed so we retry
	// multiple times.
	maxTries := 3
	rulesToAdd, rulesToRemove := addedRules, removedRules
	routesToAdd, routesToRemove := addedRoutes, removedRoutes
	var failedAddRules, failedRemoveRules []*route.Rule
	var failedAddRoutes, failedRemoveRoutes []*netlink.Route
	for try := 0; try < maxTries; try++ {
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
		return fmt.Errorf("adding and removing %d rules and routes failed after %d tries", failures, maxTries)
	}

	return nil
}

const (
	waitForNetlinkDevicesMaxRetries    = 20
	waitForNetlinkDevicesRetryInterval = 250 * time.Millisecond
)

func waitForNetlinkDevices(requiredENINameByMac map[string]string) (linkByMac linkMap, err error) {
	for try := 0; try < waitForNetlinkDevicesMaxRetries; try++ {
		links, err := netlink.LinkList()
		if err != nil {
			return nil, fmt.Errorf("failed to obtain eni link list: %w", err)
		}

		linkByMac = linkMap{}
		for _, link := range links {
			mac := link.Attrs().HardwareAddr.String()
			if _, ok := requiredENINameByMac[mac]; ok {
				linkByMac[mac] = link
			}
		}

		if len(linkByMac) == len(requiredENINameByMac) {
			return linkByMac, nil
		}

		time.Sleep(waitForNetlinkDevicesRetryInterval)
	}

	// we return the linkByMac also in the error case to allow for better logging
	return linkByMac, errors.New("timed out waiting for ENIs to be attached")
}

func configureENINetlinkDevice(link netlink.Link, eniIP, eniSubnetCIDR string, mtu int) error {
	ip := net.ParseIP(eniIP)
	if ip == nil {
		return fmt.Errorf("failed to eni primary ip %q", ip)
	}

	_, ipnet, err := net.ParseCIDR(eniSubnetCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse eni subnet cidr %q: %w", eniSubnetCIDR, err)
	}

	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("failed to change MTU of link %s to %d: %w", link.Attrs().Name, mtu, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to up link %s: %w", link.Attrs().Name, err)
	}

	// Set the primary IP in order for SNAT to work correctly on this ENI
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipnet.Mask,
		},
	})
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("failed to set eni primary ip address %q on link %q: %w", eniIP, link.Attrs().Name, err)
	}

	// Remove the the default route for this ENI, as it can overlap with the
	// default route of the primary ENI and therefore breaking node connectivity
	err = netlink.RouteDel(&netlink.Route{
		Dst:   ipnet,
		Src:   ip,
		Table: unix.RT_TABLE_MAIN,
		Scope: netlink.SCOPE_LINK,
	})
	if err != nil && !errors.Is(err, unix.ESRCH) {
		// We ignore ESRCH, as it means the entry was already deleted
		return fmt.Errorf("failed to delete default route %q on link %q: %w", eniIP, link.Attrs().Name, err)
	}

	return nil
}

func diffResources(old, new *ciliumv2.CiliumNode) (added, removed []string) {
	if old == nil {
		for newResource := range new.Status.ENI.ENIs {
			added = append(added, newResource)
		}
		return
	}

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
	ruleSet := make(map[string]struct{}, len(rules))
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
	routeSet := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		routeSet[route.String()] = struct{}{}
	}
	return routeSet
}

// ciliumNodeENIRulesAndRoutes returns the rules and routes required to configure
func ciliumNodeENIRulesAndRoutes(node *ciliumv2.CiliumNode, eniLinkByMac linkMap,
	options linuxrouting.ComputeRulesAndRoutesOptions) (rules []*route.Rule, routes []*netlink.Route) {
	if node == nil {
		return nil, nil
	}

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

	for _, resource := range resourcesByNumber {
		eni := node.Status.ENI.ENIs[resource]

		netlinkInterface, ok := eniLinkByMac[eni.MAC]
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

		ipNets := make([]net.IPNet, 0, len(eni.VPC.CIDRs))
		for _, cidrStr := range eni.VPC.CIDRs {
			cidr, err := cidr.ParseCIDR(cidrStr)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.Resource: resource,
					logfields.CIDR:     cidrStr,
				}).Warning("Failed to parse CIDR")
				continue
			}
			ipNets = append(ipNets, *cidr.IPNet)
		}
		sort.Slice(ipNets, func(i, j int) bool {
			return bytes.Compare(ipNets[i].IP, ipNets[j].IP) < 0
		})

		resourceRules, resourceRoutes := linuxrouting.ComputeRulesAndRoutes(
			ipsByResource[resource],
			ipNets,
			netlinkInterface.Attrs().Index,
			eni.Number,
			gateway,
			options,
		)
		rules = append(rules, resourceRules...)
		routes = append(routes, resourceRoutes...)
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
