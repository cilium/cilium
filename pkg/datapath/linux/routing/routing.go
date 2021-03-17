// Copyright 2020 Authors of Cilium
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
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

	ifindex, err := RetrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
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
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %s", err)
	}

	var egressPriority, tableID int
	if compat {
		egressPriority = linux_defaults.RulePriorityEgress
		tableID = ifindex
	} else {
		egressPriority = linux_defaults.RulePriorityEgressv2
		tableID = ComputeTableIDFromIfaceNumber(info.InterfaceNumber)
	}

	if info.Masquerade {
		// Lookup a VPC specific table for all traffic from an endpoint to the
		// CIDR configured for the VPC on which the endpoint has the IP on.
		for _, cidr := range info.IPv4CIDRs {
			if err := route.ReplaceRule(route.Rule{
				Priority: egressPriority,
				From:     &ipWithMask,
				To:       &cidr,
				Table:    tableID,
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
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table: tableID,
		Gw:    info.IPv4Gateway,
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
// main routing table. Deletion of both rules only proceeds if one rule matches
// the IP & priority. If more than one rule match, then deletion is skipped.
func Delete(ip net.IP, compat bool) error {
	if ip.To4() == nil {
		log.WithFields(logrus.Fields{
			"endpointIP": ip,
		}).Warning("Unable to delete rules because IP is not an IPv4 address")
		return errors.New("IP not compatible")
	}
	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}

	scopedLog := log.WithFields(logrus.Fields{
		"ip": ipWithMask.String(),
	})

	// Ingress rules
	ingress := route.Rule{
		Priority: linux_defaults.RulePriorityIngress,
		To:       &ipWithMask,
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
	egress := route.Rule{
		Priority: priority,
		From:     &ipWithMask,
	}
	if err := deleteRule(egress); err != nil {
		return fmt.Errorf("unable to delete egress rule with ip %s: %v", ipWithMask.String(), err)
	}

	scopedLog.WithField("rule", egress).Debug("Deleted egress rule")

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
		tableId = ComputeTableIDFromIfaceNumber(ifaceNum)
	}
	return route.ReplaceRule(route.Rule{
		Priority: prio,
		From:     from,
		To:       to,
		Table:    tableId,
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
		return route.DeleteRule(r)
	}

	log.WithFields(logrus.Fields{
		"rule": r,
	}).Warning("No rule matching found")

	return errors.New("no rule found to delete")
}

// RetrieveIfIndexFromMAC finds the corresponding device index (ifindex) for a
// given MAC address. This is useful for creating rules and routes in order to
// specify the table. When the ifindex is found, the device is brought up and
// its MTU is set.
func RetrieveIfIndexFromMAC(mac mac.MAC, mtu int) (index int, err error) {
	var links []netlink.Link

	links, err = netlink.LinkList()
	if err != nil {
		err = fmt.Errorf("unable to list interfaces: %s", err)
		return
	}

	for _, link := range links {
		fmt.Printf("%q == %q: %t", link.Attrs().HardwareAddr.String(), mac.String(), link.Attrs().HardwareAddr.String() == mac.String())
		if link.Attrs().HardwareAddr.String() == mac.String() {
			index = link.Attrs().Index

			if err = netlink.LinkSetMTU(link, mtu); err != nil {
				err = fmt.Errorf("unable to change MTU of link %s to %d: %s", link.Attrs().Name, mtu, err)
				return
			}

			if err = netlink.LinkSetUp(link); err != nil {
				err = fmt.Errorf("unable to up link %s: %s", link.Attrs().Name, err)
				return
			}

			return
		}
	}

	err = fmt.Errorf("interface with MAC %s not found", mac)
	return
}

// ComputeTableIDFromIfaceNumber returns a computed per-ENI route table ID for the given
// ENI interface number.
func ComputeTableIDFromIfaceNumber(num int) int {
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
