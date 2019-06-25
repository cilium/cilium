// Copyright 2019 Authors of Cilium
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

package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
)

func prepareENI(mac string, mtu int) (index int, err error) {
	var links []netlink.Link

	mac = strings.ToLower(mac)

	links, err = netlink.LinkList()
	if err != nil {
		err = fmt.Errorf("unable to list interfaces: %s", err)
		return
	}

	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == mac {
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

func eniAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf models.DaemonConfigurationStatus) error {
	for _, cidrString := range ipam.Cidrs {
		_, _, err := net.ParseCIDR(cidrString)
		if err != nil {
			return fmt.Errorf("invalid CIDR '%s': %s", cidrString, err)
		}
	}

	if ipam.MasterMac == "" {
		return fmt.Errorf("ENI master interface MAC address is not set")
	}

	ifindex, err := prepareENI(ipam.MasterMac, int(conf.DeviceMTU))
	if err != nil {
		return err
	}

	gatewayIP := net.ParseIP(ipam.Gateway)
	if gatewayIP == nil {
		return fmt.Errorf("unable to parse gateway IP %s", ipam.Gateway)
	}

	// Route all traffic to the ENI address via the main routing table
	if err := route.ReplaceRule(route.Rule{
		Priority: 20, // After encryption and proxy rules, before local table
		To:       &ipConfig.Address,
		Table:    route.MainTable,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %s", err)
	}

	if conf.Masquerade {
		for _, cidrString := range ipam.Cidrs {
			// The cidr string is already verified, this can't fail
			_, cidr, _ := net.ParseCIDR(cidrString)

			// Lookup a VPC specific table for all traffic from an endpoint
			// to the list of CIDRs configured for the VPC on which the
			// endpoint has the IP on
			if err := route.ReplaceRule(route.Rule{
				Priority: 110, // After local table
				From:     &ipConfig.Address,
				To:       cidr,
				Table:    ifindex,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %s", err)
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint
		if err := route.ReplaceRule(route.Rule{
			Priority: 110, // After local table
			From:     &ipConfig.Address,
			Table:    ifindex,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule: %s", err)
		}
	}

	// Nexthop route to the VPC or subnet gateway
	//
	// Note: This is a /32 route to avoid any L2. The endpoint does
	// no L2 either.
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: gatewayIP, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
		Table:     ifindex,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table: ifindex,
		Gw:    gatewayIP,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	return nil
}
