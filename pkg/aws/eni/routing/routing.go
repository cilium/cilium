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

package enirouting

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/mac"

	"github.com/vishvananda/netlink"
)

// RoutingInfo represents information that's required to enable
// connectivity via the local rule and route tables while in ENI mode. The
// information in this struct is used to create rules and routes which direct
// traffic out of the ENI devices (egress).
//
// This struct is mostly derived from the `ipam.AllocationResult` as the
// information comes from IPAM.
type RoutingInfo struct {
	// IPv4Gateway is the gateway where outbound/egress traffic is directed.
	IPv4Gateway net.IP

	// IPv4CIDRs is a list of CIDRs which the ENI device has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	IPv4CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the ENI itself which
	// corresponds to the IPv4Gateway IP addr.
	MasterIfMAC mac.MAC
}

// Install sets up the rules and routes needed when running in ENI mode. These
// rules and routes direct egress traffic out of the ENI device and ingress
// traffic back to the endpoint (`ip`).
//
// ip: The endpoint IP address to direct traffic out / from ENI device.
// info: The ENI device routing info used to create rules and routes.
// mtu: The ENI device MTU.
// masq: Whether masquerading is enabled.
func Install(ip net.IP, info *RoutingInfo, mtu int, masq bool) error {
	ifindex, err := retrieveIfIndexFromMAC(info.MasterIfMAC, mtu)
	if err != nil {
		return fmt.Errorf("unable to find ifindex for interface MAC: %s", err)
	}

	ipWithMask := net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}

	// Route all traffic to the ENI address via the main routing table
	if err := route.ReplaceRule(route.Rule{
		Priority: 20, // After encryption and proxy rules, before local table
		To:       &ipWithMask,
		Table:    route.MainTable,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule: %s", err)
	}

	if masq {
		// Lookup a VPC specific table for all traffic from an endpoint to the
		// CIDR configured for the VPC on which the endpoint has the IP on.
		for _, cidr := range info.IPv4CIDRs {
			if err := route.ReplaceRule(route.Rule{
				Priority: 110, // After local table
				From:     &ipWithMask,
				To:       &cidr,
				Table:    ifindex,
			}); err != nil {
				return fmt.Errorf("unable to install ip rule: %s", err)
			}
		}
	} else {
		// Lookup a VPC specific table for all traffic from an endpoint.
		if err := route.ReplaceRule(route.Rule{
			Priority: 110, // After local table
			From:     &ipWithMask,
			Table:    ifindex,
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
		Table:     ifindex,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	// Default route to the VPC or subnet gateway
	if err := netlink.RouteReplace(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table: ifindex,
		Gw:    info.IPv4Gateway,
	}); err != nil {
		return fmt.Errorf("unable to add L2 nexthop route: %s", err)
	}

	return nil
}

// retrieveIfIndexFromMAC finds the corresponding device index (ifindex) for a
// given MAC address. This is useful for creating rules and routes in order to
// specify the table. When the ifindex is found, the device is brought up and
// its MTU is set.
func retrieveIfIndexFromMAC(mac mac.MAC, mtu int) (index int, err error) {
	var links []netlink.Link

	links, err = netlink.LinkList()
	if err != nil {
		err = fmt.Errorf("unable to list interfaces: %s", err)
		return
	}

	for _, link := range links {
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
