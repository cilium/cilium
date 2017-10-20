// Copyright 2017 Authors of Cilium
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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/node"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

var (
	ipamConf *Config
)

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func reserveLocalRoutes(ipam *Config) {
	log.Debugf("Checking local routes for conflicts...")

	link, err := netlink.LinkByName("cilium_host")
	if err != nil || link == nil {
		log.Warningf("Unable to find net_device cilium_host: %s", err)
		return
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		log.Warningf("Unable to retrieve local routes: %s", err)
		return
	}

	allocRange := node.GetIPv4AllocRange()

	for _, r := range routes {
		// ignore routes which point to cilium_host
		if r.LinkIndex == link.Attrs().Index {
			log.Debugf("Ignoring route %v: points to cilium_host", r)
			continue
		}

		if r.Dst == nil {
			log.Debugf("Ignoring route %v: no destination address", r)
			continue
		}

		log.Debugf("Considering route %v", r)

		if allocRange.Contains(r.Dst.IP) {
			log.Infof("Marking local route %s as no-alloc in node allocation prefix %s", r.Dst, allocRange)
			for ip := r.Dst.IP.Mask(r.Dst.Mask); r.Dst.Contains(ip); nextIP(ip) {
				ipam.IPv4Allocator.Allocate(ip)
			}
		}
	}
}

// ReserveLocalRoutes walks through local routes/subnets and reserves them in
// the allocator pool in case of overlap
func ReserveLocalRoutes() {
	reserveLocalRoutes(ipamConf)
}

// Init initializes the IPAM package
func Init() error {
	ipamSubnets := net.IPNet{
		IP:   node.GetIPv6Router(),
		Mask: node.StateIPv6Mask,
	}

	ipamConf = &Config{
		IPAMConfig: allocator.IPAMConfig{
			Name:    "cilium-local-IPAM",
			Subnet:  cniTypes.IPNet(ipamSubnets),
			Gateway: node.GetIPv6Router(),
			Routes: []cniTypes.Route{
				// IPv6
				{
					Dst: node.GetIPv6NodeRoute(),
				},
				{
					Dst: node.IPv6DefaultRoute,
					GW:  node.GetIPv6Router(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(node.GetIPv6AllocRange()),
	}

	// Since docker doesn't support IPv6 only and there's always an IPv4
	// address we can set up ipam for IPv4. More info:
	// https://github.com/docker/libnetwork/pull/826
	ipamConf.IPv4Allocator = ipallocator.NewCIDRRange(node.GetIPv4AllocRange())
	ipamConf.IPAMConfig.Routes = append(ipamConf.IPAMConfig.Routes,
		// IPv4
		cniTypes.Route{
			Dst: node.GetIPv4NodeRoute(),
		},
		cniTypes.Route{
			Dst: node.IPv4DefaultRoute,
			GW:  node.GetInternalIPv4(),
		})

	// Reserve the IPv4 router IP if it is part of the IPv4
	// allocation range to ensure that we do not hand out the
	// router IP to a container.
	allocRange := node.GetIPv4AllocRange()
	nodeIP := node.GetExternalIPv4()
	if allocRange.Contains(nodeIP) {
		err := ipamConf.IPv4Allocator.Allocate(nodeIP)
		if err != nil {
			log.Debugf("Unable to reserve IPv4 router address '%s': %s",
				nodeIP, err)
		}
	}

	internalIP, err := ipamConf.IPv4Allocator.AllocateNext()
	if err != nil {
		return fmt.Errorf("Unable to allocate internal IPv4 node IP: %s", err)
	}

	node.SetInternalIPv4(internalIP)

	// Reserve the IPv6 router and node IP if it is part of the IPv6
	// allocation range to ensure that we do not hand out the router IP to
	// a container.
	allocRange = node.GetIPv6AllocRange()
	for _, ip6 := range []net.IP{node.GetIPv6()} {
		if allocRange.Contains(ip6) {
			err := ipamConf.IPv6Allocator.Allocate(ip6)
			if err != nil {
				log.Debugf("Unable to reserve IPv6 address '%s': %s",
					ip6, err)
			}
		}
	}

	routerIP, err := ipamConf.IPv6Allocator.AllocateNext()
	if err != nil {
		return fmt.Errorf("Unable to allocate IPv6 router IP: %s", err)
	}

	node.SetIPv6Router(routerIP)

	return nil
}
