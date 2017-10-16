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

	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/nodeaddress"

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
	log.Debug("Checking local routes for conflicts...")

	link, err := netlink.LinkByName("cilium_host")
	if err != nil || link == nil {
		log.WithError(err).Fatal("Unable to find net_device cilium_host")
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Warn("Unable to retrieve local routes")
		return
	}

	allocRange := nodeaddress.GetIPv4AllocRange()

	for _, r := range routes {
		// ignore routes which point to cilium_host
		if r.LinkIndex == link.Attrs().Index {
			log.WithField("route", r).Debug("Ignoring route: points to cilium_host")
			continue
		}

		if r.Dst == nil {
			log.WithField("route", r).Debug("Ignoring route: no destination address")
			continue
		}

		log.WithField("route", logfields.Repr(r)).Debug("Considering route")

		if allocRange.Contains(r.Dst.IP) {
			log.WithFields(log.Fields{
				"route":            r.Dst,
				logfields.V4Prefix: allocRange,
			}).Info("Marking local route as no-alloc in node allocation prefix")

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
		IP:   nodeaddress.GetIPv6Router(),
		Mask: nodeaddress.StateIPv6Mask,
	}

	ipamConf = &Config{
		IPAMConfig: allocator.IPAMConfig{
			Name:    "cilium-local-IPAM",
			Subnet:  cniTypes.IPNet(ipamSubnets),
			Gateway: nodeaddress.GetIPv6Router(),
			Routes: []cniTypes.Route{
				// IPv6
				{
					Dst: nodeaddress.GetIPv6NodeRoute(),
				},
				{
					Dst: nodeaddress.IPv6DefaultRoute,
					GW:  nodeaddress.GetIPv6Router(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(nodeaddress.GetIPv6AllocRange()),
	}

	// Since docker doesn't support IPv6 only and there's always an IPv4
	// address we can set up ipam for IPv4. More info:
	// https://github.com/docker/libnetwork/pull/826
	ipamConf.IPv4Allocator = ipallocator.NewCIDRRange(nodeaddress.GetIPv4AllocRange())
	ipamConf.IPAMConfig.Routes = append(ipamConf.IPAMConfig.Routes,
		// IPv4
		cniTypes.Route{
			Dst: nodeaddress.GetIPv4NodeRoute(),
		},
		cniTypes.Route{
			Dst: nodeaddress.IPv4DefaultRoute,
			GW:  nodeaddress.GetInternalIPv4(),
		})

	// Reserve the IPv4 router IP if it is part of the IPv4
	// allocation range to ensure that we do not hand out the
	// router IP to a container.
	allocRange := nodeaddress.GetIPv4AllocRange()
	nodeIP := nodeaddress.GetExternalIPv4()
	if allocRange.Contains(nodeIP) {
		err := ipamConf.IPv4Allocator.Allocate(nodeIP)
		if err != nil {
			log.WithError(err).WithField(logfields.IPAddr, nodeIP).Debug("Unable to reserve IPv4 router address")
		}
	}

	internalIP, err := ipamConf.IPv4Allocator.AllocateNext()
	if err != nil {
		return fmt.Errorf("Unable to allocate internal IPv4 node IP: %s", err)
	}

	nodeaddress.SetInternalIPv4(internalIP)

	// Reserve the IPv6 router and node IP if it is part of the IPv6
	// allocation range to ensure that we do not hand out the router IP to
	// a container.
	allocRange = nodeaddress.GetIPv6AllocRange()
	for _, ip6 := range []net.IP{nodeaddress.GetIPv6()} {
		if allocRange.Contains(ip6) {
			err := ipamConf.IPv6Allocator.Allocate(ip6)
			if err != nil {
				log.WithError(err).WithField(logfields.IPAddr, ip6).Debug("Unable to reserve IPv6 address")
			}
		}
	}

	routerIP, err := ipamConf.IPv6Allocator.AllocateNext()
	if err != nil {
		return fmt.Errorf("Unable to allocate IPv6 router IP: %s", err)
	}

	nodeaddress.SetIPv6Router(routerIP)

	return nil
}
