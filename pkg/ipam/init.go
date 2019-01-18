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

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

var (
	log      = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam")
	ipamConf *Config
)

type ErrAllocation error

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

	link, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil || link == nil {
		log.WithError(err).Warnf("Unable to find net_device %s", defaults.HostDevice)
		return
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Warn("Unable to retrieve local routes")
		return
	}

	allocRange := node.GetIPv4AllocRange()

	for _, r := range routes {
		// ignore routes which point to defaults.HostDevice
		if r.LinkIndex == link.Attrs().Index {
			log.WithField("route", r).Debugf("Ignoring route: points to %s", defaults.HostDevice)
			continue
		}

		if r.Dst == nil {
			log.WithField("route", r).Debug("Ignoring route: no destination address")
			continue
		}

		log.WithField("route", logfields.Repr(r)).Debug("Considering route")

		if allocRange.Contains(r.Dst.IP) {
			log.WithFields(logrus.Fields{
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
func Init() {
	ipamSubnets := net.IPNet{
		IP:   node.GetIPv6Router(),
		Mask: defaults.StateIPv6Mask,
	}

	ipamConf = &Config{
		IPAMConfig: allocator.IPAMConfig{
			Name: "cilium-local-IPAM",
			Range: &allocator.Range{
				Subnet:  cniTypes.IPNet(ipamSubnets),
				Gateway: node.GetIPv6Router(),
			},
			Routes: []*cniTypes.Route{
				// IPv6
				{
					Dst: node.GetIPv6NodeRoute(),
				},
				{
					Dst: defaults.IPv6DefaultRoute,
					GW:  node.GetIPv6Router(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(node.GetIPv6AllocRange().IPNet),
	}

	// Since docker doesn't support IPv6 only and there's always an IPv4
	// address we can set up ipam for IPv4. More info:
	// https://github.com/docker/libnetwork/pull/826
	ipamConf.IPv4Allocator = ipallocator.NewCIDRRange(node.GetIPv4AllocRange().IPNet)
	ipamConf.IPAMConfig.Routes = append(ipamConf.IPAMConfig.Routes,
		// IPv4
		&cniTypes.Route{
			Dst: node.GetIPv4NodeRoute(),
		},
		&cniTypes.Route{
			Dst: defaults.IPv4DefaultRoute,
			GW:  node.GetInternalIPv4(),
		})
}

// AllocateInternalIPs allocates all non endpoint IPs in the CIDR required for
// operation. This mustbe called *after* endpoints have been restored to avoid
// allocation conflicts
func AllocateInternalIPs() error {
	// Reserve the IPv4 router IP if it is part of the IPv4
	// allocation range to ensure that we do not hand out the
	// router IP to a container.
	allocRange := node.GetIPv4AllocRange()
	nodeIP := node.GetExternalIPv4()
	if allocRange.Contains(nodeIP) {
		err := ipamConf.IPv4Allocator.Allocate(nodeIP)
		if err != nil {
			log.WithError(err).WithField(logfields.IPAddr, nodeIP).Debug("Unable to reserve IPv4 router address")
		}
	}

	internalIP := node.GetInternalIPv4()
	if internalIP == nil {
		internalIP = ip.GetNextIP(node.GetIPv4AllocRange().IP)
	}
	err := ipamConf.IPv4Allocator.Allocate(internalIP)
	if err != nil {
		// If the allocation fails here it is likely that, in a kubernetes
		// environment, cilium was not able to retrieve the node's pod-cidr
		// which will cause cilium to start with a default IPv4 allocation range
		// different from the previous running instance.
		// Since defaults.HostDevice IP is always automatically derived from the
		// IPv4 allocation range it is safe to assume defaults.HostDevice IP
		// will always belong to the IPv4AllocationRange.
		// Unless of course the user manually specifies a different IPv4range
		// between restarts which he can only solve by deleting the IPv4
		// address from defaults.HostDevice as well deleting the node_config.h.
		return ErrAllocation(fmt.Errorf("Unable to allocate internal IPv4 node IP %s: %s.",
			internalIP, err))
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
				log.WithError(err).WithField(logfields.IPAddr, ip6).Debug("Unable to reserve IPv6 address")
			}
		}
	}

	routerIP := node.GetIPv6Router()
	if routerIP == nil {
		routerIP = ip.GetNextIP(node.GetIPv6AllocRange().IP)
	}
	if !routerIP.Equal(node.GetIPv6()) {
		err = ipamConf.IPv6Allocator.Allocate(routerIP)
		if err != nil {
			return ErrAllocation(fmt.Errorf("Unable to allocate internal IPv6 router IP %s: %s.",
				routerIP, err))
		}
	}
	node.SetIPv6Router(routerIP)

	return nil
}
