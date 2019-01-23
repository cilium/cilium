// Copyright 2017-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam")
)

type ErrAllocation error

// Family is the type describing all address families support by the IP
// allocation manager
type Family string

const (
	IPv6 Family = "ipv6"
	IPv4 Family = "ipv4"
)

// Configuration is the configuration of an IP address manager
type Configuration struct {
	EnableIPv4 bool
	EnableIPv6 bool
}

// NewIPAM returns a new IP address manager
func NewIPAM(nodeAddressing datapath.NodeAddressing, c Configuration) *IPAM {
	ipam := &IPAM{
		nodeAddressing: nodeAddressing,
		config:         c,
	}

	if c.EnableIPv6 {
		ipam.IPv6Allocator = ipallocator.NewCIDRRange(nodeAddressing.IPv6().AllocationCIDR().IPNet)
	}

	if c.EnableIPv4 {
		ipam.IPv4Allocator = ipallocator.NewCIDRRange(nodeAddressing.IPv4().AllocationCIDR().IPNet)
	}

	return ipam
}

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (ipam *IPAM) reserveLocalRoutes() {
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

	allocRange := ipam.nodeAddressing.IPv4().AllocationCIDR()

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
func (ipam *IPAM) ReserveLocalRoutes() {
	if ipam.IPv4Allocator != nil {
		ipam.reserveLocalRoutes()
	}
}

// AllocateInternalIPs allocates all non endpoint IPs in the CIDR required for
// operation. This mustbe called *after* endpoints have been restored to avoid
// allocation conflicts
func (ipam *IPAM) AllocateInternalIPs() error {
	if ipam.IPv4Allocator != nil {
		// Reserve the IPv4 router IP if it is part of the IPv4
		// allocation range to ensure that we do not hand out the
		// router IP to a container.
		allocRange := ipam.nodeAddressing.IPv4().AllocationCIDR()
		nodeIP := ipam.nodeAddressing.IPv4().PrimaryExternal()
		if allocRange.Contains(nodeIP) {
			err := ipam.IPv4Allocator.Allocate(nodeIP)
			if err != nil {
				log.WithError(err).WithField(logfields.IPAddr, nodeIP).Debug("Unable to reserve IPv4 router address")
			}
		}

		internalIP := ipam.nodeAddressing.IPv4().Router()
		if internalIP == nil {
			internalIP = ip.GetNextIP(ipam.nodeAddressing.IPv4().AllocationCIDR().IP)
		}
		err := ipam.IPv4Allocator.Allocate(internalIP)
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
	}

	if ipam.IPv6Allocator != nil {
		// Reserve the IPv6 router and node IP if it is part of the IPv6
		// allocation range to ensure that we do not hand out the router IP to
		// a container.
		allocRange := ipam.nodeAddressing.IPv6().AllocationCIDR()
		nodeIP := ipam.nodeAddressing.IPv6().PrimaryExternal()
		for _, ip6 := range []net.IP{nodeIP} {
			if allocRange.Contains(ip6) {
				err := ipam.IPv6Allocator.Allocate(ip6)
				if err != nil {
					log.WithError(err).WithField(logfields.IPAddr, ip6).Debug("Unable to reserve IPv6 address")
				}
			}

			routerIP := ipam.nodeAddressing.IPv6().Router()
			if routerIP == nil {
				routerIP = ip.GetNextIP(ipam.nodeAddressing.IPv6().AllocationCIDR().IP)
			}
			if !routerIP.Equal(nodeIP) {
				err := ipam.IPv6Allocator.Allocate(routerIP)
				if err != nil {
					return ErrAllocation(fmt.Errorf("Unable to allocate internal IPv6 router IP %s: %s.",
						routerIP, err))
				}
				node.SetIPv6Router(routerIP)
			}
		}
	}

	return nil
}
