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
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

// DeriveFamily derives the address family of an IP
func DeriveFamily(ip net.IP) Family {
	if ip.To4() == nil {
		return IPv6
	}
	return IPv4
}

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
		owner:          map[string]string{},
		blacklist: IPBlacklist{
			ips: map[string]string{},
		},
	}

	switch strings.ToLower(option.Config.IPAM) {
	case option.IPAMHostScope:
		log.WithFields(logrus.Fields{
			logfields.V4Prefix: nodeAddressing.IPv4().AllocationCIDR(),
			logfields.V6Prefix: nodeAddressing.IPv6().AllocationCIDR(),
		}).Info("Initializing hostscope IPAM")

		if c.EnableIPv6 {
			ipam.IPv6Allocator = newHostScopeAllocator(nodeAddressing.IPv6().AllocationCIDR().IPNet)
		}

		if c.EnableIPv4 {
			ipam.IPv4Allocator = newHostScopeAllocator(nodeAddressing.IPv4().AllocationCIDR().IPNet)
		}
	case option.IPAMCRD:
		log.Info("Initializing CRD-based IPAM")
		if c.EnableIPv6 {
			ipam.IPv6Allocator = newCRDAllocator(IPv6)
		}

		if c.EnableIPv4 {
			ipam.IPv4Allocator = newCRDAllocator(IPv4)
		}
	default:
		log.Fatalf("Unknown IPAM backend %s", option.Config.IPAM)
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

		// ignore black hole route
		if r.Src == nil && r.Gw == nil {
			log.WithField("route", r).Debugf("Ignoring route: black hole")
			continue
		}

		log.WithField("route", r.Dst).Info("Blacklisting local route as no-alloc")
		ipam.BlacklistIPNet(*r.Dst, "local route: "+r.Dst.String())
	}
}

// ReserveLocalRoutes walks through local routes/subnets and reserves them in
// the allocator pool in case of overlap
func (ipam *IPAM) ReserveLocalRoutes() {
	if !option.Config.BlacklistConflictingRoutes {
		return
	}

	if ipam.IPv4Allocator != nil {
		ipam.reserveLocalRoutes()
	}
}

// BlacklistIP ensures that a certain IP is never allocated. It is preferred to
// use BlacklistIP() instead of allocating the IP as the allocation block can
// change and suddenly cover the IP to be blacklisted.
func (ipam *IPAM) BlacklistIP(ip net.IP, owner string) {
	ipam.allocatorMutex.Lock()
	ipam.blacklist.ips[ip.String()] = owner
	ipam.allocatorMutex.Unlock()
}

// BlacklistIPNet ensures that a certain IPNetwork is never allocated, similar
// to BlacklistIP.
func (ipam *IPAM) BlacklistIPNet(ipNet net.IPNet, owner string) {
	ipam.allocatorMutex.Lock()
	ipam.blacklist.ipNets = append(ipam.blacklist.ipNets, &IPNetWithOwner{
		ipNet: ipNet,
		owner: owner,
	})
	ipam.allocatorMutex.Unlock()
}
