// Copyright 2017-2020 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
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

// Configuration is the configuration passed into the IPAM subsystem
type Configuration interface {
	// IPv4Enabled must return true when IPv4 is enabled
	IPv4Enabled() bool

	// IPv6 must return true when IPv6 is enabled
	IPv6Enabled() bool

	// IPAMMode returns the IPAM mode
	IPAMMode() string

	// HealthCheckingEnabled must return true when health-checking is
	// enabled
	HealthCheckingEnabled() bool

	// BlacklistConflictingRoutesEnabled must return true when blacklisting
	// of conflicting IPs is enabled
	BlacklistConflictingRoutesEnabled() bool

	// SetIPv4NativeRoutingCIDR is called by the IPAM module to announce
	// the native IPv4 routing CIDR if it exists
	SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR)

	// IPv4NativeRoutingCIDR is called by the IPAM module retrieve
	// the native IPv4 routing CIDR if it exists
	IPv4NativeRoutingCIDR() *cidr.CIDR
}

// Owner is the interface the owner of an IPAM allocator has to implement
type Owner interface {
	// UpdateCiliumNodeResource is called to create/update the CiliumNode
	// resource. The function must block until the custom resource has been
	// created.
	UpdateCiliumNodeResource()
}

type K8sEventRegister interface {
	// K8sEventReceived is called to do metrics accounting for received
	// Kubernetes events
	K8sEventReceived(scope string, action string, valid, equal bool)

	// K8sEventProcessed is called to do metrics accounting for each processed
	// Kubernetes event
	K8sEventProcessed(scope string, action string, status bool)
}

// NewIPAM returns a new IP address manager
func NewIPAM(nodeAddressing datapath.NodeAddressing, c Configuration, owner Owner, k8sEventReg K8sEventRegister) *IPAM {
	ipam := &IPAM{
		nodeAddressing:   nodeAddressing,
		config:           c,
		owner:            map[string]string{},
		expirationTimers: map[string]string{},
		blacklist: IPBlacklist{
			ips: map[string]string{},
		},
	}

	switch c.IPAMMode() {
	case ipamOption.IPAMHostScopeLegacy, ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool:
		log.WithFields(logrus.Fields{
			logfields.V4Prefix: nodeAddressing.IPv4().AllocationCIDR(),
			logfields.V6Prefix: nodeAddressing.IPv6().AllocationCIDR(),
		}).Infof("Initializing %s IPAM", c.IPAMMode())

		if c.IPv6Enabled() {
			ipam.IPv6Allocator = newHostScopeAllocator(nodeAddressing.IPv6().AllocationCIDR().IPNet)
		}

		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newHostScopeAllocator(nodeAddressing.IPv4().AllocationCIDR().IPNet)
		}
	case ipamOption.IPAMCRD, ipamOption.IPAMENI, ipamOption.IPAMAzure:
		log.Info("Initializing CRD-based IPAM")
		if c.IPv6Enabled() {
			ipam.IPv6Allocator = newCRDAllocator(IPv6, c, owner, k8sEventReg)
		}

		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newCRDAllocator(IPv4, c, owner, k8sEventReg)
		}
	default:
		log.Fatalf("Unknown IPAM backend %s", c.IPAMMode())
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

// ReserveLocalRoutes walks through local routes/subnets and reserves them in
// the allocator pool in case of overlap
func (ipam *IPAM) ReserveLocalRoutes() {
	if !ipam.config.BlacklistConflictingRoutesEnabled() {
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
