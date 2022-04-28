// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	// UnreachableRoutesEnabled returns true when unreachable-routes is
	// enabled
	UnreachableRoutesEnabled() bool

	// SetIPv4NativeRoutingCIDR is called by the IPAM module to announce
	// the native IPv4 routing CIDR if it exists
	SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR)

	// IPv4NativeRoutingCIDR is called by the IPAM module retrieve
	// the native IPv4 routing CIDR if it exists
	GetIPv4NativeRoutingCIDR() *cidr.CIDR
}

// Owner is the interface the owner of an IPAM allocator has to implement
type Owner interface {
	// UpdateCiliumNodeResource is called to create/update the CiliumNode
	// resource. The function must block until the custom resource has been
	// created.
	UpdateCiliumNodeResource()

	// LocalAllocCIDRsUpdated informs the agent that the local allocation CIDRs have
	// changed.
	LocalAllocCIDRsUpdated(ipv4AllocCIDRs, ipv6AllocCIDRs []*cidr.CIDR)
}

type K8sEventRegister interface {
	// K8sEventReceived is called to do metrics accounting for received
	// Kubernetes events
	K8sEventReceived(scope string, action string, valid, equal bool)

	// K8sEventProcessed is called to do metrics accounting for each processed
	// Kubernetes event
	K8sEventProcessed(scope string, action string, status bool)

	// RegisterCiliumNodeSubscriber allows registration of subscriber.CiliumNode
	// implementations. Events for all CiliumNode events (not just the local one)
	// will be sent to the subscriber.
	RegisterCiliumNodeSubscriber(s subscriber.CiliumNode)
}

type MtuConfiguration interface {
	GetDeviceMTU() int
}

// NewIPAM returns a new IP address manager
func NewIPAM(nodeAddressing types.NodeAddressing, c Configuration, owner Owner, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration) *IPAM {
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
	case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool:
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
	case ipamOption.IPAMClusterPoolV2:
		log.Info("Initializing ClusterPool v2 IPAM")

		if c.IPv6Enabled() {
			ipam.IPv6Allocator = newClusterPoolAllocator(IPv6, c, owner, k8sEventReg)
		}
		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newClusterPoolAllocator(IPv4, c, owner, k8sEventReg)
		}
	case ipamOption.IPAMCRD, ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
		log.Info("Initializing CRD-based IPAM")
		if c.IPv6Enabled() {
			ipam.IPv6Allocator = newCRDAllocator(IPv6, c, owner, k8sEventReg, mtuConfig)
		}

		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newCRDAllocator(IPv4, c, owner, k8sEventReg, mtuConfig)
		}
	case ipamOption.IPAMDelegatedPlugin:
		log.Info("Initializing no-op IPAM since we're using a CNI delegated plugin")
		if c.IPv6Enabled() {
			ipam.IPv6Allocator = &noOpAllocator{}
		}
		if c.IPv4Enabled() {
			ipam.IPv4Allocator = &noOpAllocator{}
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

// BlacklistIP ensures that a certain IP is never allocated. It is preferred to
// use BlacklistIP() instead of allocating the IP as the allocation block can
// change and suddenly cover the IP to be blacklisted.
func (ipam *IPAM) BlacklistIP(ip net.IP, owner string) {
	ipam.allocatorMutex.Lock()
	ipam.blacklist.ips[ip.String()] = owner
	ipam.allocatorMutex.Unlock()
}
