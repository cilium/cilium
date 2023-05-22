// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
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

// K8sEventRegister is used to register and handle events as they are processed
// by K8s controllers.
type K8sEventRegister interface {
	// K8sEventReceived is called to do metrics accounting for received
	// Kubernetes events, as well as calculating timeouts for k8s watcher
	// cache sync.
	K8sEventReceived(apiGroupResourceName string, scope string, action string, valid, equal bool)

	// K8sEventProcessed is called to do metrics accounting for each processed
	// Kubernetes event.
	K8sEventProcessed(scope string, action string, status bool)

	// RegisterCiliumNodeSubscriber allows registration of subscriber.CiliumNode
	// implementations. Events for all CiliumNode events (not just the local one)
	// will be sent to the subscriber.
	RegisterCiliumNodeSubscriber(s subscriber.CiliumNode)
}

type MtuConfiguration interface {
	GetDeviceMTU() int
}

type Metadata interface {
	GetIPPoolForPod(owner string) (pool string, err error)
}

// NewIPAM returns a new IP address manager
func NewIPAM(nodeAddressing types.NodeAddressing, c Configuration, owner Owner, k8sEventReg K8sEventRegister, mtuConfig MtuConfiguration, clientset client.Clientset) *IPAM {
	ipam := &IPAM{
		nodeAddressing:   nodeAddressing,
		config:           c,
		owner:            map[Pool]map[string]string{},
		expirationTimers: map[string]string{},
		excludedIPs:      map[string]string{},
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
			ipam.IPv6Allocator = newClusterPoolAllocator(IPv6, c, owner, k8sEventReg, clientset)
		}
		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newClusterPoolAllocator(IPv4, c, owner, k8sEventReg, clientset)
		}
	case ipamOption.IPAMMultiPool:
		log.Info("Initializing MultiPool IPAM")
		manager := newMultiPoolManager(c, k8sEventReg, owner, clientset.CiliumV2().CiliumNodes())

		if c.IPv6Enabled() {
			ipam.IPv6Allocator = manager.Allocator(IPv6)
		}
		if c.IPv4Enabled() {
			ipam.IPv4Allocator = manager.Allocator(IPv4)
		}
	case ipamOption.IPAMCRD, ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
		log.Info("Initializing CRD-based IPAM")
		if c.IPv6Enabled() {
			ipam.IPv6Allocator = newCRDAllocator(IPv6, c, owner, clientset, k8sEventReg, mtuConfig)
		}

		if c.IPv4Enabled() {
			ipam.IPv4Allocator = newCRDAllocator(IPv4, c, owner, clientset, k8sEventReg, mtuConfig)
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

// WithMetadata sets an optional Metadata provider, which IPAM will use to
// determine what IPAM pool an IP owner should allocate its IP from
func (ipam *IPAM) WithMetadata(m Metadata) {
	ipam.metadata = m
}

// getIPOwner returns the owner for an IP in a particular pool or the empty
// string in case the pool or IP is not registered.
func (ipam *IPAM) getIPOwner(ip string, pool Pool) string {
	if p, ok := ipam.owner[pool]; ok {
		return p[ip]
	}
	return ""
}

// registerIPOwner registers a new owner for an IP in a particular pool.
func (ipam *IPAM) registerIPOwner(ip net.IP, owner string, pool Pool) {
	if _, ok := ipam.owner[pool]; !ok {
		ipam.owner[pool] = make(map[string]string)
	}
	ipam.owner[pool][ip.String()] = owner
}

// releaseIPOwner releases ip from pool and returns the previous owner.
func (ipam *IPAM) releaseIPOwner(ip net.IP, pool Pool) string {
	var owner string
	if m, ok := ipam.owner[pool]; ok {
		ipStr := ip.String()
		owner = m[ipStr]
		delete(m, ipStr)
		if len(m) == 0 {
			delete(ipam.owner, pool)
		}
	}
	return owner
}

// ExcludeIP ensures that a certain IP is never allocated. It is preferred to
// use this method instead of allocating the IP as the allocation block can
// change and suddenly cover the IP to be excluded.
func (ipam *IPAM) ExcludeIP(ip net.IP, owner string, pool Pool) {
	ipam.allocatorMutex.Lock()
	ipam.excludedIPs[pool.String()+":"+ip.String()] = owner
	ipam.allocatorMutex.Unlock()
}

// isIPExcluded is used to check if a particular IP is excluded from being allocated.
func (ipam *IPAM) isIPExcluded(ip net.IP, pool Pool) (string, bool) {
	owner, ok := ipam.excludedIPs[pool.String()+":"+ip.String()]
	return owner, ok
}

// PoolOrDefault returns the default pool if no pool is specified.
func PoolOrDefault(pool string) Pool {
	if pool == "" {
		return PoolDefault
	}
	return Pool(pool)
}
