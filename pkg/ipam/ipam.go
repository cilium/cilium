// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"log/slog"
	"net"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

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

// Owner is the interface the owner of an IPAM allocator has to implement
type Owner interface {
	// UpdateCiliumNodeResource is called to create/update the CiliumNode
	// resource. The function must block until the custom resource has been
	// created.
	UpdateCiliumNodeResource()
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
}

type MtuConfiguration interface {
	GetDeviceMTU() int
}

type Metadata interface {
	GetIPPoolForPod(owner string, family Family) (pool string, err error)
}

// NewIPAM returns a new IP address manager
func NewIPAM(logger *slog.Logger, nodeAddressing types.NodeAddressing, c *option.DaemonConfig, nodeDiscovery Owner, localNodeStore *node.LocalNodeStore, k8sEventReg K8sEventRegister, node agentK8s.LocalCiliumNodeResource, mtuConfig MtuConfiguration, clientset client.Clientset, metadata Metadata, sysctl sysctl.Sysctl) *IPAM {
	return &IPAM{
		logger:           logger,
		nodeAddressing:   nodeAddressing,
		config:           c,
		owner:            map[Pool]map[string]string{},
		expirationTimers: map[timerKey]expirationTimer{},
		excludedIPs:      map[string]string{},

		k8sEventReg:    k8sEventReg,
		localNodeStore: localNodeStore,
		nodeResource:   node,
		mtuConfig:      mtuConfig,
		clientset:      clientset,
		nodeDiscovery:  nodeDiscovery,
		metadata:       metadata,
		sysctl:         sysctl,
	}
}

// ConfigureAllocator initializes the IPAM allocator according to the configuration.
// As a precondition, the NodeAddressing must be fully initialized - therefore the method
// must be called after Daemon.WaitForNodeInformation.
func (ipam *IPAM) ConfigureAllocator() {
	switch ipam.config.IPAMMode() {
	case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool:
		ipam.logger.Info(
			"Initializing IPAM",
			logfields.Mode, ipam.config.IPAMMode(),
			logfields.V4Prefix, ipam.nodeAddressing.IPv4().AllocationCIDR(),
			logfields.V6Prefix, ipam.nodeAddressing.IPv6().AllocationCIDR(),
		)

		if ipam.config.IPv6Enabled() {
			ipam.IPv6Allocator = newHostScopeAllocator(ipam.nodeAddressing.IPv6().AllocationCIDR().IPNet)
		}

		if ipam.config.IPv4Enabled() {
			ipam.IPv4Allocator = newHostScopeAllocator(ipam.nodeAddressing.IPv4().AllocationCIDR().IPNet)
		}
	case ipamOption.IPAMMultiPool:
		ipam.logger.Info("Initializing MultiPool IPAM")
		manager := newMultiPoolManager(ipam.logger, ipam.config, ipam.nodeResource, ipam.nodeDiscovery, ipam.clientset.CiliumV2().CiliumNodes())

		if ipam.config.IPv6Enabled() {
			ipam.IPv6Allocator = manager.Allocator(IPv6)
		}
		if ipam.config.IPv4Enabled() {
			ipam.IPv4Allocator = manager.Allocator(IPv4)
		}
	case ipamOption.IPAMCRD, ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
		ipam.logger.Info("Initializing CRD-based IPAM")
		if ipam.config.IPv6Enabled() {
			ipam.IPv6Allocator = newCRDAllocator(ipam.logger, IPv6, ipam.config, ipam.nodeDiscovery, ipam.localNodeStore, ipam.clientset, ipam.k8sEventReg, ipam.mtuConfig, ipam.sysctl)
		}

		if ipam.config.IPv4Enabled() {
			ipam.IPv4Allocator = newCRDAllocator(ipam.logger, IPv4, ipam.config, ipam.nodeDiscovery, ipam.localNodeStore, ipam.clientset, ipam.k8sEventReg, ipam.mtuConfig, ipam.sysctl)
		}
	case ipamOption.IPAMDelegatedPlugin:
		ipam.logger.Info("Initializing no-op IPAM since we're using a CNI delegated plugin")
		if ipam.config.IPv6Enabled() {
			ipam.IPv6Allocator = &noOpAllocator{}
		}
		if ipam.config.IPv4Enabled() {
			ipam.IPv4Allocator = &noOpAllocator{}
		}
	default:
		logging.Fatal(ipam.logger, fmt.Sprintf("Unknown IPAM backend %s", ipam.config.IPAMMode()))
	}
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
		return PoolDefault()
	}
	return Pool(pool)
}

// PoolDefault returns the default pool
func PoolDefault() Pool {
	return Pool(option.Config.IPAMDefaultIPPool)
}
