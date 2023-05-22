// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	multiPoolControllerName = "ipam-sync-multi-pool"
	multiPoolTriggerName    = "ipam-sync-multi-pool-trigger"

	waitForPoolTimeout = 3 * time.Minute
)

type poolPair struct {
	v4 *podCIDRPool
	v6 *podCIDRPool
}

type preAllocValue int
type preAllocMap map[string]preAllocValue

func parsePreAllocMap(conf map[string]string) (preAllocMap, error) {
	m := make(map[string]preAllocValue, len(conf))
	for pool, s := range conf {
		value, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid pre-alloc value for pool %q: %w", pool, err)
		}
		m[pool] = preAllocValue(value)
	}

	return m, nil
}

type multiPoolManager struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	preallocMap  preAllocMap
	pools        map[string]*poolPair
	poolsUpdated chan struct{}

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var _ Allocator = (*multiPoolAllocator)(nil)

func newMultiPoolManager(conf Configuration, nodeWatcher nodeWatcher, owner Owner, clientset nodeUpdater) *multiPoolManager {
	preallocMap, err := parsePreAllocMap(option.Config.IPAMMultiPoolNodePreAlloc)
	if err != nil {
		log.WithError(err).Fatalf("Invalid %s flag value", option.IPAMMultiPoolNodePreAlloc)
	}

	k8sController := controller.NewManager()
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 15 * time.Second,
		TriggerFunc: func(reasons []string) {
			k8sController.TriggerController(multiPoolControllerName)
		},
		Name: multiPoolTriggerName,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}

	c := &multiPoolManager{
		mutex:           &lock.Mutex{},
		owner:           owner,
		conf:            conf,
		preallocMap:     preallocMap,
		pools:           map[string]*poolPair{},
		poolsUpdated:    make(chan struct{}, 1),
		node:            nil,
		controller:      k8sController,
		k8sUpdater:      k8sUpdater,
		nodeUpdater:     clientset,
		finishedRestore: false,
	}

	// Subscribe to CiliumNode updates
	nodeWatcher.RegisterCiliumNodeSubscriber(c)
	owner.UpdateCiliumNodeResource()

	c.waitForAllPools()

	return c
}

// waitForAllPools waits for all pools in preallocMap to have IPs available.
// This function blocks the IPAM constructor forever and periodically logs
// that it is waiting for IPs to be assigned. This blocking behavior is
// consistent with other IPAM modes.
func (m *multiPoolManager) waitForAllPools() {
	allPoolsReady := false
	for !allPoolsReady {
		allPoolsReady = true
		for pool := range m.preallocMap {
			ctx, cancel := context.WithTimeout(context.Background(), waitForPoolTimeout)
			if m.conf.IPv4Enabled() {
				allPoolsReady = m.waitForPool(ctx, IPv4, pool) && allPoolsReady
			}
			if m.conf.IPv6Enabled() {
				allPoolsReady = m.waitForPool(ctx, IPv6, pool) && allPoolsReady
			}
			cancel()
		}
	}
}

// waitForPool waits for the pool poolName to have at least one allocatable IP
// available for the given IP family. This function is supposed to only be called
// before any IPs are handed out, so hasAvailableIPs returns true so as long as
// the local node has IPs assigned to it in the given pool.
func (m *multiPoolManager) waitForPool(ctx context.Context, family Family, poolName string) (ready bool) {
	timer, stop := inctimer.New()
	defer stop()
	for {
		m.mutex.Lock()
		switch family {
		case IPv4:
			if p, ok := m.pools[poolName]; ok && p.v4 != nil && p.v4.hasAvailableIPs() {
				m.mutex.Unlock()
				return true
			}
		case IPv6:
			if p, ok := m.pools[poolName]; ok && p.v6 != nil && p.v6.hasAvailableIPs() {
				m.mutex.Unlock()
				return true
			}
		}
		m.mutex.Unlock()

		select {
		case <-ctx.Done():
			return false
		case <-m.poolsUpdated:
			continue
		case <-timer.After(5 * time.Second):
			log.WithFields(logrus.Fields{
				logfields.HelpMessage: "Check if cilium-operator pod is running and does not have any warnings or error messages.",
				logfields.Family:      family,
			}).Infof("Waiting for %s pod CIDR pool %q to become available", family, poolName)
		}
	}
}

func (m *multiPoolManager) ciliumNodeUpdated(newNode *ciliumv2.CiliumNode) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// m.node will only be nil the first time this callback is invoked
	if m.node == nil {
		// This enables the upstream sync controller. It requires m.node to be populated.
		// Note: The controller will only run after m.mutex is unlocked
		m.controller.UpdateController(multiPoolControllerName, controller.ControllerParams{
			DoFunc: m.updateCiliumNode,
		})
	}

	for _, pool := range newNode.Spec.IPAM.Pools.Allocated {
		m.upsertPoolLocked(pool.Pool, pool.CIDRs)
	}

	m.node = newNode
}

// neededIPCeil rounds up numIPs to the next but one multiple of preAlloc.
// Example for preAlloc=16:
//
//	numIP  0 -> 16
//	numIP  1 -> 32
//	numIP 15 -> 32
//	numIP 16 -> 32
//	numIP 17 -> 48
//
// This always ensures that there we always have a buffer of at least preAlloc
// IPs.
func neededIPCeil(numIP int, preAlloc int) int {
	if preAlloc == 0 {
		return numIP
	}

	quotient := numIP / preAlloc
	rem := numIP % preAlloc
	if rem > 0 {
		return (quotient + 2) * preAlloc
	}
	return (quotient + 1) * preAlloc
}

func (m *multiPoolManager) updateCiliumNode(ctx context.Context) error {
	m.mutex.Lock()
	newNode := m.node.DeepCopy()
	requested := []types.IPAMPoolRequest{}
	allocated := []types.IPAMPoolAllocation{}

	// Only pools present in multi-pool-node-pre-alloc can be requested
	for poolName, preAlloc := range m.preallocMap {
		var neededIPv4, neededIPv6 int
		pool, ok := m.pools[poolName]
		if ok {
			if pool.v4 != nil {
				neededIPv4 = pool.v4.inUseIPCount()
			}
			if pool.v6 != nil {
				neededIPv6 = pool.v6.inUseIPCount()
			}
		}

		if m.conf.IPv4Enabled() {
			neededIPv4 = neededIPCeil(neededIPv4, int(preAlloc))
			if ok && pool.v4 != nil {
				pool.v4.releaseExcessCIDRsMultiPool(neededIPv4)
			}
		}
		if m.conf.IPv6Enabled() {
			neededIPv6 = neededIPCeil(neededIPv6, int(preAlloc))
			if ok && pool.v6 != nil {
				pool.v6.releaseExcessCIDRsMultiPool(neededIPv6)
			}
		}

		requested = append(requested, types.IPAMPoolRequest{
			Pool: poolName,
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: neededIPv4,
				IPv6Addrs: neededIPv6,
			},
		})
	}

	// Write in-use pools to podCIDR. This removes any released pod CIDRs
	for poolName, pool := range m.pools {
		cidrs := []types.IPAMPodCIDR{}
		if pool.v4 != nil {
			v4CIDRs := pool.v4.inUsePodCIDRs()
			slices.Sort(v4CIDRs)
			cidrs = append(cidrs, v4CIDRs...)
		}
		if pool.v6 != nil {
			v6CIDRs := pool.v6.inUsePodCIDRs()
			slices.Sort(v6CIDRs)
			cidrs = append(cidrs, v6CIDRs...)
		}

		allocated = append(allocated, types.IPAMPoolAllocation{
			Pool:  poolName,
			CIDRs: cidrs,
		})
	}

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool > requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool > allocated[j].Pool
	})
	newNode.Spec.IPAM.Pools.Requested = requested
	newNode.Spec.IPAM.Pools.Allocated = allocated

	m.mutex.Unlock()

	if !newNode.Spec.IPAM.DeepEqual(&m.node.Spec.IPAM) {
		_, err := m.nodeUpdater.Update(ctx, newNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update node spec: %w", err)
		}
	}

	return nil
}

func (m *multiPoolManager) upsertPoolLocked(poolName string, podCIDRs []types.IPAMPodCIDR) {
	pool, ok := m.pools[poolName]
	if !ok {
		pool = &poolPair{}
		if m.conf.IPv4Enabled() {
			pool.v4 = newPodCIDRPool(nil)
		}
		if m.conf.IPv6Enabled() {
			pool.v6 = newPodCIDRPool(nil)
		}
	}

	var ipv4PodCIDRs, ipv6PodCIDRs []string
	for _, ipamPodCIDR := range podCIDRs {
		podCIDR := string(ipamPodCIDR)
		switch podCIDRFamily(podCIDR) {
		case IPv4:
			ipv4PodCIDRs = append(ipv4PodCIDRs, podCIDR)
		case IPv6:
			ipv6PodCIDRs = append(ipv6PodCIDRs, podCIDR)
		}
	}

	if pool.v4 != nil {
		pool.v4.updatePool(ipv4PodCIDRs)
	}
	if pool.v6 != nil {
		pool.v6.updatePool(ipv6PodCIDRs)
	}

	m.pools[poolName] = pool

	select {
	case m.poolsUpdated <- struct{}{}:
	default:
	}
}

func (m *multiPoolManager) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		m.ciliumNodeUpdated(node)
	}

	return nil
}

func (m *multiPoolManager) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(newNode) {
		m.ciliumNodeUpdated(newNode)
	}

	return nil
}

func (m *multiPoolManager) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		log.WithField(logfields.Node, node).Warning("Local CiliumNode deleted. IPAM will continue on last seen version")
	}

	return nil
}

func (m *multiPoolManager) dump(family Family) (allocated map[string]string, status string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	allocated = map[string]string{}
	for poolName, pool := range m.pools {
		var p *podCIDRPool
		switch family {
		case IPv4:
			p = pool.v4
		case IPv6:
			p = pool.v6
		}
		if p == nil {
			return nil, fmt.Sprintf("family %q not supported", family)
		}

		ipToOwner, _, _, _, err := p.dump()
		if err != nil {
			return nil, fmt.Sprintf("error: %s", err)
		}

		ipPrefix := ""
		if poolName != PoolDefault.String() {
			ipPrefix = poolName + "/"
		}

		for ip, owner := range ipToOwner {
			allocated[ipPrefix+ip] = owner
		}
	}

	return allocated, fmt.Sprintf("%d IPAM pool(s) available", len(m.pools))
}

func (m *multiPoolManager) poolByFamilyLocked(poolName string, family Family) *podCIDRPool {
	switch family {
	case IPv4:
		pair, ok := m.pools[poolName]
		if ok {
			return pair.v4
		}
	case IPv6:
		pair, ok := m.pools[poolName]
		if ok {
			return pair.v6
		}
	}

	return nil
}

func (m *multiPoolManager) allocateNext(owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pool := m.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to allocate from unknown pool %q (family %s)", poolName, family)
	}

	ip, err := pool.allocateNext()
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		m.k8sUpdater.TriggerWithReason("allocation of next IP")
	}
	return &AllocationResult{IP: ip, IPPoolName: poolName}, nil
}

func (m *multiPoolManager) allocateIP(ip net.IP, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pool := m.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to reserve IP %s from unknown pool %q (family %s)", ip, poolName, family)
	}

	err := pool.allocate(ip)
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		m.k8sUpdater.TriggerWithReason("allocation of IP")
	}
	return &AllocationResult{IP: ip, IPPoolName: poolName}, nil
}

func (m *multiPoolManager) releaseIP(ip net.IP, poolName Pool, family Family, upstreamSync bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pool := m.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
	}

	pool.release(ip)
	if upstreamSync {
		m.k8sUpdater.TriggerWithReason("release of IP")
	}
	return nil
}

func (m *multiPoolManager) Allocator(family Family) Allocator {
	return &multiPoolAllocator{
		manager: m,
		family:  family,
	}
}

type multiPoolAllocator struct {
	manager *multiPoolManager
	family  Family
}

func (c *multiPoolAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, false)
}

func (c *multiPoolAllocator) Release(ip net.IP, pool Pool) error {
	return c.manager.releaseIP(ip, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, false)
}

func (c *multiPoolAllocator) Dump() (map[string]string, string) {
	return c.manager.dump(c.family)
}

func (c *multiPoolAllocator) RestoreFinished() {}
