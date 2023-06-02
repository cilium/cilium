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

	// pendingAllocationTTL is how long we wait for pending allocation to
	// be fulfilled
	pendingAllocationTTL = 5 * time.Minute
)

type poolPair struct {
	v4 *podCIDRPool
	v6 *podCIDRPool
}

type preAllocatePerPool map[Pool]int

func parseMultiPoolPreAllocMap(conf map[string]string) (preAllocatePerPool, error) {
	m := make(map[Pool]int, len(conf))
	for pool, s := range conf {
		value, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid value for pool %q: %w", pool, err)
		}
		m[Pool(pool)] = int(value)
	}

	return m, nil
}

// pendingAllocationsPerPool tracks the number of pending allocations per pool.
// A pending allocation is an allocation that has been requested, but not yet
// fulfilled (i.e. typically because the pool is currently empty).
// If an allocation is pending, we will request one additional IP from the
// operator for every outstanding pending request. We will do this until the
// allocation is fulfilled (e.g. because the operator has replenished our pool),
// or if pending allocation expires (i.e. the owner has not performed any retry
// attempt within pendingAllocationTTL)
type pendingAllocationsPerPool struct {
	pools map[Pool]pendingAllocationsPerOwner
	clock func() time.Time // support custom clock for testing
}

// newPendingAllocationsPerPool returns a new pendingAllocationsPerPool with the
// default monotonic expiration clock
func newPendingAllocationsPerPool() *pendingAllocationsPerPool {
	return &pendingAllocationsPerPool{
		pools: map[Pool]pendingAllocationsPerOwner{},
		clock: func() time.Time {
			return time.Now()
		},
	}
}

// upsertPendingAllocation adds (or refreshes) a pending allocation to a particular pool.
// The pending allocation is associated with a particular owner for bookkeeping purposes.
func (p pendingAllocationsPerPool) upsertPendingAllocation(poolName Pool, owner string, family Family) {
	pool, ok := p.pools[poolName]
	if !ok {
		pool = pendingAllocationsPerOwner{}
	}

	log.WithFields(logrus.Fields{
		"owner":  owner,
		"family": family,
		"pool":   poolName,
	}).Debug("IP allocation failed, upserting pending allocation")

	now := p.clock()
	pool.startExpirationAt(now, owner, family)
	p.pools[poolName] = pool
}

// markAsAllocated marks a pending allocation as fulfilled. This means that the owner
// has now been assigned an IP from the given IP family
func (p pendingAllocationsPerPool) markAsAllocated(poolName Pool, owner string, family Family) {
	pool, ok := p.pools[poolName]
	if !ok {
		return
	}
	pool.removeExpiration(owner, family)
	if len(pool) == 0 {
		delete(p.pools, poolName)
	}
}

// removeExpiredEntries removes all expired pending allocations from all pools.
// Pending allocations expire if they are not fulfilled after the time interval
// specified in pendingAllocationTTL has elapsed.
// This typically means that we are no longer trying to reserve an additional IP for
// the expired allocation. The owner of the expired pending allocation may still
// reissue the allocation and be successful next time if the IP pool has now
// enough capacity.
func (p pendingAllocationsPerPool) removeExpiredEntries() {
	now := p.clock()
	for poolName, pool := range p.pools {
		pool.removeExpiredEntries(now, poolName)
		if len(pool) == 0 {
			delete(p.pools, poolName)
		}
	}
}

// pendingForPool returns how many IP allocations are pending for the given
// pool and IP family
func (p pendingAllocationsPerPool) pendingForPool(pool Pool, family Family) int {
	return p.pools[pool].pendingForFamily(family)
}

// pendingAllocationsPerOwner tracks if an IP owner has a pending allocation
// request for a particular IP family.
// The IP family as the first key allows one to quickly determine how many
// IP allocations are pending for a given IP family.
type pendingAllocationsPerOwner map[Family]map[string]time.Time

// startExpiration starts the expiration timer for a pending allocation
func (p pendingAllocationsPerOwner) startExpirationAt(now time.Time, owner string, family Family) {
	expires, ok := p[family]
	if !ok {
		expires = map[string]time.Time{}
	}

	expires[owner] = now.Add(pendingAllocationTTL)
	p[family] = expires
}

// startExpiration removes the expiration timer for a pending allocation, this
// happens either because the timer expired, or the allocation was fulfilled
func (p pendingAllocationsPerOwner) removeExpiration(owner string, family Family) {
	delete(p[family], owner)
	if len(p[family]) == 0 {
		delete(p, family)
	}
}

// removeExpiredEntries removes all pending allocation requests which have expired
func (p pendingAllocationsPerOwner) removeExpiredEntries(now time.Time, pool Pool) {
	for family, owners := range p {
		for owner, expires := range owners {
			if now.After(expires) {
				p.removeExpiration(owner, family)
				log.WithFields(logrus.Fields{
					"owner":  owner,
					"family": family,
					"pool":   pool,
				}).Debug("Pending IP allocation has expired without being fulfilled")
			}
		}
	}
}

// pendingForPool returns how many IP allocations are pending for the given family
func (p pendingAllocationsPerOwner) pendingForFamily(family Family) int {
	return len(p[family])
}

type multiPoolManager struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	preallocatedIPsPerPool preAllocatePerPool
	pendingIPsPerPool      *pendingAllocationsPerPool

	pools        map[Pool]*poolPair
	poolsUpdated chan struct{}

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var _ Allocator = (*multiPoolAllocator)(nil)

func newMultiPoolManager(conf Configuration, nodeWatcher nodeWatcher, owner Owner, clientset nodeUpdater) *multiPoolManager {
	preallocMap, err := parseMultiPoolPreAllocMap(option.Config.IPAMMultiPoolPreAllocation)
	if err != nil {
		log.WithError(err).Fatalf("Invalid %s flag value", option.IPAMMultiPoolPreAllocation)
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
		mutex:                  &lock.Mutex{},
		owner:                  owner,
		conf:                   conf,
		preallocatedIPsPerPool: preallocMap,
		pendingIPsPerPool:      newPendingAllocationsPerPool(),
		pools:                  map[Pool]*poolPair{},
		poolsUpdated:           make(chan struct{}, 1),
		node:                   nil,
		controller:             k8sController,
		k8sUpdater:             k8sUpdater,
		nodeUpdater:            clientset,
		finishedRestore:        false,
	}

	// Subscribe to CiliumNode updates
	nodeWatcher.RegisterCiliumNodeSubscriber(c)
	owner.UpdateCiliumNodeResource()

	c.waitForAllPools()

	return c
}

// waitForAllPools waits for all pools in preallocatedIPsPerPool to have IPs available.
// This function blocks the IPAM constructor forever and periodically logs
// that it is waiting for IPs to be assigned. This blocking behavior is
// consistent with other IPAM modes.
func (m *multiPoolManager) waitForAllPools() {
	allPoolsReady := false
	for !allPoolsReady {
		allPoolsReady = true
		for pool := range m.preallocatedIPsPerPool {
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
func (m *multiPoolManager) waitForPool(ctx context.Context, family Family, poolName Pool) (ready bool) {
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
		m.upsertPoolLocked(Pool(pool.Pool), pool.CIDRs)
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

// computeNeededIPsPerPoolLocked computes how many IPs we want to request from
// the operator for each pool. The formula we use for each pool is basically
//
//	neededIPs = roundUp(inUseIPs + pendingIPs + preAllocIPs, preAllocIPs)
//
//	      inUseIPs      Number of IPs that are currently actively in use
//	      pendingIPs    Number of IPs that have been requested, but not yet assigned
//	      preAllocIPs   Minimum number of IPs that we want to pre-allocate as a buffer
//
// Rounded up to the next multiple of preAllocIPs.
func (m *multiPoolManager) computeNeededIPsPerPoolLocked() map[Pool]types.IPAMPoolDemand {
	demand := make(map[Pool]types.IPAMPoolDemand, len(m.pools))

	// inUseIPs
	for poolName, pool := range m.pools {
		ipv4Addrs := 0
		if p := pool.v4; p != nil {
			ipv4Addrs = p.inUseIPCount()
		}
		ipv6Addrs := 0
		if p := pool.v6; p != nil {
			ipv6Addrs = p.inUseIPCount()
		}

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	// + pendingIPs
	for poolName, pending := range m.pendingIPsPerPool.pools {
		ipv4Addrs := demand[poolName].IPv4Addrs + pending.pendingForFamily(IPv4)
		ipv6Addrs := demand[poolName].IPv6Addrs + pending.pendingForFamily(IPv6)

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	// + preAllocIPs
	for poolName, preAlloc := range m.preallocatedIPsPerPool {
		ipv4Addrs := demand[poolName].IPv4Addrs
		if m.conf.IPv4Enabled() {
			ipv4Addrs = neededIPCeil(ipv4Addrs, preAlloc)
		}
		ipv6Addrs := demand[poolName].IPv6Addrs
		if m.conf.IPv6Enabled() {
			ipv6Addrs = neededIPCeil(ipv6Addrs, preAlloc)
		}

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	return demand
}

func (m *multiPoolManager) updateCiliumNode(ctx context.Context) error {
	m.mutex.Lock()
	newNode := m.node.DeepCopy()
	requested := []types.IPAMPoolRequest{}
	allocated := []types.IPAMPoolAllocation{}

	m.pendingIPsPerPool.removeExpiredEntries()
	neededIPsPerPool := m.computeNeededIPsPerPoolLocked()
	for poolName, needed := range neededIPsPerPool {
		if needed.IPv4Addrs == 0 && needed.IPv6Addrs == 0 {
			continue // no need to request "0" IPs
		}

		requested = append(requested, types.IPAMPoolRequest{
			Pool:   poolName.String(),
			Needed: needed,
		})
	}

	// Write in-use pools to podCIDR. This removes any released pod CIDRs
	for poolName, pool := range m.pools {
		neededIPs := neededIPsPerPool[poolName]

		cidrs := []types.IPAMPodCIDR{}
		if v4Pool := pool.v4; v4Pool != nil {
			v4Pool.releaseExcessCIDRsMultiPool(neededIPs.IPv4Addrs)
			v4CIDRs := v4Pool.inUsePodCIDRs()

			slices.Sort(v4CIDRs)
			cidrs = append(cidrs, v4CIDRs...)
		}
		if v6Pool := pool.v6; v6Pool != nil {
			v6Pool.releaseExcessCIDRsMultiPool(neededIPs.IPv6Addrs)
			v6CIDRs := v6Pool.inUsePodCIDRs()

			slices.Sort(v6CIDRs)
			cidrs = append(cidrs, v6CIDRs...)
		}

		// remove pool if we've released all CIDRs
		if len(cidrs) == 0 {
			delete(m.pools, poolName)
			continue
		}

		allocated = append(allocated, types.IPAMPoolAllocation{
			Pool:  poolName.String(),
			CIDRs: cidrs,
		})
	}

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool < requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool < allocated[j].Pool
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

func (m *multiPoolManager) upsertPoolLocked(poolName Pool, podCIDRs []types.IPAMPodCIDR) {
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
		if poolName != PoolDefault {
			ipPrefix = poolName.String() + "/"
		}

		for ip, owner := range ipToOwner {
			allocated[ipPrefix+ip] = owner
		}
	}

	return allocated, fmt.Sprintf("%d IPAM pool(s) available", len(m.pools))
}

func (m *multiPoolManager) poolByFamilyLocked(poolName Pool, family Family) *podCIDRPool {
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

	defer func() {
		if syncUpstream {
			m.k8sUpdater.TriggerWithReason("allocation of next IP")
		}
	}()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, fmt.Errorf("unable to allocate from pool %q (family %s): pool not (yet) available", poolName, family)
	}

	ip, err := pool.allocateNext()
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: ip, IPPoolName: poolName}, nil
}

func (m *multiPoolManager) allocateIP(ip net.IP, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	defer func() {
		if syncUpstream {
			m.k8sUpdater.TriggerWithReason("allocation of specific IP")
		}
	}()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, fmt.Errorf("unable to reserve IP %s from pool %q (family %s): pool not (yet) available", ip, poolName, family)
	}

	err := pool.allocate(ip)
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: ip, IPPoolName: poolName}, nil
}

func (m *multiPoolManager) releaseIP(ip net.IP, poolName Pool, family Family, upstreamSync bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pool := m.poolByFamilyLocked(poolName, family)
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
