// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	waitForPoolTimeout = 3 * time.Minute

	// pendingAllocationTTL is how long we wait for pending allocation to
	// be fulfilled
	pendingAllocationTTL = 5 * time.Minute

	// refreshPoolsInterval defines the run interval of the ipam-sync-multi-pool controller
	refreshPoolInterval = 1 * time.Minute
)

type ErrPoolNotReadyYet struct {
	poolName Pool
	family   Family
	ip       net.IP
}

func (e *ErrPoolNotReadyYet) Error() string {
	if e.ip == nil {
		return fmt.Sprintf("unable to allocate from pool %q (family %s): pool not (yet) available", e.poolName, e.family)
	} else {
		return fmt.Sprintf("unable to reserve IP %s from pool %q (family %s): pool not (yet) available", e.ip, e.poolName, e.family)
	}
}

func (e *ErrPoolNotReadyYet) Is(err error) bool {
	_, ok := err.(*ErrPoolNotReadyYet)
	return ok
}

type poolPair struct {
	v4 *cidrPool
	v6 *cidrPool
}

type preAllocatePerPool map[Pool]int

func ParseMultiPoolPreAllocMap(conf map[string]string) (preAllocatePerPool, error) {
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
	logger *slog.Logger
	pools  map[Pool]pendingAllocationsPerOwner
	clock  func() time.Time // support custom clock for testing
}

// newPendingAllocationsPerPool returns a new pendingAllocationsPerPool with the
// default monotonic expiration clock
func newPendingAllocationsPerPool(logger *slog.Logger) *pendingAllocationsPerPool {
	return &pendingAllocationsPerPool{
		logger: logger,
		pools:  map[Pool]pendingAllocationsPerOwner{},
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

	p.logger.Debug(
		"IP allocation failed, upserting pending allocation",
		logfields.Owner, owner,
		logfields.Family, family,
		logfields.PoolName, poolName,
	)

	now := p.clock()
	pool.startExpirationAt(now, owner, family)
	p.pools[poolName] = pool
}

// markAsAllocated marks a pending allocation as fulfilled. This means that the owner
// has now been assigned an IP from the given IP family
func (p pendingAllocationsPerPool) markAsAllocated(poolName Pool, owner string, family Family) {
	p.logger.Debug(
		"Marking pending allocation as allocated",
		logfields.Owner, owner,
		logfields.Family, family,
		logfields.PoolName, poolName,
	)

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
		pool.removeExpiredEntries(p.logger, now, poolName)
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

// removeExpiration removes the expiration timer for a pending allocation, this
// happens either because the timer expired, or the allocation was fulfilled
func (p pendingAllocationsPerOwner) removeExpiration(owner string, family Family) {
	delete(p[family], owner)
	if len(p[family]) == 0 {
		delete(p, family)
	}
}

// removeExpiredEntries removes all pending allocation requests which have expired
func (p pendingAllocationsPerOwner) removeExpiredEntries(logger *slog.Logger, now time.Time, pool Pool) {
	for family, owners := range p {
		for owner, expires := range owners {
			if now.After(expires) {
				p.removeExpiration(owner, family)
				logger.Debug(
					"Pending IP allocation has expired without being fulfilled",
					logfields.Owner, owner,
					logfields.Family, family,
					logfields.PoolName, pool,
				)
			}
		}
	}
}

// pendingForPool returns how many IP allocations are pending for the given family
func (p pendingAllocationsPerOwner) pendingForFamily(family Family) int {
	return len(p[family])
}

// SkipMasqueradeForPoolFn is the type of a function that, given a pool
// returns true if the addresses of that pool should be excluded from
// masquerading, false otherwise.
// In case the pool is not found a non-nil error is returned.
type SkipMasqueradeForPoolFn func(Pool) (bool, error)

type MultiPoolManagerParams struct {
	Logger *slog.Logger

	IPv4Enabled          bool
	IPv6Enabled          bool
	CiliumNodeUpdateRate time.Duration
	PreallocMap          preAllocatePerPool

	Node     agentK8s.LocalCiliumNodeResource
	CNClient cilium_v2.CiliumNodeInterface
	JobGroup job.Group

	PoolsFromResource ciliumv2.PoolsFromResourceFunc

	SkipMasqueradeForPool SkipMasqueradeForPoolFn
}

type multiPoolManager struct {
	ipv4Enabled bool
	ipv6Enabled bool

	preallocatedIPsPerPool preAllocatePerPool
	pendingIPsPerPool      *pendingAllocationsPerPool

	poolsMutex      lock.Mutex
	pools           map[Pool]*poolPair
	poolsUpdated    chan struct{}
	finishedRestore map[Family]bool

	nodeMutex lock.Mutex
	node      *ciliumv2.CiliumNode

	jobGroup   job.Group
	k8sUpdater job.Trigger
	cnClient   cilium_v2.CiliumNodeInterface

	localNodeUpdate   chan struct{}
	localNodeUpdateFn func()

	logger *slog.Logger

	poolsFromResource     ciliumv2.PoolsFromResourceFunc
	skipMasqueradeForPool SkipMasqueradeForPoolFn
}

func newMultiPoolManager(p MultiPoolManagerParams) *multiPoolManager {
	localNodeUpdated := make(chan struct{})
	mgr := &multiPoolManager{
		logger:                 p.Logger,
		ipv4Enabled:            p.IPv4Enabled,
		ipv6Enabled:            p.IPv6Enabled,
		preallocatedIPsPerPool: p.PreallocMap,
		pendingIPsPerPool:      newPendingAllocationsPerPool(p.Logger),
		pools:                  map[Pool]*poolPair{},
		poolsUpdated:           make(chan struct{}, 1),
		jobGroup:               p.JobGroup,
		k8sUpdater:             job.NewTrigger(job.WithDebounce(p.CiliumNodeUpdateRate)),
		cnClient:               p.CNClient,
		finishedRestore:        map[Family]bool{},
		localNodeUpdate:        localNodeUpdated,
		localNodeUpdateFn: sync.OnceFunc(func() {
			close(localNodeUpdated)
		}),
		poolsFromResource: p.PoolsFromResource,
		skipMasqueradeForPool: func(Pool) (bool, error) {
			return false, nil
		},
	}
	if p.SkipMasqueradeForPool != nil {
		mgr.skipMasqueradeForPool = p.SkipMasqueradeForPool
	}

	mgr.jobGroup.Add(
		job.OneShot(
			"multi-pool-cilium-node-events-handler",
			func(ctx context.Context, health cell.Health) error {
				for ev := range p.Node.Events(ctx) {
					switch ev.Kind {
					case resource.Upsert:
						mgr.ciliumNodeUpdated(ev.Object)
					case resource.Delete:
						mgr.logger.Debug(
							"Local CiliumNode deleted. IPAM will continue on last seen version",
							logfields.Node, ev.Object,
						)
					}
					ev.Done(nil)
				}
				return nil
			},
		),
		job.Timer(
			"multi-pool-cilium-node-updater",
			mgr.updateLocalNode,
			refreshPoolInterval,
			job.WithTrigger(mgr.k8sUpdater),
		),
	)

	mgr.waitForAllPools()

	return mgr
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
			if m.ipv4Enabled {
				allPoolsReady = m.waitForPool(ctx, IPv4, pool) && allPoolsReady
			}
			if m.ipv6Enabled {
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
	for {
		m.poolsMutex.Lock()
		poolReady := false
		switch family {
		case IPv4:
			if p, ok := m.pools[poolName]; ok && p.v4 != nil && p.v4.hasAvailableIPs() {
				poolReady = true
			}
		case IPv6:
			if p, ok := m.pools[poolName]; ok && p.v6 != nil && p.v6.hasAvailableIPs() {
				poolReady = true
			}
		}
		m.poolsMutex.Unlock()

		if poolReady {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-m.poolsUpdated:
			continue
		case <-time.After(5 * time.Second):
			m.logger.Info(
				"Waiting for cidr pool to become available",
				logfields.PoolName, poolName,
				logfields.Family, family,
				logfields.HelpMessage, "Check if cilium-operator pod is running and does not have any warnings or error messages.",
			)
		}
	}
}

func (m *multiPoolManager) ciliumNodeUpdated(newNode *ciliumv2.CiliumNode) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	pools := m.poolsFromResource(newNode)
	for _, pool := range pools.Allocated {
		m.upsertPoolLocked(Pool(pool.Pool), pool.CIDRs)
	}

	// node will only be nil the first time this callback is invoked
	// Note: The job will only run after m.poolsMutex is unlocked
	oldNode := m.setNode(newNode)
	if oldNode == nil {
		m.k8sUpdater.Trigger()
	}
}

func (m *multiPoolManager) localNodeUpdated() <-chan struct{} {
	return m.localNodeUpdate
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
		if m.ipv4Enabled {
			ipv4Addrs = neededIPCeil(ipv4Addrs, preAlloc)
		}
		ipv6Addrs := demand[poolName].IPv6Addrs
		if m.ipv6Enabled {
			ipv6Addrs = neededIPCeil(ipv6Addrs, preAlloc)
		}

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	return demand
}

func (m *multiPoolManager) restoreFinished(family Family) {
	m.poolsMutex.Lock()
	m.finishedRestore[family] = true
	m.poolsMutex.Unlock()
}

func (m *multiPoolManager) isRestoreFinishedLocked(family Family) bool {
	return m.finishedRestore[family]
}

func (m *multiPoolManager) updateLocalNode(ctx context.Context) error {
	m.poolsMutex.Lock()

	curNode := m.getNode()
	if curNode == nil {
		m.poolsMutex.Unlock()
		return nil
	}

	newNode := curNode.DeepCopy()
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

	// Write in-use pools to cidr. This removes any released CIDRs
	for poolName, pool := range m.pools {
		neededIPs := neededIPsPerPool[poolName]

		cidrs := []types.IPAMCIDR{}
		if v4Pool := pool.v4; v4Pool != nil {
			if m.isRestoreFinishedLocked(IPv4) {
				// releaseExcessCIDRsMultiPool interprets neededIPs as how many
				// free addresses must remain after a CIDR is dropped.
				// Therefore we subtract the number of in-use addresses from neededIPs.
				freeNeeded4 := max(neededIPs.IPv4Addrs-v4Pool.inUseIPCount(), 0)
				v4Pool.releaseExcessCIDRsMultiPool(freeNeeded4)
			}
			v4CIDRs := v4Pool.inUseCIDRs()

			slices.Sort(v4CIDRs)
			cidrs = append(cidrs, v4CIDRs...)
		}
		if v6Pool := pool.v6; v6Pool != nil {
			if m.isRestoreFinishedLocked(IPv6) {
				freeNeeded6 := max(neededIPs.IPv6Addrs-v6Pool.inUseIPCount(), 0)
				v6Pool.releaseExcessCIDRsMultiPool(freeNeeded6)
			}
			v6CIDRs := v6Pool.inUseCIDRs()

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

	newPools := m.poolsFromResource(newNode)

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool < requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool < allocated[j].Pool
	})
	newPools.Requested = requested
	newPools.Allocated = allocated

	m.poolsMutex.Unlock()

	pools := m.poolsFromResource(curNode)

	if !newPools.DeepEqual(pools) {
		_, err := m.cnClient.Update(ctx, newNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update node spec: %w", err)
		}
	}

	m.localNodeUpdateFn()

	return nil
}

func (m *multiPoolManager) upsertPoolLocked(poolName Pool, cidrs []types.IPAMCIDR) {
	pool, ok := m.pools[poolName]
	if !ok {
		pool = &poolPair{}
		if m.ipv4Enabled {
			pool.v4 = newCIDRPool(m.logger)
		}
		if m.ipv6Enabled {
			pool.v6 = newCIDRPool(m.logger)
		}
	}

	var ipv4CIDRs, ipv6CIDRs []string
	for _, ipamCIDR := range cidrs {
		cidr := string(ipamCIDR)
		switch cidrFamily(cidr) {
		case IPv4:
			ipv4CIDRs = append(ipv4CIDRs, cidr)
		case IPv6:
			ipv6CIDRs = append(ipv6CIDRs, cidr)
		}
	}

	if pool.v4 != nil {
		pool.v4.updatePool(ipv4CIDRs)
	}
	if pool.v6 != nil {
		pool.v6.updatePool(ipv6CIDRs)
	}

	m.pools[poolName] = pool

	select {
	case m.poolsUpdated <- struct{}{}:
	default:
	}
}

func (m *multiPoolManager) dump(family Family) (allocated map[Pool]map[string]string, status string) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	allocated = map[Pool]map[string]string{}
	for poolName, pool := range m.pools {
		var p *cidrPool
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

		if poolName == "" {
			poolName = PoolDefault()
		}

		if _, ok := allocated[poolName]; !ok {
			allocated[poolName] = map[string]string{}
		}

		maps.Copy(allocated[poolName], ipToOwner)
	}

	return allocated, fmt.Sprintf("%d IPAM pool(s) available", len(m.pools))
}

func (m *multiPoolManager) poolByFamilyLocked(poolName Pool, family Family) *cidrPool {
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
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	defer func() {
		if syncUpstream {
			m.k8sUpdater.Trigger()
		}
	}()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, &ErrPoolNotReadyYet{poolName: poolName, family: family}
	}

	skipMasq, err := m.skipMasqueradeForPool(poolName)
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	ip, err := pool.allocateNext()
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: ip, IPPoolName: poolName, SkipMasquerade: skipMasq}, nil
}

func (m *multiPoolManager) allocateIP(ip net.IP, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	defer func() {
		if syncUpstream {
			m.k8sUpdater.Trigger()
		}
	}()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, &ErrPoolNotReadyYet{poolName: poolName, family: family, ip: ip}
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
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
	}

	pool.release(ip)
	if upstreamSync {
		m.k8sUpdater.Trigger()
	}
	return nil
}

func (m *multiPoolManager) getNode() *ciliumv2.CiliumNode {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()
	return m.node
}

func (m *multiPoolManager) setNode(node *ciliumv2.CiliumNode) *ciliumv2.CiliumNode {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()

	oldNode := m.node
	m.node = node
	return oldNode
}
