// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
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

	// refreshPoolInterval defines the run interval of the ipam-sync-multi-pool controller
	refreshPoolInterval = 1 * time.Minute
)

type ErrPoolNotReadyYet struct {
	poolName Pool
	family   Family
	addr     netip.Addr
}

func (e *ErrPoolNotReadyYet) Error() string {
	if !e.addr.IsValid() {
		return fmt.Sprintf("unable to allocate from pool %q (family %s): pool not (yet) available", e.poolName, e.family)
	}
	return fmt.Sprintf("unable to reserve IP %s from pool %q (family %s): pool not (yet) available", e.addr, e.poolName, e.family)
}

func (e *ErrPoolNotReadyYet) Is(err error) bool {
	_, ok := err.(*ErrPoolNotReadyYet)
	return ok
}

type poolPair struct {
	v4           *cidrPool
	v6           *cidrPool
	allowFirstIP bool
	allowLastIP  bool
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

// pendingForFamily returns how many IP allocations are pending for the given family
func (p pendingAllocationsPerOwner) pendingForFamily(family Family) int {
	return len(p[family])
}

// PoolSpecAccessors reads and writes the pool specification in the CiliumNode.
//
// This is needed to reuse the same multi-pool manager for different implementations,
// since each frontend targets a different field when reading and writing the pool
// specs.
type PoolSpecAccessors struct {
	// FromResource returns the IPAM Pool specs from the CiliumNode.
	//
	// authoritative reports whether the returned Allocated CIDRs are owned
	// by the operator alone, e.g. because they are derived from a status
	// field that only the operator writes. If so, a CIDR that was removed
	// while in use and that shows up again has been re-assigned by the
	// operator, and the agent allocates from it again. It must be false
	// whenever the Allocated CIDRs may contain the agent's own output, as in
	// generic multi-pool mode: there, the agent keeps publishing removed but
	// in-use CIDRs to Spec.IPAM.Pools.Allocated, so their reappearance may
	// be its own echo rather than a re-assignment, and the operator may have
	// given them to another node (cilium/cilium#47910).
	FromResource func(*ciliumv2.CiliumNode) (spec types.IPAMPoolSpec, authoritative bool)

	// ToResource writes the IPAM Pool specs to the CiliumNode.
	// It returns true if the pools have been updated, false otherwise.
	ToResource func(*ciliumv2.CiliumNode, types.IPAMPoolSpec) bool

	// CIDRReleaseHandshake makes the agent take part in the CIDR release
	// handshake: it advertises Spec.IPAM.CIDRReleaseHandshake and answers
	// the release marks in Status.IPAM.ReleaseCIDRs, which the operator then
	// waits for before it releases a CIDR (cilium/cilium#47910). It must
	// only be set if the Allocated CIDRs returned by FromResource are those
	// that the operator releases, as in ENI mode.
	CIDRReleaseHandshake bool
}

// OperatorStatusAccessors reads and writes the OperatorStatus in the CiliumNode.
//
// This is needed to reuse the same multi-pool manager for different implementations,
// since each frontend targets a different field when reading and writing the operator
// status.
type OperatorStatusAccessors struct {
	// FromResource returns the OperatorStatus error from the CiliumNode
	FromResource func(*ciliumv2.CiliumNode) string

	// ToResource writes the OperatorStatus error to the CiliumNode.
	// It returns true if the error has been updated, false otherwise.
	ToResource func(*ciliumv2.CiliumNode, string) bool
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

	PoolSpecAccessors PoolSpecAccessors

	SkipMasqueradeForPool SkipMasqueradeForPoolFn

	// LinearPreAlloc uses a simple inUse + preAlloc formula for demand
	// computation instead of the multi-pool's neededIPCeil rounding. This
	// matches the CRD allocator's calculateNeededIPs behavior and allows
	// the operator to recover exact usage from the demand signal.
	LinearPreAlloc bool
}

type MultiPoolManager struct {
	ipv4Enabled bool
	ipv6Enabled bool

	preallocatedIPsPerPool preAllocatePerPool
	pendingIPsPerPool      *pendingAllocationsPerPool

	poolsMutex      lock.Mutex
	pools           map[Pool]*poolPair
	poolsUpdated    chan struct{}
	staticIPUpdated chan struct{}
	finishedRestore map[Family]bool

	nodeMutex  lock.Mutex
	node       *ciliumv2.CiliumNode
	nodeSynced bool

	jobGroup   job.Group
	k8sUpdater job.Trigger
	cnClient   cilium_v2.CiliumNodeInterface

	localNodeUpdate   chan struct{}
	localNodeUpdateFn func()

	logger *slog.Logger

	poolsAccessor PoolSpecAccessors

	// releaseMarks holds the operator's release marks of the last CiliumNode
	// seen, per family, see PoolSpecAccessors.CIDRReleaseHandshake. Protected
	// by poolsMutex.
	releaseMarks map[Family]map[netip.Prefix]string
	// releaseAnswers holds the agent's last answers to the release marks.
	// An answer of ready-for-release is handed to pools created later, so
	// that they keep the CIDR blocked even if the CiliumNode seen last does
	// not show the answer yet. Protected by poolsMutex.
	releaseAnswers map[netip.Prefix]string
	// handshakeAdvertised is set once Spec.IPAM.CIDRReleaseHandshake has been
	// written. It is not written on its own again, so that an apiserver that
	// prunes the field (CRD of an older operator) does not cause an update
	// on every run.
	handshakeAdvertised bool

	skipMasqueradeForPool SkipMasqueradeForPoolFn

	linearPreAlloc bool
}

func NewMultiPoolManager(p MultiPoolManagerParams) *MultiPoolManager {
	localNodeUpdated := make(chan struct{})
	mgr := &MultiPoolManager{
		logger:                 p.Logger,
		ipv4Enabled:            p.IPv4Enabled,
		ipv6Enabled:            p.IPv6Enabled,
		preallocatedIPsPerPool: p.PreallocMap,
		pendingIPsPerPool:      newPendingAllocationsPerPool(p.Logger),
		pools:                  map[Pool]*poolPair{},
		poolsUpdated:           make(chan struct{}, 1),
		staticIPUpdated:        make(chan struct{}, 1),
		jobGroup:               p.JobGroup,
		k8sUpdater:             job.NewTrigger(job.WithDebounce(p.CiliumNodeUpdateRate)),
		cnClient:               p.CNClient,
		finishedRestore:        map[Family]bool{},
		localNodeUpdate:        localNodeUpdated,
		localNodeUpdateFn: sync.OnceFunc(func() {
			close(localNodeUpdated)
		}),
		poolsAccessor:  p.PoolSpecAccessors,
		linearPreAlloc: p.LinearPreAlloc,
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
					case resource.Sync:
						mgr.setNodeSynced()
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
	mgr.waitForStaticIP()

	return mgr
}

// waitForAllPools waits for all pools with a non-zero preallocation request
// in preallocatedIPsPerPool to have IPs available.
// This function blocks the IPAM constructor forever and periodically logs
// that it is waiting for IPs to be assigned. This blocking behavior is
// consistent with other IPAM modes.
func (m *MultiPoolManager) waitForAllPools() {
	allPoolsReady := false
	for !allPoolsReady {
		allPoolsReady = true
		for pool, request := range m.preallocatedIPsPerPool {
			if request == 0 {
				continue
			}

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

// waitForStaticIP blocks until a requested static IP address has been assigned
// to the local node by the operator. If no static IP was requested, it returns
// immediately.
func (m *MultiPoolManager) waitForStaticIP() {
	for {
		requested, assigned := m.staticIPStatus()
		if !requested || assigned.IsValid() {
			return
		}

		select {
		case <-m.staticIPUpdated:
		case <-time.After(5 * time.Second):
			m.logger.Info(
				"Waiting for static IP address to be assigned",
				logfields.HelpMessage, "Check if cilium-operator pod is running and does not have any warnings or error messages.",
			)
		}
	}
}

// waitForPool waits for the pool poolName to have at least one allocatable IP
// available for the given IP family. This function is supposed to only be called
// before any IPs are handed out, so hasAvailableIPs returns true so as long as
// the local node has IPs assigned to it in the given pool.
func (m *MultiPoolManager) waitForPool(ctx context.Context, family Family, poolName Pool) (ready bool) {
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

func (m *MultiPoolManager) ciliumNodeUpdated(newNode *ciliumv2.CiliumNode) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	pools, authoritative := m.poolsAccessor.FromResource(newNode)
	if m.poolsAccessor.CIDRReleaseHandshake {
		// The marks must be in place before the pools are updated, see
		// cidrPool.setReleaseMarks.
		m.setReleaseMarksLocked(newNode)
		if releaseHandshakePending(newNode, pools) {
			m.k8sUpdater.Trigger()
		}
	}
	for _, pool := range pools.Allocated {
		m.upsertPoolLocked(Pool(pool.Pool), pool.CIDRs, pool.AllowFirstIP, pool.AllowLastIP, authoritative)
	}

	// Sync pre-allocate value from the CiliumNode spec. For cloud IPAM modes,
	// the agent writes it during node discovery and the operator may adjust
	// it. For standard multi-pool mode this field is unset (0).
	if newNode.Spec.IPAM.PreAllocate > 0 {
		m.preallocatedIPsPerPool[Pool(defaults.IPAMDefaultIPPool)] = newNode.Spec.IPAM.PreAllocate
	}

	// node will only be nil the first time this callback is invoked
	// Note: The job will only run after m.poolsMutex is unlocked
	oldNode := m.setNode(newNode)
	if oldNode == nil {
		m.k8sUpdater.Trigger()
	}

	// Signal any goroutine waiting in waitForStaticIP if the static IP
	// request or assignment changed.
	if oldNode == nil ||
		!maps.Equal(oldNode.Spec.IPAM.StaticIPTags, newNode.Spec.IPAM.StaticIPTags) ||
		oldNode.Status.IPAM.AssignedStaticIP != newNode.Status.IPAM.AssignedStaticIP {
		select {
		case m.staticIPUpdated <- struct{}{}:
		default:
		}
	}
}

func (m *MultiPoolManager) LocalNodeUpdated() <-chan struct{} {
	return m.localNodeUpdate
}

func (m *MultiPoolManager) staticIPStatus() (requested bool, assigned netip.Addr) {
	node := m.getNode()
	if node == nil {
		return false, netip.Addr{}
	}
	return len(node.Spec.IPAM.StaticIPTags) > 0, node.Status.IPAM.AssignedStaticIP.Addr
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
// This ensures that we always have a buffer of at least preAlloc
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
func (m *MultiPoolManager) computeNeededIPsPerPoolLocked() map[Pool]types.IPAMPoolDemand {
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
		ipv6Addrs := demand[poolName].IPv6Addrs

		if m.linearPreAlloc {
			// Linear pre-allocation: inUse + preAlloc. This matches the
			// CRD allocator's calculateNeededIPs formula and allows the
			// operator to recover exact usage as requested - preAllocate.
			if m.ipv4Enabled {
				ipv4Addrs += preAlloc
			}
			if m.ipv6Enabled {
				ipv6Addrs += preAlloc
			}
		} else {
			// Standard multi-pool rounding: rounds up to ensure at least
			// one full preAlloc buffer above usage.
			if m.ipv4Enabled {
				ipv4Addrs = neededIPCeil(ipv4Addrs, preAlloc)
			}
			if m.ipv6Enabled {
				ipv6Addrs = neededIPCeil(ipv6Addrs, preAlloc)
			}
		}

		demand[poolName] = types.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		}
	}

	return demand
}

func (m *MultiPoolManager) RestoreFinished(family Family) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	m.finishedRestore[family] = true

	// Trigger update to k8s to recalculate and synchronize requested addresses in CiliumNode
	// .Spec.IPAM.Pools.Requested with the actual need after restore is finished.
	if m.ipv4Enabled && !m.finishedRestore[IPv4] {
		return
	}
	if m.ipv6Enabled && !m.finishedRestore[IPv6] {
		return
	}
	m.k8sUpdater.Trigger()
}

func (m *MultiPoolManager) isRestoreFinishedLocked(family Family) bool {
	return m.finishedRestore[family]
}

func (m *MultiPoolManager) updateLocalNode(ctx context.Context) error {
	curNode := m.getNode()
	if curNode == nil {
		return nil
	}

	nodeSynced := m.isNodeSynced()

	m.poolsMutex.Lock()

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

	// Answer the operator's release marks before the in-use CIDRs are
	// collected, so that a CIDR acknowledged for release is no longer
	// published.
	var releaseAnswers map[netip.Prefix]string
	if m.poolsAccessor.CIDRReleaseHandshake {
		releaseAnswers = m.answerReleaseMarksLocked()
	}

	// Write in-use pools to cidr. This removes any released CIDRs
	for poolName, pool := range m.pools {
		neededIPs := neededIPsPerPool[poolName]

		cidrs := []iputil.Prefix{}
		if v4Pool := pool.v4; v4Pool != nil {
			if m.isRestoreFinishedLocked(IPv4) {
				// releaseExcessCIDRsMultiPool interprets neededIPs as how many
				// free addresses must remain after a CIDR is dropped.
				// Therefore we subtract the number of in-use addresses from neededIPs.
				freeNeeded4 := max(neededIPs.IPv4Addrs-v4Pool.inUseIPCount(), 0)
				v4Pool.releaseExcessCIDRsMultiPool(freeNeeded4)
			}
			v4CIDRs := v4Pool.inUseCIDRs()

			slices.SortFunc(v4CIDRs, func(a, b iputil.Prefix) int { return a.Prefix.Compare(b.Prefix) })
			cidrs = append(cidrs, v4CIDRs...)
		}
		if v6Pool := pool.v6; v6Pool != nil {
			if m.isRestoreFinishedLocked(IPv6) {
				freeNeeded6 := max(neededIPs.IPv6Addrs-v6Pool.inUseIPCount(), 0)
				v6Pool.releaseExcessCIDRsMultiPool(freeNeeded6)
			}
			v6CIDRs := v6Pool.inUseCIDRs()

			slices.SortFunc(v6CIDRs, func(a, b iputil.Prefix) int { return a.Prefix.Compare(b.Prefix) })
			cidrs = append(cidrs, v6CIDRs...)
		}

		// remove pool if we've released all CIDRs
		if len(cidrs) == 0 {
			delete(m.pools, poolName)
			continue
		}

		allocated = append(allocated, types.IPAMPoolAllocation{
			Pool:         poolName.String(),
			AllowFirstIP: pool.allowFirstIP,
			AllowLastIP:  pool.allowLastIP,
			CIDRs:        cidrs,
		})
	}

	sort.Slice(requested, func(i, j int) bool {
		return requested[i].Pool < requested[j].Pool
	})
	sort.Slice(allocated, func(i, j int) bool {
		return allocated[i].Pool < allocated[j].Pool
	})

	var newPoolsSpec types.IPAMPoolSpec
	newPoolsSpec.Requested = requested

	// Only update Allocated once local pools have been populated. Before
	// that, the agent has no CIDRs of its own and updating with an empty
	// Allocated would clear CIDRs that may still be in use from a
	// previous agent run. Once the CiliumNode resource has been synced
	// it updates Allocated to communicate in-use CIDRs back to the operator.
	if nodeSynced {
		newPoolsSpec.Allocated = allocated
	} else {
		pools, _ := m.poolsAccessor.FromResource(curNode)
		newPoolsSpec.Allocated = pools.Allocated
	}

	m.poolsMutex.Unlock()

	changed := m.poolsAccessor.ToResource(newNode, newPoolsSpec)
	if m.poolsAccessor.CIDRReleaseHandshake && !newNode.Spec.IPAM.CIDRReleaseHandshake {
		newNode.Spec.IPAM.CIDRReleaseHandshake = true
		changed = changed || !m.handshakeAdvertised
	}
	if changed {
		advertised := newNode.Spec.IPAM.CIDRReleaseHandshake
		updatedNode, err := m.cnClient.Update(ctx, newNode, metav1.UpdateOptions{})
		switch {
		case k8sErrors.IsConflict(err):
			m.logger.Info(
				"Conflict when updating local CiliumNode resource, will retry",
				logfields.Error, err,
			)
			return nil
		case err != nil:
			return fmt.Errorf("failed to update node spec: %w", err)
		}
		newNode = updatedNode
		if advertised {
			m.handshakeAdvertised = true
		}
	}

	statusChanged := false
	if m.poolsAccessor.CIDRReleaseHandshake {
		statusChanged = m.writeReleaseAnswers(newNode, releaseAnswers)
	}

	// Clear stale Status.IPAM.Used left by the previous CRD allocator.
	// This is needed so the operator detects the agent as multi-pool
	// (the detection heuristic checks len(Status.IPAM.Used) == 0).
	//
	// This only happens when an agent starts on a node that was previously
	// running a 1.19 agent.
	// TODO: Remove with 1.21.
	if len(newNode.Status.IPAM.Used) > 0 {
		newNode.Status.IPAM.Used = nil
		statusChanged = true
	}
	if statusChanged {
		_, err := m.cnClient.UpdateStatus(ctx, newNode, metav1.UpdateOptions{})
		switch {
		case k8sErrors.IsConflict(err):
			m.logger.Info(
				"Conflict when updating local CiliumNode Status subresource, will retry",
				logfields.Error, err,
			)
			return nil
		case err != nil:
			return fmt.Errorf("failed to update node status: %w", err)
		}
	}

	m.localNodeUpdateFn()

	return nil
}

// setReleaseMarksLocked records the release marks of node and hands them to
// the pools. Caller must hold poolsMutex.
func (m *MultiPoolManager) setReleaseMarksLocked(node *ciliumv2.CiliumNode) {
	m.releaseMarks = map[Family]map[netip.Prefix]string{
		IPv4: {},
		IPv6: {},
	}
	for cidr, status := range node.Status.IPAM.ReleaseCIDRs {
		if !cidr.IsValid() {
			continue
		}
		prefix := cidr.Prefix.Masked()
		m.releaseMarks[prefixFamily(prefix)][prefix] = string(status)
	}
	// Forget the answers to marks that the operator has cleared.
	for cidr := range m.releaseAnswers {
		switch m.releaseMarks[prefixFamily(cidr)][cidr] {
		case ipamOption.IPAMMarkForRelease, ipamOption.IPAMReadyForRelease:
		default:
			delete(m.releaseAnswers, cidr)
		}
	}
	for _, pool := range m.pools {
		m.applyReleaseMarksLocked(pool)
	}
}

// applyReleaseMarksLocked hands the recorded release marks to the pools of
// pool. Caller must hold poolsMutex.
func (m *MultiPoolManager) applyReleaseMarksLocked(pool *poolPair) {
	if !m.poolsAccessor.CIDRReleaseHandshake {
		return
	}
	marks := func(family Family) map[netip.Prefix]string {
		out := maps.Clone(m.releaseMarks[family])
		for cidr, status := range out {
			if status == ipamOption.IPAMMarkForRelease && m.releaseAnswers[cidr] == ipamOption.IPAMReadyForRelease {
				out[cidr] = ipamOption.IPAMReadyForRelease
			}
		}
		return out
	}
	if pool.v4 != nil {
		pool.v4.setReleaseMarks(marks(IPv4))
	}
	if pool.v6 != nil {
		pool.v6.setReleaseMarks(marks(IPv6))
	}
}

// answerReleaseMarksLocked answers the release marks of all pools, see
// cidrPool.answerReleaseMarks. A mark is answered only once the restore of
// its family has finished. If several pools answer for the same CIDR,
// do-not-release wins. Caller must hold poolsMutex.
func (m *MultiPoolManager) answerReleaseMarksLocked() map[netip.Prefix]string {
	answers := map[netip.Prefix]string{}
	merge := func(pool *cidrPool, family Family) {
		if pool == nil {
			return
		}
		for cidr, answer := range pool.answerReleaseMarks(m.isRestoreFinishedLocked(family)) {
			if answers[cidr] != ipamOption.IPAMDoNotRelease {
				answers[cidr] = answer
			}
		}
	}
	for _, pool := range m.pools {
		merge(pool.v4, IPv4)
		merge(pool.v6, IPv6)
	}
	// Every pool answers every mark of its family, so a mark is left
	// unanswered only if there is no pool of its family (e.g. all its CIDRs
	// were released). The CIDR is not in use then.
	for family, marks := range m.releaseMarks {
		if !m.isRestoreFinishedLocked(family) {
			continue
		}
		for cidr, status := range marks {
			if _, ok := answers[cidr]; !ok && status == ipamOption.IPAMMarkForRelease {
				answers[cidr] = ipamOption.IPAMReadyForRelease
			}
		}
	}
	m.releaseAnswers = answers
	return answers
}

// writeReleaseAnswers writes the agent's answers to the release marks into
// node.Status.IPAM.ReleaseCIDRs and returns true if it changed anything. It
// only answers marks that are present in node: a mark that the operator has
// cleared in the meantime is not brought back. A released CIDR is removed
// once it is no longer advertised to the agent, which ends its handshake.
func (m *MultiPoolManager) writeReleaseAnswers(node *ciliumv2.CiliumNode, answers map[netip.Prefix]string) bool {
	if len(node.Status.IPAM.ReleaseCIDRs) == 0 {
		return false
	}
	pools, _ := m.poolsAccessor.FromResource(node)
	advertised := sets.New[netip.Prefix]()
	for _, pool := range pools.Allocated {
		for _, cidr := range pool.CIDRs {
			if cidr.IsValid() {
				advertised.Insert(cidr.Prefix.Masked())
			}
		}
	}

	changed := false
	next := make(types.CIDRReleaseStatusMap, len(node.Status.IPAM.ReleaseCIDRs))
	for cidr, status := range node.Status.IPAM.ReleaseCIDRs {
		switch status {
		case ipamOption.IPAMMarkForRelease:
			if answer, ok := answers[cidr.Prefix.Masked()]; ok {
				status = types.IPReleaseStatus(answer)
				changed = true
				m.logger.Debug("Answering CIDR release mark",
					logfields.CIDR, cidr,
					logfields.Status, answer,
				)
			}
		case ipamOption.IPAMReadyForRelease:
			if answers[cidr.Prefix.Masked()] == ipamOption.IPAMDoNotRelease {
				status = ipamOption.IPAMDoNotRelease
				changed = true
			}
		case ipamOption.IPAMReleased:
			if !advertised.Has(cidr.Prefix.Masked()) {
				changed = true
				continue
			}
		}
		next[cidr] = status
	}
	if changed {
		node.Status.IPAM.ReleaseCIDRs = next
	}
	return changed
}

// releaseHandshakePending returns true if the agent has to write
// Status.IPAM.ReleaseCIDRs of node, because a mark is not answered yet or a
// released CIDR is no longer advertised.
func releaseHandshakePending(node *ciliumv2.CiliumNode, pools types.IPAMPoolSpec) bool {
	for cidr, status := range node.Status.IPAM.ReleaseCIDRs {
		switch status {
		case ipamOption.IPAMMarkForRelease:
			return true
		case ipamOption.IPAMReleased:
			advertised := false
			for _, pool := range pools.Allocated {
				if slices.ContainsFunc(pool.CIDRs, func(c iputil.Prefix) bool {
					return c.Prefix.Masked() == cidr.Prefix.Masked()
				}) {
					advertised = true
					break
				}
			}
			if !advertised {
				return true
			}
		}
	}
	return false
}

// upsertPoolLocked creates or updates the pool with the given CIDRs.
// regainRemoved must only be set if the CIDRs are authoritative, see
// PoolSpecAccessors.FromResource.
func (m *MultiPoolManager) upsertPoolLocked(poolName Pool, cidrs []iputil.Prefix, allowFirstIP, allowLastIP, regainRemoved bool) {
	pool, ok := m.pools[poolName]
	if !ok {
		pool = &poolPair{
			allowFirstIP: allowFirstIP,
			allowLastIP:  allowLastIP,
		}
		if m.ipv4Enabled {
			pool.v4 = newCIDRPool(m.logger, allowFirstIP, allowLastIP)
		}
		if m.ipv6Enabled {
			pool.v6 = newCIDRPool(m.logger, allowFirstIP, allowLastIP)
		}
	} else if pool.allowFirstIP != allowFirstIP || pool.allowLastIP != allowLastIP {
		if pool.v4 != nil {
			if pool.v4.inUseIPCount() == 0 {
				pool.v4 = newCIDRPool(m.logger, allowFirstIP, allowLastIP)
			} else {
				m.logger.Warn(
					"ignoring changed first/last IP settings for pool with in-use IPs",
					logfields.PoolName, poolName,
					logfields.Family, IPv4,
				)
			}
		}
		if pool.v6 != nil {
			if pool.v6.inUseIPCount() == 0 {
				pool.v6 = newCIDRPool(m.logger, allowFirstIP, allowLastIP)
			} else {
				m.logger.Warn(
					"ignoring changed first/last IP settings for pool with in-use IPs",
					logfields.PoolName, poolName,
					logfields.Family, IPv6,
				)
			}
		}
		pool.allowFirstIP = allowFirstIP
		pool.allowLastIP = allowLastIP
	}

	var ipv4Prefixes, ipv6Prefixes []netip.Prefix
	for _, c := range cidrs {
		if !c.IsValid() {
			m.logger.Error(
				"ignoring invalid CIDR",
				logfields.CIDR, c,
			)
			continue
		}
		prefix := c.Prefix.Masked()
		if prefix.Addr().Is6() {
			ipv6Prefixes = append(ipv6Prefixes, prefix)
		} else {
			ipv4Prefixes = append(ipv4Prefixes, prefix)
		}
	}

	m.applyReleaseMarksLocked(pool)
	if pool.v4 != nil {
		pool.v4.updatePool(ipv4Prefixes, regainRemoved)
	}
	if pool.v6 != nil {
		pool.v6.updatePool(ipv6Prefixes, regainRemoved)
	}

	m.pools[poolName] = pool

	select {
	case m.poolsUpdated <- struct{}{}:
	default:
	}
}

func (m *MultiPoolManager) dump(family Family) (allocated map[Pool]sets.Set[netip.Addr], status string) {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	allocated = map[Pool]sets.Set[netip.Addr]{}
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

		poolAllocated, _, _, _, err := p.dump()
		if err != nil {
			return nil, fmt.Sprintf("error: %s", err)
		}

		if poolName == "" {
			poolName = PoolDefault()
		}

		// A pool named "" and one named "default" both map to PoolDefault(),
		// so merge rather than overwrite.
		allocated[poolName] = allocated[poolName].Union(poolAllocated)
	}

	return allocated, fmt.Sprintf("%d IPAM pool(s) available", len(m.pools))
}

func (m *MultiPoolManager) poolByFamilyLocked(poolName Pool, family Family) *cidrPool {
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

func (m *MultiPoolManager) AllocateNext(owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
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

	addr, err := pool.allocateNext()
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: addr, IPPoolName: poolName, SkipMasquerade: skipMasq}, nil
}

func (m *MultiPoolManager) AllocateIP(addr netip.Addr, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
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
		return nil, &ErrPoolNotReadyYet{poolName: poolName, family: family, addr: addr}
	}

	err := pool.allocate(addr)
	if err != nil {
		m.pendingIPsPerPool.upsertPendingAllocation(poolName, owner, family)
		return nil, err
	}

	m.pendingIPsPerPool.markAsAllocated(poolName, owner, family)
	return &AllocationResult{IP: addr, IPPoolName: poolName}, nil
}

func (m *MultiPoolManager) ReleaseIP(addr netip.Addr, poolName Pool, family Family, upstreamSync bool) error {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	pool := m.poolByFamilyLocked(poolName, family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", addr, poolName, family)
	}

	pool.release(addr)
	if upstreamSync {
		m.k8sUpdater.Trigger()
	}
	return nil
}

func (m *MultiPoolManager) capacity(family Family) uint64 {
	m.poolsMutex.Lock()
	defer m.poolsMutex.Unlock()

	var cap uint64
	for _, pool := range m.pools {
		var p *cidrPool
		switch family {
		case IPv4:
			p = pool.v4
		case IPv6:
			p = pool.v6
		}
		if p == nil {
			continue
		}
		cap += uint64(p.capacity())
	}
	return uint64(cap)
}

func (m *MultiPoolManager) getNode() *ciliumv2.CiliumNode {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()
	return m.node
}

func (m *MultiPoolManager) setNode(node *ciliumv2.CiliumNode) *ciliumv2.CiliumNode {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()

	oldNode := m.node
	m.node = node
	return oldNode
}

func (m *MultiPoolManager) isNodeSynced() bool {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()

	return m.nodeSynced
}

func (m *MultiPoolManager) setNodeSynced() {
	m.nodeMutex.Lock()
	defer m.nodeMutex.Unlock()

	m.nodeSynced = true
}
