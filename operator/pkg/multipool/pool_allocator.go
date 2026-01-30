// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/netip"
	"slices"
	"sort"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type cidrPool struct {
	v4         []cidralloc.CIDRAllocator
	v6         []cidralloc.CIDRAllocator
	v4MaskSize int
	v6MaskSize int
}

type cidrSet map[netip.Prefix]struct{}

func (c cidrSet) CIDRSlice() []types.IPAMCIDR {
	cidrs := make([]types.IPAMCIDR, 0, len(c))
	for cidr := range c {
		cidrs = append(cidrs, types.IPAMCIDR(cidr.String()))
	}
	slices.Sort(cidrs)
	return cidrs
}

// availableAddrs returns the number of available addresses in this set
func (c cidrSet) availableAddrs() *big.Int {
	total := big.NewInt(0)
	for p := range c {
		total.Add(total, addrsInPrefix(p))
	}
	return total
}

type cidrSets struct {
	v4 cidrSet
	v6 cidrSet
}

type poolToCIDRs map[string]cidrSets // poolName -> list of allocated CIDRs

type errAllocatorNotReady struct{}

var ErrAllocatorNotReady = errAllocatorNotReady{}

func (m errAllocatorNotReady) Error() string {
	return "allocator not ready"
}

func (m errAllocatorNotReady) Is(target error) bool {
	return errors.Is(target, ErrAllocatorNotReady)
}

// addrsInPrefix calculates the number of usable addresses in a prefix p, or 0 if p is not valid.
func addrsInPrefix(p netip.Prefix) *big.Int {
	if !p.IsValid() {
		return big.NewInt(0)
	}

	// compute number of addresses in prefix, i.e. 2^bits
	addrs := new(big.Int)
	addrs.Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))

	// prefix has less than 3 addresses
	two := big.NewInt(2)
	if addrs.Cmp(two) <= 0 {
		return addrs
	}

	// subtract network and broadcast address, which are not available for
	// allocation in the cilium/ipam library for now
	addrs.Sub(addrs, two)
	if addrs.Sign() < 0 {
		return big.NewInt(0)
	}

	return addrs
}

type PoolAllocator struct {
	logger *slog.Logger

	ipv4Enabled, ipv6Enabled bool

	mutex   lock.RWMutex
	pools   map[string]cidrPool    // poolName -> pool
	nodes   map[string]poolToCIDRs // nodeName -> pool -> cidrs
	orphans map[string]poolToCIDRs // nodeName -> pool -> list of orphaned CIDRs (CIDRs allocated to nodes but missing their parent pool)
	ready   bool
}

func NewPoolAllocator(logger *slog.Logger, enableIPv4, enableIPv6 bool) *PoolAllocator {
	return &PoolAllocator{
		logger:      logger,
		ipv4Enabled: enableIPv4,
		ipv6Enabled: enableIPv6,
		pools:       map[string]cidrPool{},
		nodes:       map[string]poolToCIDRs{},
		orphans:     map[string]poolToCIDRs{},
	}
}

func (p *PoolAllocator) RestoreFinished() {
	p.mutex.Lock()
	p.ready = true
	p.mutex.Unlock()
}

func (p *PoolAllocator) cleanupOrphans(node, pool string) {
	switch {
	case len(p.orphans[node][pool].v4) == 0 && len(p.orphans[node][pool].v6) == 0:
		delete(p.orphans[node], pool)
		if len(p.orphans[node]) == 0 {
			delete(p.orphans, node)
		}
	case len(p.orphans[node][pool].v4) == 0:
		p.orphans[node][pool] = cidrSets{v6: p.orphans[node][pool].v6}
	case len(p.orphans[node][pool].v6) == 0:
		p.orphans[node][pool] = cidrSets{v4: p.orphans[node][pool].v4}
	}
}

func (p *PoolAllocator) unorphanCIDR(isV6 bool, node, pool string, cidr netip.Prefix) error {
	p.logger.Info(
		"CIDR from pool already in use by node, marking it as allocated",
		logfields.CIDR, cidr,
		logfields.PoolName, pool,
		logfields.Node, node,
	)
	if err := p.occupyCIDR(node, pool, cidr); err != nil {
		return fmt.Errorf("unable to mark orphaned CIDR %s still used by node %s as allocated: %w", cidr, node, err)
	}
	if isV6 {
		delete(p.orphans[node][pool].v6, cidr)
	} else {
		delete(p.orphans[node][pool].v4, cidr)
	}
	return nil
}

func (p *PoolAllocator) reconcileOrphanCIDRs(pool string, v4, v6 []cidralloc.CIDRAllocator) error {
	var errs []error
	for node, cidrs := range p.orphans {
		for pool, cidrSets := range cidrs {
			for cidr := range cidrSets.v4 {
				if containsCIDR(v4, cidr) {
					errs = append(errs, p.unorphanCIDR(false, node, pool, cidr))
				}
			}
			for cidr := range cidrSets.v6 {
				if containsCIDR(v6, cidr) {
					errs = append(errs, p.unorphanCIDR(true, node, pool, cidr))
				}
			}
		}

		p.cleanupOrphans(node, pool)
	}
	return errors.Join(errs...)
}

func (p *PoolAllocator) updateCIDRSets(isV6 bool, cidrSets []cidralloc.CIDRAllocator, newCIDRs []netip.Prefix, maskSize int) ([]cidralloc.CIDRAllocator, error) {
	var newCIDRSets []cidralloc.CIDRAllocator
	var alloc []string

	// allocate new CIDR set for each CIDR not yet in the pool
	for _, cidr := range newCIDRs {
		if !hasCIDR(cidrSets, cidr) {
			alloc = append(alloc, cidr.String())
		}
	}
	if len(alloc) > 0 {
		var err error
		newCIDRSets, err = cidralloc.NewCIDRSets(isV6, alloc, maskSize)
		if err != nil {
			return nil, err
		}
	}

	var errs []error

	// delete CIDR set for CIDRs not present in the new CIDRs
	for i, oldCIDR := range cidrSets {
		if oldCIDR == nil {
			continue
		}
		if exists := slices.ContainsFunc(newCIDRs, oldCIDR.IsClusterCIDR); exists {
			continue
		}

		cidrSets[i] = nil

		for node, pools := range p.nodes {
			for pool, allocatedCIDRSets := range pools {
				var cidrs cidrSet
				if isV6 {
					cidrs = allocatedCIDRSets.v6
				} else {
					cidrs = allocatedCIDRSets.v4
				}

				for cidr := range cidrs {
					ipnet := netipx.PrefixIPNet(cidr)
					if !oldCIDR.InRange(ipnet) {
						continue
					}
					allocated, err := oldCIDR.IsAllocated(ipnet)
					if err != nil {
						errs = append(errs, err)
						continue
					}
					if !allocated {
						continue
					}
					p.logger.Warn(
						"CIDR from pool still in use by node",
						logfields.CIDR, cidr,
						logfields.PoolName, pool,
						logfields.Node, node,
					)
					p.markOrphan(node, pool, cidr)
					delete(cidrs, cidr)
				}
			}
		}
	}
	cidrSets = slices.DeleteFunc(cidrSets, func(a cidralloc.CIDRAllocator) bool { return a == nil })
	cidrSets = append(cidrSets, newCIDRSets...)
	return cidrSets, errors.Join(errs...)
}

func parseCIDRStrings(cidrStrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrStrs))
	for _, cidrStr := range cidrStrs {
		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (p *PoolAllocator) UpsertPool(poolName string, ipv4CIDRs []string, ipv4MaskSize int, ipv6CIDRs []string, ipv6MaskSize int) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	pool, exists := p.pools[poolName]
	if exists && ipv4MaskSize != pool.v4MaskSize {
		return fmt.Errorf("cannot change IPv4 mask size in existing pool %q", poolName)
	}
	if exists && ipv6MaskSize != pool.v6MaskSize {
		return fmt.Errorf("cannot change IPv6 mask size in existing pool %q", poolName)
	}

	ipv4Prefixes, err := parseCIDRStrings(ipv4CIDRs)
	if err != nil {
		return fmt.Errorf("invalid IPv4 CIDR: %w", err)
	}
	ipv6Prefixes, err := parseCIDRStrings(ipv6CIDRs)
	if err != nil {
		return fmt.Errorf("invalid IPv6 CIDR: %w", err)
	}

	var v4Prev []cidralloc.CIDRAllocator
	if exists {
		v4Prev = pool.v4
	}
	v4, err := p.updateCIDRSets(false, v4Prev, ipv4Prefixes, ipv4MaskSize)
	if err != nil {
		return err
	}

	var v6Prev []cidralloc.CIDRAllocator
	if exists {
		v6Prev = pool.v6
	}
	v6, err := p.updateCIDRSets(true, v6Prev, ipv6Prefixes, ipv6MaskSize)
	if err != nil {
		return err
	}

	p.pools[poolName] = cidrPool{
		v4:         v4,
		v6:         v6,
		v4MaskSize: ipv4MaskSize,
		v6MaskSize: ipv6MaskSize,
	}

	return p.reconcileOrphanCIDRs(poolName, v4, v6)
}

// DeletePool deletes a pool from p. No new allocations to nodes will be made
// from the pool and all internal bookkeeping is removed. However, nodes will
// still retain their in-flight CIDRs until next time the respective CiliumNode
// is updated.
func (p *PoolAllocator) DeletePool(poolName string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, exists := p.pools[poolName]; !exists {
		return fmt.Errorf("pool %q requested for deletion doesn't exist", poolName)
	}

	for node, pools := range p.nodes {
		cidrSets, found := pools[poolName]
		if !found {
			continue
		}
		p.logger.Warn(
			"pool still in use by node",
			logfields.PoolName, poolName,
			logfields.Node, node,
		)
		delete(p.nodes[node], poolName)
		for cidr := range cidrSets.v4 {
			p.markOrphan(node, poolName, cidr)
		}
		for cidr := range cidrSets.v6 {
			p.markOrphan(node, poolName, cidr)
		}
	}

	delete(p.pools, poolName)
	return nil
}

func (p *PoolAllocator) AllocateToNode(nodeName string, pools *types.IPAMPoolSpec) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// We first need to check for CIDRs which we want to occupy, i.e. mark as
	// allocated to the node. This needs to happen before allocations, to avoid
	// handing out the same CIDR twice.
	var err error

	allocatedSet := make(map[string]map[netip.Prefix]struct{}, len(pools.Allocated))
	for _, allocatedPool := range pools.Allocated {
		allocatedSet[allocatedPool.Pool] = make(map[netip.Prefix]struct{}, len(allocatedPool.CIDRs))

		for _, cidrStr := range allocatedPool.CIDRs {
			prefix, parseErr := netip.ParsePrefix(string(cidrStr))
			if parseErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to parse CIDR of pool %q: %w", allocatedPool.Pool, parseErr))
				continue
			}

			if _, found := p.pools[allocatedPool.Pool]; found {
				if occupyErr := p.occupyCIDR(nodeName, allocatedPool.Pool, prefix); occupyErr != nil {
					err = errors.Join(err, occupyErr)
				}
			} else {
				// pool cannot be found: it must be a pool deleted before the operator restarted.
				// Mark the CIDR as orphan to preserve node allocations.
				p.markOrphan(nodeName, allocatedPool.Pool, prefix)
				err = errors.Join(err,
					fmt.Errorf("unable to find pool %s, prefix %s is still allocated to the node but is marked as orphan",
						allocatedPool.Pool, prefix))
			}

			allocatedSet[allocatedPool.Pool][prefix] = struct{}{}
		}
	}

	// release any cidrs no longer present in allocatedPool
	for poolName := range p.nodes[nodeName] {
		retainErrs := p.retainCIDRs(nodeName, poolName, allocatedSet[poolName])
		if retainErrs != nil {
			err = errors.Join(err, retainErrs)
		}
	}
	// release any orphan cidrs no longer present in allocatedPool
	for poolName := range p.orphans[nodeName] {
		retainErrs := p.retainOrphanCIDRs(nodeName, poolName, allocatedSet[poolName])
		if retainErrs != nil {
			err = errors.Join(err, retainErrs)
		}
	}

	// Delay allocation until we have occupied the CIDRs of all existing nodes.
	// The node manager will call us again once it has ensured that all nodes
	// had their CIDRs occupied, after which p.ready will be set to true
	if !p.ready {
		return ErrAllocatorNotReady
	}

	for _, reqPool := range pools.Requested {
		allocatedCIDRs := p.nodes[nodeName][reqPool.Pool]

		if p.ipv4Enabled {
			neededIPv4Addrs := big.NewInt(int64(reqPool.Needed.IPv4Addrs))
			toAllocate := neededIPv4Addrs.Sub(neededIPv4Addrs, allocatedCIDRs.v4.availableAddrs())

			if allocErr := p.allocateCIDRs(nodeName, reqPool.Pool, ipam.IPv4, toAllocate); allocErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to allocate ipv4 address for node %q from pool %q: %w",
						nodeName, reqPool.Pool, allocErr))
			}
		}
		if p.ipv6Enabled {
			neededIPv6Addrs := big.NewInt(int64(reqPool.Needed.IPv6Addrs))
			toAllocate := neededIPv6Addrs.Sub(neededIPv6Addrs, allocatedCIDRs.v6.availableAddrs())

			if allocErr := p.allocateCIDRs(nodeName, reqPool.Pool, ipam.IPv6, toAllocate); allocErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to allocate ipv6 address for node %q from pool %q: %w",
						nodeName, reqPool.Pool, allocErr))
			}
		}
	}
	return err
}

func (p *PoolAllocator) ReleaseNode(nodeName string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Release CIDRs back into pools
	var err error
	for poolName, cidrs := range p.nodes[nodeName] {
		pool, ok := p.pools[poolName]
		if !ok {
			err = errors.Join(err,
				fmt.Errorf("cannot release from non-existing pool: %s", poolName))
			continue
		}

		for cidr := range cidrs.v4 {
			err = errors.Join(err, releaseCIDR(pool.v4, cidr))
		}
		for cidr := range cidrs.v6 {
			err = errors.Join(err, releaseCIDR(pool.v6, cidr))
		}
	}

	// Remove bookkeeping for this node
	delete(p.nodes, nodeName)

	return err
}

func (p *PoolAllocator) AllocatedPools(targetNode string) (pools []types.IPAMPoolAllocation) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// we have to aggregate CIDRs allocated from existing pools as well as orphan CIDRs
	poolToCIDRs := poolToCIDRs{}
	for _, poolName := range append(
		slices.Collect(maps.Keys(p.nodes[targetNode])),
		slices.Collect(maps.Keys(p.orphans[targetNode]))...,
	) {
		if _, found := poolToCIDRs[poolName]; found {
			continue
		}
		sets := cidrSets{v4: cidrSet{}, v6: cidrSet{}}

		maps.Copy(sets.v4, p.nodes[targetNode][poolName].v4)
		maps.Copy(sets.v4, p.orphans[targetNode][poolName].v4)

		maps.Copy(sets.v6, p.nodes[targetNode][poolName].v6)
		maps.Copy(sets.v6, p.orphans[targetNode][poolName].v6)

		poolToCIDRs[poolName] = sets
	}

	for poolName, cidrs := range poolToCIDRs {
		v4CIDRs := cidrs.v4.CIDRSlice()
		v6CIDRs := cidrs.v6.CIDRSlice()

		pools = append(pools, types.IPAMPoolAllocation{
			Pool:  poolName,
			CIDRs: append(v4CIDRs, v6CIDRs...),
		})
	}

	sort.Slice(pools, func(i, j int) bool {
		return pools[i].Pool < pools[j].Pool
	})

	return pools
}

func (p *PoolAllocator) isAllocated(targetNode, sourcePool string, cidr netip.Prefix) bool {
	var found bool
	switch {
	case cidr.Addr().Is4():
		_, found = p.nodes[targetNode][sourcePool].v4[cidr]
	case cidr.Addr().Is6():
		_, found = p.nodes[targetNode][sourcePool].v6[cidr]
	}
	return found
}

func (p *PoolAllocator) markAllocated(targetNode, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.nodes[targetNode]
	if !ok {
		pools = poolToCIDRs{}
		p.nodes[targetNode] = pools
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		cidrs = cidrSets{
			v4: cidrSet{},
			v6: cidrSet{},
		}
		pools[sourcePool] = cidrs
	}

	switch {
	case cidr.Addr().Is4():
		cidrs.v4[cidr] = struct{}{}
	case cidr.Addr().Is6():
		cidrs.v6[cidr] = struct{}{}
	}
}

func (p *PoolAllocator) markReleased(targetNode, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.nodes[targetNode]
	if !ok {
		return
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		return
	}

	switch {
	case cidr.Addr().Is4():
		delete(cidrs.v4, cidr)
	case cidr.Addr().Is6():
		delete(cidrs.v6, cidr)
	}

	// remove pool reference if it is now empty
	if len(cidrs.v4) == 0 && len(cidrs.v6) == 0 {
		delete(pools, sourcePool)
	}
}

func (p *PoolAllocator) isOrphan(targetNode, sourcePool string, cidr netip.Prefix) bool {
	var found bool
	switch {
	case cidr.Addr().Is4():
		_, found = p.orphans[targetNode][sourcePool].v4[cidr]
	case cidr.Addr().Is6():
		_, found = p.orphans[targetNode][sourcePool].v6[cidr]
	}
	return found
}

func (p *PoolAllocator) markOrphan(targetNode string, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.orphans[targetNode]
	if !ok {
		pools = poolToCIDRs{}
		p.orphans[targetNode] = pools
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		cidrs = cidrSets{
			v4: cidrSet{},
			v6: cidrSet{},
		}
		pools[sourcePool] = cidrs
	}

	switch {
	case cidr.Addr().Is4():
		cidrs.v4[cidr] = struct{}{}
	case cidr.Addr().Is6():
		cidrs.v6[cidr] = struct{}{}
	}
}

func (p *PoolAllocator) markReleasedOrphan(targetNode, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.orphans[targetNode]
	if !ok {
		return
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		return
	}

	switch {
	case cidr.Addr().Is4():
		delete(cidrs.v4, cidr)
	case cidr.Addr().Is6():
		delete(cidrs.v6, cidr)
	}

	p.cleanupOrphans(targetNode, sourcePool)
}

// allocateCIDRs allocates additional IPs from the sourcePool to the targetNode.
// The number of to be allocated IPs in toAllocate may be zero or negative, in
// which case this function is a no-op.
func (p *PoolAllocator) allocateCIDRs(targetNode, sourcePool string, family ipam.Family, toAllocate *big.Int) error {
	zero := new(big.Int)
	if toAllocate.Cmp(zero) <= 0 {
		return nil // nothing to allocate
	}

	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot allocate from non-existing pool: %s", sourcePool)
	}

	p.logger.Debug(
		"allocating cidr",
		logfields.TargetNode, targetNode,
		logfields.SourcePool, sourcePool,
		logfields.Family, family,
		logfields.ToAllocate, toAllocate,
	)

	for toAllocate.Cmp(zero) > 0 {
		cidr, err := pool.allocCIDR(family)
		if err != nil {
			return err
		}

		p.markAllocated(targetNode, sourcePool, cidr)
		toAllocate.Sub(toAllocate, addrsInPrefix(cidr))
	}

	return nil
}

func (p *PoolAllocator) occupyCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// avoid allocating CIDRs twice
	if p.isAllocated(targetNode, sourcePool, cidr) {
		return nil
	}

	p.logger.Debug(
		"occupying cidr",
		logfields.TargetNode, targetNode,
		logfields.SourcePool, sourcePool,
		logfields.CIDR, cidr,
	)

	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot reuse from non-existing pool: %s", sourcePool)
	}

	err := pool.occupyCIDR(cidr)
	if err != nil {
		return fmt.Errorf("unable to reuse from pool %s: %w", sourcePool, err)
	}

	p.markAllocated(targetNode, sourcePool, cidr)

	return nil
}

// retainCIDRs releases all CIDRs in sourcePool of targetNode if they are _not_ present in the retain set
func (p *PoolAllocator) retainCIDRs(targetNode, sourcePool string, retain map[netip.Prefix]struct{}) (err error) {
	for prefix := range p.nodes[targetNode][sourcePool].v4 {
		if _, ok := retain[prefix]; ok {
			continue
		}

		releaseErr := p.releaseCIDR(targetNode, sourcePool, prefix)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}
	for prefix := range p.nodes[targetNode][sourcePool].v6 {
		if _, ok := retain[prefix]; ok {
			continue
		}

		releaseErr := p.releaseCIDR(targetNode, sourcePool, prefix)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}

	return err
}

// retainOrphanCIDRs releases all orphan CIDRs in sourcePool of targetNode if they are _not_ present in the retain set
func (p *PoolAllocator) retainOrphanCIDRs(targetNode, sourcePool string, retain map[netip.Prefix]struct{}) (err error) {
	for prefix := range p.orphans[targetNode][sourcePool].v4 {
		if _, ok := retain[prefix]; ok {
			continue
		}

		releaseErr := p.releaseOrphanCIDR(targetNode, sourcePool, prefix)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}
	for prefix := range p.orphans[targetNode][sourcePool].v6 {
		if _, ok := retain[prefix]; ok {
			continue
		}

		releaseErr := p.releaseOrphanCIDR(targetNode, sourcePool, prefix)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}

	return err
}

func (p *PoolAllocator) releaseCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// do not release CIDRs not allocated to the node
	if !p.isAllocated(targetNode, sourcePool, cidr) {
		return nil
	}

	p.logger.Debug(
		"releasing cidr",
		logfields.TargetNode, targetNode,
		logfields.SourcePool, sourcePool,
		logfields.CIDR, cidr,
	)

	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot release from non-existing pool: %s", sourcePool)
	}

	err := pool.releaseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("unable to release from pool %s: %w", sourcePool, err)
	}

	p.markReleased(targetNode, sourcePool, cidr)

	return nil
}

func (p *PoolAllocator) releaseOrphanCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// do not release orphan CIDRs not previously allocated to the node
	if !p.isOrphan(targetNode, sourcePool, cidr) {
		return nil
	}

	p.logger.Debug(
		"releasing orphan cidr",
		logfields.TargetNode, targetNode,
		logfields.SourcePool, sourcePool,
		logfields.CIDR, cidr,
	)

	p.markReleasedOrphan(targetNode, sourcePool, cidr)

	return nil
}
