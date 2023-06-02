// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-clusterpool-v2")

type cidrPool struct {
	v4 []cidralloc.CIDRAllocator
	v6 []cidralloc.CIDRAllocator
}

type cidrSet map[netip.Prefix]struct{}

func (c cidrSet) PodCIDRSlice() []types.IPAMPodCIDR {
	cidrs := make([]types.IPAMPodCIDR, 0, len(c))
	for cidr := range c {
		cidrs = append(cidrs, types.IPAMPodCIDR(cidr.String()))
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

func addrsInPrefix(p netip.Prefix) *big.Int {
	// compute number of addresses in prefix, i.e. 2^bits
	addrs := new(big.Int)
	addrs.Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
	// subtract network and broadcast address, which are not available for
	// allocation in the cilium/ipam library for now
	addrs.Sub(addrs, big.NewInt(2))
	if addrs.Sign() < 0 {
		return big.NewInt(0)
	}

	return addrs
}

type PoolAllocator struct {
	pools map[string]cidrPool    // poolName -> pool
	nodes map[string]poolToCIDRs // nodeName -> pool -> cidrs
	ready bool
}

func NewPoolAllocator() *PoolAllocator {
	return &PoolAllocator{
		pools: map[string]cidrPool{},
		nodes: map[string]poolToCIDRs{},
	}
}

func (p *PoolAllocator) RestoreFinished() {
	p.ready = true
}

func (p *PoolAllocator) AddPool(poolName string, ipv4CIDRs []string, ipv4MaskSize int, ipv6CIDRs []string, ipv6MaskSize int) error {
	if _, ok := p.pools[poolName]; ok {
		return fmt.Errorf("pool %q already exists", poolName)
	}

	v4, err := cidralloc.NewCIDRSets(false, ipv4CIDRs, ipv4MaskSize)
	if err != nil {
		return err
	}

	v6, err := cidralloc.NewCIDRSets(true, ipv6CIDRs, ipv6MaskSize)
	if err != nil {
		return err
	}

	p.pools[poolName] = cidrPool{
		v4: v4,
		v6: v6,
	}

	return nil
}

func (p *PoolAllocator) AllocateToNode(cn *v2.CiliumNode) error {
	// We first need to check for CIDRs which we want to occupy, i.e. mark as
	// allocated to the node. This needs to happen before allocations, to avoid
	// handing out the same CIDR twice.
	var err error

	allocatedSet := make(map[string]map[netip.Prefix]struct{}, len(cn.Spec.IPAM.Pools.Allocated))
	for _, allocatedPool := range cn.Spec.IPAM.Pools.Allocated {
		allocatedSet[allocatedPool.Pool] = make(map[netip.Prefix]struct{}, len(allocatedPool.CIDRs))

		for _, cidrStr := range allocatedPool.CIDRs {
			prefix, parseErr := netip.ParsePrefix(string(cidrStr))
			if parseErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to parse CIDR of pool %q: %w", allocatedPool.Pool, parseErr))
				continue
			}

			occupyErr := p.occupyCIDR(cn.Name, allocatedPool.Pool, prefix)
			if occupyErr != nil {
				err = errors.Join(err, occupyErr)
			}

			allocatedSet[allocatedPool.Pool][prefix] = struct{}{}
		}
	}

	// release any cidrs no longer present in allocatedPool
	for poolName := range p.nodes[cn.Name] {
		retainErrs := p.retainCIDRs(cn.Name, poolName, allocatedSet[poolName])
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

	for _, reqPool := range cn.Spec.IPAM.Pools.Requested {
		allocatedCIDRs := p.nodes[cn.Name][reqPool.Pool]

		if option.Config.EnableIPv4 {
			neededIPv4Addrs := big.NewInt(int64(reqPool.Needed.IPv4Addrs))
			toAllocate := neededIPv4Addrs.Sub(neededIPv4Addrs, allocatedCIDRs.v4.availableAddrs())

			allocErr := p.allocateCIDRs(cn.Name, reqPool.Pool, ipam.IPv4, toAllocate)
			if allocErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to allocate ipv4 address for node %q from pool %q: %w",
						cn.Name, reqPool.Pool, allocErr))
			}
		}
		if option.Config.EnableIPv6 {
			neededIPv6Addrs := big.NewInt(int64(reqPool.Needed.IPv6Addrs))
			toAllocate := neededIPv6Addrs.Sub(neededIPv6Addrs, allocatedCIDRs.v6.availableAddrs())

			allocErr := p.allocateCIDRs(cn.Name, reqPool.Pool, ipam.IPv6, toAllocate)
			if allocErr != nil {
				err = errors.Join(err,
					fmt.Errorf("failed to allocate ipv6 address for node %q from pool %q: %w",
						cn.Name, reqPool.Pool, allocErr))
			}
		}
	}
	return err
}

func (p *PoolAllocator) ReleaseNode(nodeName string) error {
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
	for poolName, cidrs := range p.nodes[targetNode] {
		v4CIDRs := cidrs.v4.PodCIDRSlice()
		v6CIDRs := cidrs.v6.PodCIDRSlice()

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

	log.WithFields(logrus.Fields{
		"targetNode": targetNode,
		"sourcePool": sourcePool,
		"family":     family,
		"toAllocate": toAllocate,
	}).Debug("allocating cidr")

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

	log.WithFields(logrus.Fields{
		"targetNode": targetNode,
		"sourcePool": sourcePool,
		"cidr":       cidr.String(),
	}).Debug("occupying cidr")

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

func (p *PoolAllocator) releaseCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// do not release CIDRs not allocated to the node
	if !p.isAllocated(targetNode, sourcePool, cidr) {
		return nil
	}

	log.WithFields(logrus.Fields{
		"targetNode": targetNode,
		"sourcePool": sourcePool,
		"cidr":       cidr.String(),
	}).Debug("releasing cidr")

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
