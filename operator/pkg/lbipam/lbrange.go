// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipalloc"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type LBRange struct {
	// the actual data of which ips have been allocated or not and to what services
	alloc ipalloc.Allocator[*sharingCluster]
	// If true, the LB range has been disabled via the CRD and thus no IPs should be allocated from this range
	externallyDisabled bool
	// If true, the LB range has been disabled by us, because it conflicts with other ranges for example.
	// This range should not be used for allocation.
	internallyDisabled bool
	// The name of the pool that originated this LB range
	originPool string
}

func NewLBRange(from, to netip.Addr, pool *cilium_api_v2.CiliumLoadBalancerIPPool) (*LBRange, error) {
	alloc, err := ipalloc.NewHashAllocator[*sharingCluster](from, to, 0)
	if err != nil {
		return nil, fmt.Errorf("new cidr range: %w", err)
	}

	return &LBRange{
		alloc:              alloc,
		internallyDisabled: false,
		externallyDisabled: pool.Spec.Disabled,
		originPool:         pool.GetName(),
	}, err
}

func (lr *LBRange) Disabled() bool {
	return lr.internallyDisabled || lr.externallyDisabled
}

func (lr *LBRange) String() string {
	from, to := lr.alloc.Range()
	used, available := lr.alloc.Stats()
	return fmt.Sprintf(
		"%s - %s (free: %s, used: %d, intDis: %v, extDis: %v) - origin %s",
		from,
		to,
		available,
		used,
		lr.internallyDisabled,
		lr.externallyDisabled,
		lr.originPool,
	)
}

func (lr *LBRange) Equal(other *LBRange) bool {
	lrFrom, lrTo := lr.alloc.Range()
	otherFrom, otherTo := other.alloc.Range()
	return lrFrom == otherFrom && lrTo == otherTo
}

func (lr *LBRange) EqualCIDR(from, to netip.Addr) bool {
	lrFrom, lrTo := lr.alloc.Range()
	return lrFrom == from && lrTo == to
}

func ipNetStr(rng *LBRange) string {
	from, to := rng.alloc.Range()
	return fmt.Sprintf("%s - %s", from, to)
}

// areRangesInternallyConflicting checks if any of the ranges within the same list conflict with each other.
func areRangesInternallyConflicting(ranges []*LBRange) (conflicting bool, rangeA, rangeB *LBRange) {
	for i, outer := range ranges {
		for ii, inner := range ranges {
			if i == ii {
				continue
			}

			if !rangesIntersect(outer, inner) {
				continue
			}

			return true, outer, inner
		}
	}

	return false, nil, nil
}

func areRangesConflicting(outerRanges, innerRanges []*LBRange) (conflicting bool, targetRange, conflictingRange *LBRange) {
	for _, outerRange := range outerRanges {
		for _, innerRange := range innerRanges {
			// no intersection, no conflict
			if !rangesIntersect(outerRange, innerRange) {
				continue
			}

			return true, outerRange, innerRange
		}
	}

	return false, nil, nil
}

func rangesIntersect(one, two *LBRange) bool {
	oneFrom, oneTo := one.alloc.Range()
	twoFrom, twoTo := two.alloc.Range()
	return intersect(oneFrom, oneTo, twoFrom, twoTo)
}

func intersect(from1, to1, from2, to2 netip.Addr) bool {
	return from1.Compare(to2) <= 0 && from2.Compare(to1) <= 0
}
