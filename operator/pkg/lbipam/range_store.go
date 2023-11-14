// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/ipalloc"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type rangesStore struct {
	ranges                     []*LBRange
	poolToRanges               map[string][]*LBRange
	sharingKeyToServiceViewIPs map[string][]*ServiceViewIP
}

func newRangesStore() rangesStore {
	return rangesStore{
		poolToRanges:               make(map[string][]*LBRange),
		sharingKeyToServiceViewIPs: make(map[string][]*ServiceViewIP),
	}
}

func (rs *rangesStore) Delete(lbRange *LBRange) {
	idx := slices.Index(rs.ranges, lbRange)
	if idx != -1 {
		rs.ranges = slices.Delete(rs.ranges, idx, idx+1)
	}

	poolRanges := rs.poolToRanges[lbRange.originPool]

	idx = slices.Index(poolRanges, lbRange)
	if idx != -1 {
		poolRanges = slices.Delete(poolRanges, idx, idx+1)
	}

	if len(poolRanges) > 0 {
		rs.poolToRanges[lbRange.originPool] = poolRanges
	} else {
		delete(rs.poolToRanges, lbRange.originPool)
	}
}

func (rs *rangesStore) Add(lbRange *LBRange) {
	rs.ranges = append(rs.ranges, lbRange)
	poolRanges := rs.poolToRanges[lbRange.originPool]
	poolRanges = append(poolRanges, lbRange)
	rs.poolToRanges[lbRange.originPool] = poolRanges
}

func (rs *rangesStore) GetRangesForPool(name string) ([]*LBRange, bool) {
	ranges, found := rs.poolToRanges[name]
	return ranges, found
}

func (rs *rangesStore) GetServiceViewIPsForSharingKey(sk string) ([]*ServiceViewIP, bool) {
	serviceViewIPs, found := rs.sharingKeyToServiceViewIPs[sk]
	return serviceViewIPs, found
}

func (rs *rangesStore) AddServiceViewIPForSharingKey(sk string, svip *ServiceViewIP) {
	serviceViewIPs, found := rs.sharingKeyToServiceViewIPs[sk]
	if !found {
		serviceViewIPs = make([]*ServiceViewIP, 0)
		serviceViewIPs = append(serviceViewIPs, svip)
	} else {
		for _, serviceViewIP := range serviceViewIPs {
			if *serviceViewIP == *svip {
				return
			}
		}
		serviceViewIPs = append(serviceViewIPs, svip)
	}
	rs.sharingKeyToServiceViewIPs[sk] = serviceViewIPs
}

func (rs *rangesStore) DeleteServiceViewIPForSharingKey(sk string, svip *ServiceViewIP) {
	serviceViewIPs, found := rs.sharingKeyToServiceViewIPs[sk]
	if !found {
		return
	}
	for i, serviceViewIP := range serviceViewIPs {
		if *serviceViewIP == *svip {
			serviceViewIPs = slices.Delete(serviceViewIPs, i, i+1)
			break
		}
	}
	if len(serviceViewIPs) > 0 {
		rs.sharingKeyToServiceViewIPs[sk] = serviceViewIPs
	} else {
		delete(rs.sharingKeyToServiceViewIPs, sk)
	}
}

type LBRange struct {
	// the actual data of which ips have been allocated or not and to what services
	alloc ipalloc.Allocator[[]*ServiceView]
	// If true, the LB range has been disabled via the CRD and thus no IPs should be allocated from this range
	externallyDisabled bool
	// If true, the LB range has been disabled by us, because it conflicts with other ranges for example.
	// This range should not be used for allocation.
	internallyDisabled bool
	// The name of the pool that originated this LB range
	originPool string
}

func NewLBRange(from, to netip.Addr, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (*LBRange, error) {
	alloc, err := ipalloc.NewHashAllocator[[]*ServiceView](from, to, 0)
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
