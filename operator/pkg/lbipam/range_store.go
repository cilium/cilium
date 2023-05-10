// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"bytes"
	"fmt"
	"net"

	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type rangesStore struct {
	ranges       []*LBRange
	poolToRanges map[string][]*LBRange
}

func newRangesStore() rangesStore {
	return rangesStore{
		poolToRanges: make(map[string][]*LBRange),
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

type LBRange struct {
	// the actual data of which ips have been allocated or not
	allocRange *ipallocator.Range
	// If true, the LB range has been disabled via the CRD and thus no IPs should be allocated from this range
	externallyDisabled bool
	// If true, the LB range has been disabled by us, because it conflicts with other ranges for example.
	// This range should not be used for allocation.
	internallyDisabled bool
	// The name of the pool that originated this LB range
	originPool string
}

func NewLBRange(cidr *net.IPNet, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (*LBRange, error) {
	allocRange, err := ipallocator.NewCIDRRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("new cidr range: %w", err)
	}

	return &LBRange{
		allocRange:         allocRange,
		internallyDisabled: false,
		externallyDisabled: pool.Spec.Disabled,
		originPool:         pool.GetName(),
	}, nil
}

func (lr *LBRange) Disabled() bool {
	return lr.internallyDisabled || lr.externallyDisabled
}

func (lr *LBRange) String() string {
	cidr := lr.allocRange.CIDR()
	return fmt.Sprintf(
		"%s (free: %d, used: %d, intDis: %v, extDis: %v) - origin %s",
		cidr.String(),
		lr.allocRange.Free(),
		lr.allocRange.Used(),
		lr.internallyDisabled,
		lr.externallyDisabled,
		lr.originPool,
	)
}

func (lr *LBRange) Equal(other *LBRange) bool {
	lrCidr := lr.allocRange.CIDR()
	otherCidr := other.allocRange.CIDR()
	return lrCidr.IP.Equal(otherCidr.IP) && bytes.Equal(lrCidr.Mask, otherCidr.Mask)
}

func (lr *LBRange) EqualCIDR(cidr *net.IPNet) bool {
	lrCidr := lr.allocRange.CIDR()
	return lrCidr.IP.Equal(cidr.IP) && bytes.Equal(lrCidr.Mask, cidr.Mask)
}

func ipNetStr(net net.IPNet) string {
	ptr := &net
	return ptr.String()
}

// areRangesInternallyConflicting checks if any of the ranges within the same list conflict with each other.
func areRangesInternallyConflicting(ranges []*LBRange) (conflicting bool, rangeA, rangeB *LBRange) {
	for i, outer := range ranges {
		for ii, inner := range ranges {
			if i == ii {
				continue
			}

			if !intersect(outer.allocRange.CIDR(), inner.allocRange.CIDR()) {
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
			// IPs of dissimilar IP families can't overlap
			outerIsIpv4 := outerRange.allocRange.CIDR().IP.To4() != nil
			innerIsIpv4 := innerRange.allocRange.CIDR().IP.To4() != nil
			if innerIsIpv4 != outerIsIpv4 {
				continue
			}

			// no intersection, no conflict
			if !intersect(outerRange.allocRange.CIDR(), innerRange.allocRange.CIDR()) {
				continue
			}

			return true, outerRange, innerRange
		}
	}

	return false, nil, nil
}

func intersect(n1, n2 net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}
