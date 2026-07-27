// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidralloc

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/cidrset"
)

type CIDRAllocator interface {
	fmt.Stringer

	Occupy(prefix netip.Prefix) error
	AllocateNext() (netip.Prefix, error)
	Release(prefix netip.Prefix) error
	IsAllocated(prefix netip.Prefix) (bool, error)
	IsFull() bool
	InRange(prefix netip.Prefix) bool
	IsClusterCIDR(prefix netip.Prefix) bool
	Prefix() netip.Prefix
}

type ErrCIDRCollision struct {
	cidr      string
	allocator CIDRAllocator
}

func (e ErrCIDRCollision) Error() string {
	return fmt.Sprintf("requested CIDR %s collides with %s", e.cidr, e.allocator)
}

func (e *ErrCIDRCollision) Is(target error) bool {
	t, ok := target.(*ErrCIDRCollision)
	if !ok {
		return false
	}
	return t.cidr == e.cidr
}

func NewCIDRSets(isV6 bool, strCIDRs []string, maskSize int) ([]CIDRAllocator, error) {
	cidrAllocators := make([]CIDRAllocator, 0, len(strCIDRs))
	for _, strCIDR := range strCIDRs {
		prefix, err := netip.ParsePrefix(strCIDR)
		if err != nil {
			return nil, err
		}
		// Check if CIDRs collide with each other.
		for _, cidrAllocator := range cidrAllocators {
			if cidrAllocator.InRange(prefix) {
				return nil, &ErrCIDRCollision{
					cidr:      strCIDR,
					allocator: cidrAllocator,
				}
			}
		}

		addr := prefix.Addr()
		switch {
		case isV6 && addr.Is4():
			return nil, fmt.Errorf("CIDR is not v6 family: %s", prefix)
		case !isV6 && !addr.Is4():
			return nil, fmt.Errorf("CIDR is not v4 family: %s", prefix)
		}
		cidrSet, err := cidrset.NewCIDRSet(prefix, maskSize)
		if err != nil {
			return nil, err
		}
		cidrAllocators = append(cidrAllocators, cidrSet)
	}
	return cidrAllocators, nil
}
