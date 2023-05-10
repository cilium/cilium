// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidralloc

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/cidrset"
)

type CIDRAllocator interface {
	fmt.Stringer

	Occupy(cidr *net.IPNet) error
	AllocateNext() (*net.IPNet, error)
	Release(cidr *net.IPNet) error
	IsAllocated(cidr *net.IPNet) (bool, error)
	IsFull() bool
	InRange(cidr *net.IPNet) bool
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
		addr, cidr, err := net.ParseCIDR(strCIDR)
		if err != nil {
			return nil, err
		}
		// Check if CIDRs collide with each other.
		for _, cidrAllocator := range cidrAllocators {
			if cidrAllocator.InRange(cidr) {
				return nil, &ErrCIDRCollision{
					cidr:      strCIDR,
					allocator: cidrAllocator,
				}
			}
		}

		switch {
		case isV6 && ip.IsIPv4(addr):
			return nil, fmt.Errorf("CIDR is not v6 family: %s", cidr)
		case !isV6 && !ip.IsIPv4(addr):
			return nil, fmt.Errorf("CIDR is not v4 family: %s", cidr)
		}
		cidrSet, err := cidrset.NewCIDRSet(cidr, maskSize)
		if err != nil {
			return nil, err
		}
		cidrAllocators = append(cidrAllocators, cidrSet)
	}
	return cidrAllocators, nil
}
