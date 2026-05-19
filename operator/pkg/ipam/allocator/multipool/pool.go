// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam"
)

var (
	errPoolEmpty = errors.New("pool empty")
)

func allocFirstFreeCIDR(allocators []cidralloc.CIDRAllocator) (netip.Prefix, error) {
	for _, alloc := range allocators {
		if alloc.IsFull() {
			continue
		}

		return alloc.AllocateNext()
	}

	return netip.Prefix{}, errPoolEmpty
}

func occupyCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	for _, alloc := range allocators {
		if !alloc.InRange(cidr) {
			continue
		}
		if alloc.IsFull() {
			return errPoolEmpty
		}
		allocated, err := alloc.IsAllocated(cidr)
		if err != nil {
			return err
		}
		if allocated {
			return fmt.Errorf("cidr %s has already been allocated", cidr)
		}

		return alloc.Occupy(cidr)
	}

	return fmt.Errorf("cidr %s is not part of the requested pool", cidr)
}

func releaseCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	for _, alloc := range allocators {
		if !alloc.InRange(cidr) {
			continue
		}

		allocated, err := alloc.IsAllocated(cidr)
		if err != nil {
			return err
		}
		if !allocated {
			return nil // not an error to release a cidr twice
		}

		return alloc.Release(cidr)
	}

	return fmt.Errorf("released cidr %s was not part the pool", cidr)
}

func hasCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) bool {
	for _, alloc := range allocators {
		if alloc.IsClusterCIDR(cidr) {
			return true
		}
	}
	return false
}

func containsCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) bool {
	for _, alloc := range allocators {
		if alloc.InRange(cidr) {
			return true
		}
	}
	return false
}

func (c *cidrPool) allocCIDR(family ipam.Family) (netip.Prefix, error) {
	switch family {
	case ipam.IPv4:
		return allocFirstFreeCIDR(c.v4)
	case ipam.IPv6:
		return allocFirstFreeCIDR(c.v6)
	default:
		return netip.Prefix{}, fmt.Errorf("invalid cidr family: %s", family)
	}
}

func (c *cidrPool) occupyCIDR(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		return occupyCIDR(c.v4, cidr)
	} else {
		return occupyCIDR(c.v6, cidr)
	}
}

func (c *cidrPool) releaseCIDR(cidr netip.Prefix) error {
	if cidr.Addr().Is4() {
		return releaseCIDR(c.v4, cidr)
	} else {
		return releaseCIDR(c.v6, cidr)
	}
}

func (c *cidrPool) hasCIDR(cidr netip.Prefix) bool {
	if cidr.Addr().Is4() {
		return hasCIDR(c.v4, cidr)
	} else {
		return hasCIDR(c.v6, cidr)
	}
}
