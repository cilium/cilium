// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"fmt"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
)

var (
	errPoolEmpty = errors.New("pool empty")
)

func allocFirstFreeCIDR(allocators []cidralloc.CIDRAllocator) (netip.Prefix, error) {
	for _, alloc := range allocators {
		if alloc.IsFull() {
			continue
		}

		ipnet, err := alloc.AllocateNext()
		if err != nil {
			return netip.Prefix{}, err
		}

		prefix, ok := netipx.FromStdIPNet(ipnet)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %s allocated", ipnet)
		}
		return prefix, nil
	}

	return netip.Prefix{}, errPoolEmpty
}

func occupyCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	ipnet := ip.PrefixToIPNet(cidr)
	for _, alloc := range allocators {
		if !alloc.InRange(ipnet) {
			continue
		}
		if alloc.IsFull() {
			return errPoolEmpty
		}
		allocated, err := alloc.IsAllocated(ipnet)
		if err != nil {
			return err
		}
		if allocated {
			return fmt.Errorf("cidr %s has already been allocated", cidr)
		}

		return alloc.Occupy(ipnet)
	}

	return fmt.Errorf("cidr %s is not part of the requested pool", cidr)
}

func releaseCIDR(allocators []cidralloc.CIDRAllocator, cidr netip.Prefix) error {
	ipnet := ip.PrefixToIPNet(cidr)
	for _, alloc := range allocators {
		if !alloc.InRange(ipnet) {
			continue
		}

		allocated, err := alloc.IsAllocated(ipnet)
		if err != nil {
			return err
		}
		if !allocated {
			return nil // not an error to release a cidr twice
		}

		return alloc.Release(ipnet)
	}

	return fmt.Errorf("released cidr %s was not part the pool", cidr)
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
