// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

type hostScopeAllocator struct {
	allocCIDR netip.Prefix
	allocator *ipallocator.Range
}

func newHostScopeAllocator(prefix netip.Prefix) Allocator {
	return &hostScopeAllocator{
		allocCIDR: prefix,
		allocator: ipallocator.NewCIDRRange(prefix),
	}
}

func (h *hostScopeAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(addr); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: addr}, nil
}

func (h *hostScopeAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	if err := h.allocator.Allocate(addr); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: addr}, nil
}

func (h *hostScopeAllocator) Release(addr netip.Addr, pool Pool) error {
	h.allocator.Release(addr)
	return nil
}

func (h *hostScopeAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	addr, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: addr}, nil
}

func (h *hostScopeAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	addr, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: addr}, nil
}

func (h *hostScopeAllocator) Dump() (map[Pool]map[string]string, string) {
	alloc := map[string]string{}
	h.allocator.ForEach(func(addr netip.Addr) {
		alloc[addr.String()] = ""
	})

	maxIPs := ip.CountIPsInCIDR(netipx.PrefixIPNet(h.allocCIDR))
	status := fmt.Sprintf("%d/%s allocated from %s", len(alloc), maxIPs.String(), h.allocCIDR.String())

	return map[Pool]map[string]string{PoolDefault(): alloc}, status
}

func (h *hostScopeAllocator) Capacity() uint64 {
	return ip.CountIPsInCIDR(netipx.PrefixIPNet(h.allocCIDR)).Uint64()
}

// RestoreFinished marks the status of restoration as done
func (h *hostScopeAllocator) RestoreFinished() {}
