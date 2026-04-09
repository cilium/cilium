// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

type hostScopeAllocator struct {
	allocCIDR netip.Prefix
	allocator *ipallocator.Range
}

func newHostScopeAllocator(n *net.IPNet) Allocator {
	prefix, ok := netipx.FromStdIPNet(n)
	if !ok {
		panic(fmt.Sprintf("invalid IPNet: %v", n))
	}
	return &hostScopeAllocator{
		allocCIDR: prefix,
		allocator: ipallocator.NewCIDRRange(prefix),
	}
}

func (h *hostScopeAllocator) Allocate(ipAddr net.IP, owner string, pool Pool) (*AllocationResult, error) {
	addr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		return nil, fmt.Errorf("invalid IP address: %v", ipAddr)
	}
	if err := h.allocator.Allocate(addr.Unmap()); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ipAddr}, nil
}

func (h *hostScopeAllocator) AllocateWithoutSyncUpstream(ipAddr net.IP, owner string, pool Pool) (*AllocationResult, error) {
	addr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		return nil, fmt.Errorf("invalid IP address: %v", ipAddr)
	}
	if err := h.allocator.Allocate(addr.Unmap()); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ipAddr}, nil
}

func (h *hostScopeAllocator) Release(ipAddr net.IP, pool Pool) error {
	addr, ok := netip.AddrFromSlice(ipAddr)
	if !ok {
		return nil
	}
	h.allocator.Release(addr.Unmap())
	return nil
}

func (h *hostScopeAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	addr, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: net.IP(addr.AsSlice()).To16()}, nil
}

func (h *hostScopeAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	addr, err := h.allocator.AllocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: net.IP(addr.AsSlice()).To16()}, nil
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
