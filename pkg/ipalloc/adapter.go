// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"go4.org/netipx"
)

var _ ipallocator.Interface = (*ServiceAllocatorAdapter)(nil)

// ServiceAllocatorAdapter is an adapter that converts the Allocator[bool] interface to the
// ipallocator.Interface interface.
type ServiceAllocatorAdapter struct {
	inner Allocator[bool]
}

// NewServiceAllocatorAdapter creates a new ServiceAllocatorAdapter.
func NewServiceAllocatorAdapter(alloc Allocator[bool]) ipallocator.Interface {
	return &ServiceAllocatorAdapter{
		inner: alloc,
	}
}

// Allocate allocates the given IP address.
func (saa *ServiceAllocatorAdapter) Allocate(addr netip.Addr) error {
	return saa.inner.Alloc(addr, true)
}

// AllocateNext allocates the next available IP address.
func (saa *ServiceAllocatorAdapter) AllocateNext() (netip.Addr, error) {
	return saa.inner.AllocAny(true)
}

// Release releases the given IP address.
func (saa *ServiceAllocatorAdapter) Release(addr netip.Addr) {
	saa.inner.Free(addr)
}

// ForEach calls the given function for each allocated IP address.
func (saa *ServiceAllocatorAdapter) ForEach(fn func(netip.Addr)) {
	saa.inner.ForEach(func(addr netip.Addr, val bool) error {
		fn(addr)
		return nil
	})
}

// Prefix returns the best approximation of a CIDR of the IP range managed by this allocator.
// Some ranges can't be converted to an equal CIDR, so this CIDR should not be used for anything
// other than user feedback.
func (saa *ServiceAllocatorAdapter) Prefix() netip.Prefix {
	startAddr, stopAddr := saa.inner.Range()
	return ipRangeToPrefix(startAddr, stopAddr)
}

func ipRangeToPrefix(start, stop netip.Addr) netip.Prefix {
	prefix, _ := netipx.IPRangeFrom(start, stop).Prefix()
	return prefix
}

// Has returns true if the given IP address is allocated.
func (saa *ServiceAllocatorAdapter) Has(addr netip.Addr) bool {
	_, found := saa.inner.Get(addr)
	return found
}
