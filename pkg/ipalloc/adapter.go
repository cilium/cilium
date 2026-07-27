// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"math/bits"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
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
func (saa *ServiceAllocatorAdapter) Release(addr netip.Addr) error {
	return saa.inner.Free(addr)
}

// ForEach calls the given function for each allocated IP address.
func (saa *ServiceAllocatorAdapter) ForEach(fn func(netip.Addr)) {
	saa.inner.ForEach(func(addr netip.Addr, val bool) error {
		fn(addr)
		return nil
	})
}

// CIDR returns the best approximation of a CIDR of the IP range managed by this allocator.
// Some ranges can't be converted to an equal CIDR, so this CIDR should not be used for anything
// other than user feedback.
func (saa *ServiceAllocatorAdapter) CIDR() netip.Prefix {
	start, stop := saa.inner.Range()
	return ipRangeToPrefix(start, stop)
}

// ipRangeToPrefix computes the smallest netip.Prefix that contains both start
// and stop addresses.
func ipRangeToPrefix(start, stop netip.Addr) netip.Prefix {
	var prefixLen int
	if start.Is4() {
		s := start.As4()
		e := stop.As4()
		prefixLen = commonPrefixBits(s[:], e[:])
	} else {
		s := start.As16()
		e := stop.As16()
		prefixLen = commonPrefixBits(s[:], e[:])
	}
	prefix, _ := start.Prefix(prefixLen)
	return prefix
}

// commonPrefixBits returns the number of leading bits that are identical
// between a and b.
func commonPrefixBits(a, b []byte) int {
	n := 0
	for i := range a {
		xor := a[i] ^ b[i]
		if xor == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(xor)
		break
	}
	return n
}

// Has returns true if the given IP address is allocated.
func (saa *ServiceAllocatorAdapter) Has(addr netip.Addr) bool {
	_, found := saa.inner.Get(addr)
	return found
}
