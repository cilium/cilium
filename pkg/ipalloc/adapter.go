// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipalloc

import (
	"errors"
	"net"
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
func (saa *ServiceAllocatorAdapter) Allocate(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return errors.New("Invalid IP address")
	}

	return saa.inner.Alloc(addr, true)
}

// AllocateNext allocates the next available IP address.
func (saa *ServiceAllocatorAdapter) AllocateNext() (net.IP, error) {
	addr, err := saa.inner.AllocAny(true)
	if err != nil {
		return nil, err
	}

	return addr.AsSlice(), nil
}

// Release releases the given IP address.
func (saa *ServiceAllocatorAdapter) Release(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return errors.New("Invalid IP address")
	}

	return saa.inner.Free(addr)
}

// ForEach calls the given function for each allocated IP address.
func (saa *ServiceAllocatorAdapter) ForEach(fn func(net.IP)) {
	saa.inner.ForEach(func(addr netip.Addr, val bool) error {
		fn(addr.AsSlice())
		return nil
	})
}

// CIDR returns the best approximation of a CIDR of the IP range managed by this allocator.
// Some ranges can't be converted to an equal CIDR, so this CIDR should not be used for anything
// other than user feedback.
func (saa *ServiceAllocatorAdapter) CIDR() net.IPNet {
	startAddr, stopAddr := saa.inner.Range()
	start := startAddr.AsSlice()
	stop := stopAddr.AsSlice()
	return ipRangeToIPNet(start, stop)
}

func ipRangeToIPNet(start, stop net.IP) net.IPNet {
	var mask net.IPMask
	if start.To4() == nil {
		mask = make(net.IPMask, 16)
	} else {
		mask = make(net.IPMask, 4)
		start = start.To4()
		stop = stop.To4()
	}

	for i := range mask {
		if start[i] == stop[i] {
			mask[i] = 255
			continue
		}

		// Find the first bit that differs
		for ii := 7; ii >= 0; ii-- {
			if (start[i] & (1 << (ii))) == (stop[i] & (1 << (ii))) {
				mask[i] |= 1 << ii
				continue
			}
			break
		}
	}

	return net.IPNet{
		IP:   start.To16(),
		Mask: mask,
	}
}

// Has returns true if the given IP address is allocated.
func (saa *ServiceAllocatorAdapter) Has(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}

	_, found := saa.inner.Get(addr)
	return found
}
