// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// Copyright The Kubernetes Authors.

package ipallocator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/service/allocator"
)

// Interface manages the allocation of IP addresses out of a range. Interface
// should be threadsafe.
type Interface interface {
	Allocate(netip.Addr) error
	AllocateNext() (netip.Addr, error)
	Release(netip.Addr) error
	ForEach(func(netip.Addr))
	CIDR() netip.Prefix
	Has(addr netip.Addr) bool
}

var (
	ErrFull              = errors.New("range is full")
	ErrAllocated         = errors.New("provided IP is already allocated")
	ErrMismatchedNetwork = errors.New("the provided network does not match the current range")
)

type ErrNotInRange struct {
	ValidRange string
}

func (e *ErrNotInRange) Error() string {
	return fmt.Sprintf("provided IP is not in the valid range. The range of valid IPs is %s", e.ValidRange)
}

// CIDRRangeOption is a functional option for NewCIDRRange.
type CIDRRangeOption func(*cidrRangeOptions)

type cidrRangeOptions struct {
	allowFirstLastIPs bool
}

// WithAllowFirstLastIPs configures the Range to include the first and last IPs
// of the CIDR (normally reserved as network and broadcast addresses). This is
// useful for delegated prefixes (e.g. AWS /28 prefix delegation) where the
// entire range is exclusively assigned and there is no shared network segment.
func WithAllowFirstLastIPs() CIDRRangeOption {
	return func(o *cidrRangeOptions) {
		o.allowFirstLastIPs = true
	}
}

// Range is a contiguous block of IPs that can be allocated atomically.
//
// The internal structure of the range is:
//
//	For CIDR 10.0.0.0/24
//	254 addresses usable out of 256 total (minus base and broadcast IPs)
//	  The number of usable addresses is r.max
//
//	CIDR base IP          CIDR broadcast IP
//	10.0.0.0                     10.0.0.255
//	|                                     |
//	0 1 2 3 4 5 ...         ... 253 254 255
//	  |                              |
//	r.base               addOffset(r.base, r.max-1)
//	  |                              |
//	offset #0 of r.alloc   last offset of r.alloc
type Range struct {
	prefix netip.Prefix
	// base is the first allocatable address in the range.
	base netip.Addr
	// max is the maximum size of the usable addresses in the range.
	max int

	alloc allocator.Interface
}

// NewCIDRRange creates a Range over a netip.Prefix, calling allocator.NewAllocationMap
// to construct the backing store. By default, the first (network) and last
// (broadcast) addresses are excluded for CIDRs with more than 2 addresses.
// Pass functional options (e.g. WithAllowFirstLastIPs) to alter this behavior.
func NewCIDRRange(prefix netip.Prefix, opts ...CIDRRangeOption) *Range {
	var o cidrRangeOptions
	for _, opt := range opts {
		opt(&o)
	}

	prefix = prefix.Masked()
	base := prefix.Addr()
	size := RangeSize(prefix)

	// for any CIDR other than /32 or /128:
	if size > 2 && !o.allowFirstLastIPs {
		// don't use the network broadcast
		size = max(0, size-2)
		// don't use the network base
		base = base.Next()
	}

	return &Range{
		prefix: prefix,
		base:   base,
		max:    int(size),
		alloc:  allocator.NewAllocationMap(int(size), prefix.String()),
	}
}

// Free returns the count of IP addresses left in the range.
func (r *Range) Free() int {
	return r.alloc.Free()
}

// Used returns the count of IP addresses used in the range.
func (r *Range) Used() int {
	return r.max - r.alloc.Free()
}

// CIDR returns the CIDR covered by the range.
func (r *Range) CIDR() netip.Prefix {
	return r.prefix
}

// Allocate attempts to reserve the provided IP. ErrNotInRange or
// ErrAllocated will be returned if the IP is not valid for this range
// or has already been reserved.  ErrFull will be returned if there
// are no addresses left.
func (r *Range) Allocate(ip netip.Addr) error {
	ok, offset := r.contains(ip)
	if !ok {
		return &ErrNotInRange{r.prefix.String()}
	}

	allocated := r.alloc.Allocate(offset)
	if !allocated {
		return ErrAllocated
	}
	return nil
}

// AllocateNext reserves one of the IPs from the pool. ErrFull may
// be returned if there are no addresses left.
func (r *Range) AllocateNext() (netip.Addr, error) {
	offset, ok := r.alloc.AllocateNext()
	if !ok {
		return netip.Addr{}, ErrFull
	}
	return addOffset(r.base, offset), nil
}

// Release releases the IP back to the pool. Releasing an
// unallocated IP or an IP out of the range is a no-op and
// returns no error.
func (r *Range) Release(ip netip.Addr) {
	ok, offset := r.contains(ip)
	if ok {
		r.alloc.Release(offset)
	}
}

// ForEach calls the provided function for each allocated IP.
func (r *Range) ForEach(fn func(netip.Addr)) {
	r.alloc.ForEach(func(offset int) {
		fn(addOffset(r.base, offset))
	})
}

// Has returns true if the provided IP is already allocated and a call
// to Allocate(ip) would fail with ErrAllocated.
func (r *Range) Has(ip netip.Addr) bool {
	ok, offset := r.contains(ip)
	if !ok {
		return false
	}

	return r.alloc.Has(offset)
}

// Snapshot saves the current state of the pool.
func (r *Range) Snapshot() (string, []byte, error) {
	snapshottable, ok := r.alloc.(allocator.Snapshottable)
	if !ok {
		return "", nil, fmt.Errorf("not a snapshottable allocator")
	}
	str, data := snapshottable.Snapshot()
	return str, data, nil
}

// Restore restores the pool to the previously captured state. ErrMismatchedNetwork
// is returned if the provided prefix doesn't exactly match the previous range.
func (r *Range) Restore(prefix netip.Prefix, data []byte) error {
	if prefix != r.prefix {
		return ErrMismatchedNetwork
	}
	snapshottable, ok := r.alloc.(allocator.Snapshottable)
	if !ok {
		return fmt.Errorf("not a snapshottable allocator")
	}
	if err := snapshottable.Restore(prefix.String(), data); err != nil {
		return fmt.Errorf("restoring snapshot encountered: %w", err)
	}
	return nil
}

// contains returns true and the offset if the ip is in the range, and false
// and 0 otherwise.
func (r *Range) contains(ip netip.Addr) (bool, int) {
	if !r.prefix.Contains(ip) {
		return false, 0
	}

	offset := addrOffset(r.base, ip)
	if offset < 0 || offset >= r.max {
		return false, 0
	}
	return true, offset
}

// addOffset adds an integer offset to a base address.
func addOffset(base netip.Addr, offset int) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := binary.BigEndian.Uint32(b[:]) + uint32(offset)
		binary.BigEndian.PutUint32(b[:], v)
		return netip.AddrFrom4(b)
	}
	b := base.As16()
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	newLo := lo + uint64(offset)
	if newLo < lo {
		hi++
	}
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], newLo)
	return netip.AddrFrom16(b)
}

// addrOffset returns the integer offset of addr from base (addr - base).
func addrOffset(base, addr netip.Addr) int {
	if base.Is4() {
		b := base.As4()
		a := addr.As4()
		return int(binary.BigEndian.Uint32(a[:]) - binary.BigEndian.Uint32(b[:]))
	}
	b := base.As16()
	a := addr.As16()
	return int(binary.BigEndian.Uint64(a[8:]) - binary.BigEndian.Uint64(b[8:]))
}

// RangeSize returns the size of a range in valid addresses.
func RangeSize(prefix netip.Prefix) int64 {
	bits := prefix.Addr().BitLen()
	ones := prefix.Bits()
	if bits == 32 && (bits-ones) >= 31 || bits == 128 && (bits-ones) >= 127 {
		return 0
	}
	// For IPv6, the max size will be limited to 65536
	// This is due to the allocator keeping track of all the
	// allocated IP's in a bitmap. This will keep the size of
	// the bitmap to 64k.
	if bits == 128 && (bits-ones) >= 16 {
		return int64(1) << uint(16)
	}
	return int64(1) << uint(bits-ones)
}
