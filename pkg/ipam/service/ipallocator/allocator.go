// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// Copyright The Kubernetes Authors.

package ipallocator

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/service/allocator"
)

// Interface manages the allocation of IP addresses out of a range. Interface
// should be threadsafe.
type Interface interface {
	Allocate(netip.Addr) error
	AllocateNext() (netip.Addr, error)
	Release(netip.Addr)
	ForEach(func(netip.Addr))
	Prefix() netip.Prefix
	Has(netip.Addr) bool
}

var (
	ErrFull              = errors.New("range is full")
	ErrAllocated         = errors.New("provided IP is already allocated")
	ErrMismatchedNetwork = errors.New("the provided network does not match the current range")
)

type ErrNotInRange struct {
	ValidRange netip.Prefix
}

func (e *ErrNotInRange) Error() string {
	return fmt.Sprintf("provided IP is not in the valid range. The range of valid IPs is %s", e.ValidRange)
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
//	r.base                     r.base + r.max
//	  |                              |
//	offset #0 of r.allocated   last offset of r.allocated
type Range struct {
	prefix netip.Prefix
	// base is a cached version of the start IP in the CIDR range as a *big.Int
	base *big.Int
	// max is the maximum size of the usable addresses in the range
	max int

	alloc allocator.Interface
}

var _ Interface = (*Range)(nil)

// NewCIDRRange creates a Range over a netip.Prefix, calling allocator.NewAllocationMap to construct
// the backing store. Returned Range excludes first (base) and last addresses (max) if provided cidr
// has more than 2 addresses.
func NewCIDRRange(prefix netip.Prefix) *Range {
	base := bigForAddr(prefix.Masked().Addr())
	size := rangeSize(prefix)

	// for any CIDR other than /32 or /128:
	if size > 2 {
		// don't use the network broadcast
		size = max(0, size-2)
		// don't use the network base
		base = base.Add(base, big.NewInt(1))
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

// Prefix returns the IP prefix covered by the range.
func (r *Range) Prefix() netip.Prefix {
	return r.prefix
}

// Allocate attempts to reserve the provided IP. ErrNotInRange or
// ErrAllocated will be returned if the IP is not valid for this range
// or has already been reserved.  ErrFull will be returned if there
// are no addresses left.
func (r *Range) Allocate(addr netip.Addr) error {
	ok, offset := r.contains(addr)
	if !ok {
		return &ErrNotInRange{r.prefix}
	}

	allocated, err := r.alloc.Allocate(offset)
	if err != nil {
		return err
	}
	if !allocated {
		return ErrAllocated
	}
	return nil
}

// AllocateNext reserves one of the IPs from the pool. ErrFull may
// be returned if there are no addresses left.
func (r *Range) AllocateNext() (netip.Addr, error) {
	offset, ok, err := r.alloc.AllocateNext()
	if err != nil {
		return netip.Addr{}, err
	}
	if !ok {
		return netip.Addr{}, ErrFull
	}
	return addAddrOffset(r.base, offset), nil
}

// Release releases the IP back to the pool. Releasing an
// unallocated IP or an IP out of the range is a no-op and
// returns no error.
func (r *Range) Release(addr netip.Addr) {
	ok, offset := r.contains(addr)
	if ok {
		r.alloc.Release(offset)
	}
}

// ForEach calls the provided function for each allocated IP.
func (r *Range) ForEach(fn func(netip.Addr)) {
	r.alloc.ForEach(func(offset int) {
		addr, _ := GetIndexedIP(r.prefix, offset+1) // +1 because Range doesn't store IP 0
		fn(addr)
	})
}

// Has returns true if the provided IP is already allocated and a call
// to Allocate(addr) would fail with ErrAllocated.
func (r *Range) Has(addr netip.Addr) bool {
	ok, offset := r.contains(addr)
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
// is returned if the provided prefix range doesn't exactly match the previous range.
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
// and nil otherwise. The first and last addresses of the CIDR are omitted.
func (r *Range) contains(addr netip.Addr) (bool, int) {
	if !r.prefix.Contains(addr) {
		return false, 0
	}

	offset := calculateIPOffset(r.base, addr)
	if offset < 0 || offset >= r.max {
		return false, 0
	}
	return true, offset
}

// bigForAddr creates a big.Int based on the provided netip.Addr
func bigForAddr(addr netip.Addr) *big.Int {
	// NOTE: Convert to 16-byte representation so we can
	// handle v4 and v6 values the same way.
	b := addr.As16()
	return big.NewInt(0).SetBytes(b[:])
}

// addAddrOffset adds the provided integer offset to a base big.Int representing a netip.Addr
// NOTE: If you started with a v4 address and overflow it, you get a v6 result.
func addAddrOffset(base *big.Int, offset int) netip.Addr {
	r := big.NewInt(0).Add(base, big.NewInt(int64(offset))).Bytes()
	r = append(make([]byte, 16), r...)
	return netip.AddrFrom16([16]byte(r[len(r)-16:])).Unmap()
}

// calculateIPOffset calculates the integer offset of addr from base such that
// base + offset = addr. It requires addr >= base.
func calculateIPOffset(base *big.Int, addr netip.Addr) int {
	return int(big.NewInt(0).Sub(bigForAddr(addr), base).Int64())
}

// rangeSize returns the size of a range in valid addresses.
func rangeSize(prefix netip.Prefix) int64 {
	ones := prefix.Bits()
	bits := prefix.Addr().BitLen()
	if bits == 32 && (bits-ones) >= 31 || bits == 128 && (bits-ones) >= 127 {
		return 0
	}
	// For IPv6, the max size will be limited to 65536
	// This is due to the allocator keeping track of all the
	// allocated IP's in a bitmap. This will keep the size of
	// the bitmap to 64k.
	if bits == 128 && (bits-ones) >= 16 {
		return int64(1) << uint(16)
	} else {
		return int64(1) << uint(bits-ones)
	}
}

// GetIndexedIP returns a netip.Addr that is prefix.Addr() + index in the contiguous IP space.
func GetIndexedIP(prefix netip.Prefix, index int) (netip.Addr, error) {
	addr := prefix.Addr()
	for range index {
		addr = addr.Next()
	}
	if !prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("can't generate IP with index %d from subnet. subnet too small. subnet: %q", index, prefix)
	}
	return addr, nil
}
