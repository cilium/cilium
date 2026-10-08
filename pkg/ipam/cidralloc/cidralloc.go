// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidralloc

import (
	"fmt"
	"math/big"
	"net/netip"

	"go4.org/netipx"
)

// RangesToReserve holds a bitmap representation of the CIDRs that must be excluded from new
// allocations. The way the underlying bitmap (accessible through Bitmap()) encodes the range is up
// to the user.
type RangesToReserve struct {
	bitmap *big.Int
}

// NewRangesToReserve creates a new empty set of ranges to reserve (i.e.: the initial bitmap is
// zeroed).
func NewRangesToReserve() RangesToReserve {
	return RangesToReserve{bitmap: big.NewInt(0)}
}

// Bitmap returns the underlying bitmap representation.
func (r *RangesToReserve) Bitmap() *big.Int {
	return r.bitmap
}

type CIDRAllocator interface {
	fmt.Stringer

	Occupy(prefix netip.Prefix) error
	AllocateNext() (netip.Prefix, error)
	Release(prefix netip.Prefix) error
	IsAllocated(prefix netip.Prefix) (bool, error)
	IsFull() bool
	InRange(prefix netip.Prefix) bool
	IsClusterCIDR(prefix netip.Prefix) bool
	Prefix() netip.Prefix
	ComputeRangesToReserve(ranges []netipx.IPRange) (RangesToReserve, error)
	SetReservedRanges(rangesToReserve RangesToReserve)
}
