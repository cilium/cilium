// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidralloc

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

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
	SetReservedRanges(ranges []netipx.IPRange) error
}
