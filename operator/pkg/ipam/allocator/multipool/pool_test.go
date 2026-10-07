// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/ipam/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/cidrset"
)

func TestOccupyReservedCIDR(t *testing.T) {
	allocator, err := cidrset.NewCIDRSet(netip.MustParsePrefix("10.0.0.0/30"), 31)
	if err != nil {
		t.Fatalf("NewCIDRSet() returned an unexpected error: %v", err)
	}

	reserved := netipx.IPRangeFrom(
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.3"),
	)

	rangesToReserve, err := allocator.ComputeRangesToReserve([]netipx.IPRange{reserved})
	if err != nil {
		t.Fatalf("ComputeRangesToReserve() returned an unexpected error: %v", err)
	}
	allocator.SetReservedRanges(rangesToReserve)

	cidr := netip.MustParsePrefix("10.0.0.0/31")
	if err := occupyCIDR([]cidralloc.CIDRAllocator{allocator}, cidr); err != nil {
		t.Fatalf("occupyCIDR() returned an unexpected error: %v", err)
	}

	allocated, err := allocator.IsAllocated(cidr)
	if err != nil {
		t.Fatalf("IsAllocated() returned an unexpected error: %v", err)
	}
	assert.True(t, allocated)
}
