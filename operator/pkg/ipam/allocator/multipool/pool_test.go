// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"go4.org/netipx"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/clusterpool/cidralloc"
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
	if err := allocator.SetReservedRanges([]netipx.IPRange{reserved}); err != nil {
		t.Fatalf("SetReservedRanges() returned an unexpected error: %v", err)
	}

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
