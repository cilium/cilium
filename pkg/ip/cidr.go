// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"errors"
	"net/netip"
	"strings"

	"go4.org/netipx"
)

// ParsePrefixes parses all CIDRs referred to by the specified slice and
// returns them as regular golang netip.Prefix objects. A CIDR may also be
// given in host format, in which case it is parsed as a single-address
// prefix.
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	var errs []error
	for _, cidr := range cidrs {
		if !strings.ContainsRune(cidr, '/') {
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, errors.Join(errs...)
}

// PrefixesContains checks that any prefix in prefix *fully* contains addr.
func PrefixesContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, pfx := range prefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// LaminarCIDRsOverlap reports whether c1 and c2 overlap, i.e. one is contained
// within the other. CIDRs are laminar: two prefixes are either nested or
// disjoint, never partially overlapping, so checking containment in either
// direction is equivalent to checking that the two ranges intersect.
func LaminarCIDRsOverlap(c1, c2 netip.Prefix) bool {
	return c1.Contains(c2.Addr()) || c2.Contains(c1.Addr())
}

// CoalescePrefixes reduces the prefixes to the minimal equivalent set: prefixes
// contained in another one are dropped, and prefixes that together cover a
// contiguous range are merged into the shortest prefixes covering that range.
// The result is sorted by address family, IPv4 prefixes first.
//
// Ranges of different address families are never contiguous, so a single set
// coalesces both families independently.
//
// Invalid prefixes are dropped: netipx.IPSetBuilder only reports errors for the
// invalid inputs it was asked to add, so callers that need to reject them must
// validate before calling.
func CoalescePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	var builder netipx.IPSetBuilder

	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}

	set, _ := builder.IPSet()

	return set.Prefixes()
}
