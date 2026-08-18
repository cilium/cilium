// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"errors"
	"net"
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

// IPToNetPrefix is a convenience helper for migrating from the older 'net'
// standard library types to the newer 'netip' types. Use this to plug the new
// types in newer code into older types in older code during the migration.
//
// Note: This function assumes given ip is not an IPv4 mapped IPv6 address.
//
// The problem behind this is that when we convert the IPv4 net.IP address with
// netip.AddrFromSlice, the address is interpreted as an IPv4 mapped IPv6 address in some
// cases.
//
// For example, when we do netip.AddrFromSlice(net.ParseIP("1.1.1.1")), it is interpreted
// as an IPv6 address "::ffff:1.1.1.1". This is because 1) net.IP created with
// net.ParseIP(IPv4 string) holds IPv4 address as an IPv4 mapped IPv6 address internally
// and 2) netip.AddrFromSlice recognizes address family with length of the slice (4-byte =
// IPv4 and 16-byte = IPv6).
//
// By using netipx.FromStdIP, we can preserve the address family, but since we cannot distinguish
// IPv4 and IPv4 mapped IPv6 address only from net.IP value (see #37921 on golang/go) we
// need an assumption that given net.IP is not an IPv4 mapped IPv6 address.
func IPToNetPrefix(ip net.IP) netip.Prefix {
	a, ok := netipx.FromStdIP(ip)
	if !ok {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a, a.BitLen())
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
