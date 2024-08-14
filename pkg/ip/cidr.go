// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"net"
	"net/netip"

	"go4.org/netipx"
)

// ParseCIDRs fetches all CIDRs referred to by the specified slice and returns
// them as regular golang CIDR objects.
//
// Deprecated. Consider using ParsePrefixes() instead.
func ParseCIDRs(cidrs []string) (valid []*net.IPNet, invalid []string) {
	valid = make([]*net.IPNet, 0, len(cidrs))
	invalid = make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			// Likely the CIDR is specified in host format.
			ip := net.ParseIP(cidr)
			if ip == nil {
				invalid = append(invalid, cidr)
				continue
			} else {
				prefix = IPToPrefix(ip)
			}
		}
		if prefix != nil {
			valid = append(valid, prefix)
		}
	}
	return valid, invalid
}

// ParsePrefixes parses all CIDRs referred to by the specified slice and
// returns them as regular golang netip.Prefix objects.
func ParsePrefixes(cidrs []string) (valid []netip.Prefix, invalid []string, errors []error) {
	valid = make([]netip.Prefix, 0, len(cidrs))
	invalid = make([]string, 0, len(cidrs))
	errors = make([]error, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			ip, err2 := netip.ParseAddr(cidr)
			if err2 != nil {
				invalid = append(invalid, cidr)
				errors = append(errors, err2)
				continue
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		valid = append(valid, prefix.Masked())
	}

	return valid, invalid, errors
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

// IPsToNetPrefixes returns all of the ips as a slice of netip.Prefix.
//
// See IPToNetPrefix() for how net.IP types are handled by this function.
func IPsToNetPrefixes(ips []net.IP) []netip.Prefix {
	if len(ips) == 0 {
		return nil
	}
	res := make([]netip.Prefix, 0, len(ips))
	for _, ip := range ips {
		res = append(res, IPToNetPrefix(ip))
	}
	return res
}

// NetsContainsAny checks that any subnet in the `a` subnet group *fully*
// contains any of the subnets in the `b` subnet group.
func NetsContainsAny(a, b []*net.IPNet) bool {
	for _, an := range a {
		aMask, _ := an.Mask.Size()
		aIsIPv4 := an.IP.To4() != nil
		for _, bn := range b {
			bIsIPv4 := bn.IP.To4() != nil
			isSameFamily := aIsIPv4 == bIsIPv4
			if isSameFamily {
				bMask, _ := bn.Mask.Size()
				if bMask >= aMask && an.Contains(bn.IP) {
					return true
				}
			}
		}
	}
	return false
}
