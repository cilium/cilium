// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"net"
	"net/netip"
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

// PrefixToIPNet is a convenience helper for migrating from the older 'net'
// standard library types to the newer 'netip' types. Use this to plug the
// new types in newer code into older types in older code during the migration.
func PrefixToIPNet(prefix netip.Prefix) *net.IPNet {
	if !prefix.IsValid() {
		return nil
	}
	addr := prefix.Masked().Addr()
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), addr.BitLen()),
	}
}

// AddrToIPNet is a convenience helper to convert a netip.Addr to a *net.IPNet
// with a mask corresponding to the addresses's bit length.
func AddrToIPNet(addr netip.Addr) *net.IPNet {
	if !addr.IsValid() {
		return nil
	}
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(addr.BitLen(), addr.BitLen()),
	}
}

// IPToNetPrefix is a convenience helper for migrating from the older 'net'
// standard library types to the newer 'netip' types. Use this to plug the new
// types in newer code into older types in older code during the migration.
//
// Note: This function assumes given ip is not an IPv4 mapped IPv6 address.
// See the comment of AddrFromIP for more details.
func IPToNetPrefix(ip net.IP) netip.Prefix {
	a, ok := AddrFromIP(ip)
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
