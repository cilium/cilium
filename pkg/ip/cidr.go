// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"net"
	"net/netip"
)

// ParseCIDRs fetches all CIDRs referred to by the specified slice and returns
// them as regular golang CIDR objects.
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

// IPNetToPrefix is a convenience helper for migrating from the older 'net'
// standard library types to the newer 'netip' types. Use this to plug the
// new types in newer code into older types in older code during the migration.
//
// Note: This function assumes given prefix.IP is not an IPv4 mapped IPv6
// address. See the comment of AddrFromIP for more details.
func IPNetToPrefix(prefix *net.IPNet) netip.Prefix {
	if prefix == nil {
		return netip.Prefix{}
	}
	ip, ok := AddrFromIP(prefix.IP)
	if !ok {
		return netip.Prefix{}
	}
	ones, bits := prefix.Mask.Size()
	if bits != net.IPv4len*8 && bits != net.IPv6len*8 {
		// invalid mask
		return netip.Prefix{}
	}
	return netip.PrefixFrom(ip, ones)
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
