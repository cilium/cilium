// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package ip

import (
	"net"
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
