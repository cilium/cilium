// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import "net"

type IPFamily int

const (
	// IPFamilyNone is used for non-IP based endpoints (e.g., HTTP URL)
	IPFamilyNone IPFamily = iota
	IPFamilyV4
	IPFamilyV6
)

func (f IPFamily) String() string {
	switch f {
	case IPFamilyNone:
		return "none"
	case IPFamilyV4:
		return "ipv4"
	case IPFamilyV6:
		return "ipv6"
	}
	return "undefined"
}

func GetIPFamily(addr string) IPFamily {
	ip := net.ParseIP(addr)

	if ip.To4() != nil {
		return IPFamilyV4
	}

	if ip.To16() != nil {
		return IPFamilyV6
	}

	return IPFamilyNone
}
