// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/subnet"
)

type IPFamily int

const (
	// IPFamilyAny is used for non-IP based endpoints (e.g., HTTP URL),
	// and when any IP family could be used.
	IPFamilyAny IPFamily = iota
	IPFamilyV4
	IPFamilyV6
)

func (f IPFamily) String() string {
	switch f {
	case IPFamilyAny:
		return "any"
	case IPFamilyV4:
		return "ipv4"
	case IPFamilyV6:
		return "ipv6"
	}
	return "undefined"
}

// GetIPFamilies function converts string slice to IPFamily slice.
func GetIPFamilies(families []string) []IPFamily {
	ipFams := make([]IPFamily, 0, len(families))
	for i := range families {
		ipFams = append(ipFams, NewIPFamily(families[i]))
	}
	return ipFams
}

// NewIPFamily is a factory function that consumes string and returns IPFamily.
func NewIPFamily(s string) IPFamily {
	switch s {
	case "ipv4":
		return IPFamilyV4
	case "ipv6":
		return IPFamilyV6
	default:
		return IPFamilyAny
	}
}

func GetIPFamily(addr string) IPFamily {
	ip := net.ParseIP(addr)

	if ip.To4() != nil {
		return IPFamilyV4
	}

	if ip.To16() != nil {
		return IPFamilyV6
	}

	return IPFamilyAny
}

// ComputeFailureExceptions computes a list of failure exceptions for various
// tests, from a default list of exceptions and a diff given via a CLI flag.
// The diff is given as a list of exceptions, with optional leading +/- signs.
// A minus sign means the exception should be removed from the defaults; a plus
// sign means the exception should be added to the defaults. If there are
// neither minus nor plus signs, then the given exceptions are used directly
// without considering the defaults.
// See the unit tests for examples.
func ComputeFailureExceptions(defaultExceptions, inputExceptions []string) []string {
	exceptions := map[string]bool{}
	if len(inputExceptions) > 0 {
		// Build final list of failure exceptions based on default exceptions,
		// added exceptions (+ prefix), and removed exceptions (- prefix).
		addedAllDefaults := false
		for _, exception := range inputExceptions {
			if exception[0] == '+' || exception[0] == '-' {
				if !addedAllDefaults {
					for _, r := range defaultExceptions {
						exceptions[r] = true
					}
					addedAllDefaults = true
				}
			}
			switch exception[0] {
			case '+':
				exceptions[exception[1:]] = true
			case '-':
				exceptions[exception[1:]] = false
			default:
				exceptions[exception] = true
			}
		}
	}

	exceptionList := []string{}
	for exception, isIn := range exceptions {
		if isIn {
			exceptionList = append(exceptionList, exception)
		}
	}
	return exceptionList
}

// SameSubnet returns true if given two IP addresses belong to the same subnet, based on the subnet-topology.
func SameSubnet(ip1, ip2, topology string) bool {
	if topology == "" {
		return false
	}

	parsedIP1, err := netip.ParseAddr(ip1)
	if err != nil {
		return false
	}
	parsedIP2, err := netip.ParseAddr(ip2)
	if err != nil {
		return false
	}

	entries, err := subnet.DecodeTopology(topology)
	if err != nil {
		return false
	}

	var group1, group2 uint32
	for _, entry := range entries {
		if entry.Key.Contains(parsedIP1) {
			group1 = entry.Value
		}
		if entry.Key.Contains(parsedIP2) {
			group2 = entry.Value
		}
		if group1 != 0 && group1 == group2 {
			return true
		}
	}

	return false
}
