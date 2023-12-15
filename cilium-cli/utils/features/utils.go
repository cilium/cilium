// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import "net"

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
