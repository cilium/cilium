// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
//
// Based on code from github.com/miekg/dns which is:
//
// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2011 Miek Gieben. All rights reserved.
// Copyright 2014 CloudFlare. All rights reserved.

package dns

import "strings"

// These functions were copied and adapted from github.com/miekg/dns.

// isFQDN reports whether the domain name s is fully qualified.
func isFQDN(s string) bool {
	s2 := strings.TrimSuffix(s, ".")
	if s == s2 {
		return false
	}

	i := strings.LastIndexFunc(s2, func(r rune) bool {
		return r != '\\'
	})

	// Test whether we have an even number of escape sequences before
	// the dot or none.
	return (len(s2)-i)%2 != 0
}

// FQDN returns the fully qualified domain name from s.
// If s is already fully qualified, it behaves as the identity function.
func FQDN(s string) string {
	if isFQDN(s) {
		return strings.ToLower(s)
	}
	return strings.ToLower(s) + "."
}
