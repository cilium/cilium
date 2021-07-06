// Copyright 2021 Authors of Cilium
//
// Based on code from github.com/miekg/dns which is:
//
// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2011 Miek Gieben. All rights reserved.
// Copyright 2014 CloudFlare. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
