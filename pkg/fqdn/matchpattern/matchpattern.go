// Copyright 2018 Authors of Cilium
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

package matchpattern

import (
	"errors"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"

// Compile ensures that pattern is a parseable matchPattern. The
// pattern is Sanitized and validated before compiling. It returns the
// compiled regexp.
func Compile(pattern string) (matcher *regexp.Regexp, err error) {
	if pattern != "*" {
		pattern = dns.Fqdn(pattern)

		// error check
		if strings.ContainsAny(pattern, "[]+{},") {
			return nil, errors.New(`Only alphanumeric ASCII characters, the hyphen "-", underscore "_", "." and "*" are allowed in a matchPattern`)
		}
	}
	return regexp.Compile(toRegexp(pattern))
}

// CanonicalizeFQDN appends the trailing dot and lowers the casing as
// needed to make 'name' a fully qualified domain name (FQDN).
func CanonicalizeFQDN(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// toRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern.
// It supports:
// * to select 0 or more DNS valid characters
func toRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if pattern == "*" {
		pattern = "(" + allowedDNSCharsREGroup + "+.)+"
	}

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.Replace(pattern, "*", allowedDNSCharsREGroup+"*", -1)

	// base case. "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}
