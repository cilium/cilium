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

	"github.com/cilium/dns"
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9]"

// Validate ensures that pattern is a parseable matchPattern. It returns the
// regexp generated when validating.
func Validate(pattern string) (matcher *regexp.Regexp, err error) {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// error check
	if strings.ContainsAny(pattern, "[]+{},") {
		return nil, errors.New(`Only alphanumeric ASCII characters, the hyphen "-", "." and "*" are allowed in a matchPattern`)
	}

	return regexp.Compile(ToRegexp(pattern))
}

// Sanitize canonicalized the pattern for use by ToRegexp
func Sanitize(pattern string) string {
	if pattern == "*" {
		return pattern
	}

	return strings.ToLower(dns.Fqdn(pattern))
}

// ToRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern.
// It supports:
// * to select 0 or more DNS valid characters
func ToRegexp(pattern string) string {
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
