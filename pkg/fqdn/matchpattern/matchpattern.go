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
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9]"

// Validate ensures that pattern is a parseable matchPattern.
func Validate(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// error check
	if strings.Contains(pattern, "**") || strings.ContainsAny(pattern, "[]+{},") {
		return errors.New("** is not allowed in matchPattern")
	}

	_, err := regexp.Compile(ToRegexp(pattern))
	return err
}

// isSubAndDomainSpecial checks that the first two characters are * followed by
// a valid DNS character that isn't a .
var isSubAndDomainSpecial = regexp.MustCompile("^[*]" + allowedDNSCharsREGroup)

// ToRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern.
// It supports:
// * to select 0 or more DNS valid characters
// *domain.com to select the domain and it's subdomains
func ToRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle *domain.com case
	if isSubAndDomainSpecial.MatchString(pattern) {
		// the + at the start of the string affect the allowed chars
		// the . will be turned into [.] in the base case below
		pattern = "(" + allowedDNSCharsREGroup + "+.)?" + pattern[1:]
	}

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.Replace(pattern, "*", allowedDNSCharsREGroup+"*", -1)
	// base case. "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	return "^" + pattern + "$"
}
