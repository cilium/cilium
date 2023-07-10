// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"errors"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"

// Validate ensures that pattern is a parseable matchPattern. It returns the
// regexp generated when validating.
func Validate(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return re.CompileRegex(ToRegexp(pattern))
}

// ValidateWithoutCache is the same as Validate() but doesn't consult the regex
// LRU.
func ValidateWithoutCache(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(ToRegexp(pattern))
}

func prevalidate(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// error check
	if strings.ContainsAny(pattern, "[]+{},") {
		return errors.New(`Only alphanumeric ASCII characters, the hyphen "-", underscore "_", "." and "*" are allowed in a matchPattern`)
	}

	return nil
}

// Sanitize canonicalized the pattern for use by ToRegexp
func Sanitize(pattern string) string {
	if pattern == "*" {
		return pattern
	}

	return dns.FQDN(pattern)
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
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.Replace(pattern, "*", allowedDNSCharsREGroup+"*", -1)

	// base case. "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}

// IsMoreSpecific returns true if 'b' would match anything 'a' matches.
// Examples:
// foo.com is more specific than *
// foo.com is more specific than *.com
// *.foo.com is more specific than *.*.com
// *foo.com is more specific than *oo.com
func IsMoreSpecific(a, b string) bool {
	a = Sanitize(a)
	b = Sanitize(b)
	if len(a) <= 1 {
		return false // empty can not be more specific than anything
	}
	if a == b {
		return false // same is not more specific
	}
	if b == "*" {
		return true // anything is more specific than "*"
	}
	subdomainsA := strings.Split(a, ".")
	subdomainsB := strings.Split(b, ".")
	if len(subdomainsA) != len(subdomainsB) {
		return false // must match to same depth for 'b' to match anything 'a' matches
	}
	nDomains := len(subdomainsA) - 1 // discount the trailing '.'
	for i := 0; i < nDomains; i++ {
		subA := subdomainsA[i]
		subB := subdomainsB[i]
		partsB := strings.Split(subB, "*")
		// subA must contain all the fixed parts of b without them overlapping
		lastPart := len(partsB) - 1
		if lastPart == 0 {
			// no wildcards in b, must be an exact match
			if subB != subA {
				return false
			}
			continue
		}
		// subdomain b has at least one wildcard
		for j, part := range partsB {
			switch j {
			case 0:
				if !strings.HasPrefix(subA, part) {
					return false
				}
				subA = subA[len(part):] // remove the fixed part
			default:
				k := strings.Index(subA, part)
				if k < 0 {
					return false
				}
				subA = subA[k+len(part):] // cut till past the fixed part
			case lastPart:
				if !strings.HasSuffix(subA, part) {
					return false
				}
			}
		}
	}
	return true
}
