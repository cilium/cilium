// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

const allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"

// allowedPatternChars tests that the MatchPattern field contains only the
// characters we want in our wildcard scheme.
var allowedPatternChars = regexp.MustCompile("^[-a-zA-Z0-9_.*]+$") // the * inside the [] is a literal *

// MatchAllAnchoredPattern is the simplest pattern that match all inputs. This resulting
// parsed regular expression is the same as an empty string regex (""), but this
// value is easier to reason about when serializing to and from json.
const MatchAllAnchoredPattern = "(?:)"

// MatchAllUnAnchoredPattern is the same as MatchAllAnchoredPattern, except that
// it can be or-ed (joined with "|") with other rules, and still match all rules.
const MatchAllUnAnchoredPattern = ".*"

// MaxFQDNLength is the maximum length of a MatchName or MatchPattern statement.
//
// Must be kept in sync with the validator for these fields in pkg/policy/api.
const MaxFQDNLength = 255

// Validate ensures that pattern is a parsable matchPattern. It returns the
// regexp generated when validating.
func Validate(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return re.CompileRegex(ToAnchoredRegexp(pattern))
}

// ValidateWithoutCache is the same as Validate() but doesn't consult the regex
// LRU.
func ValidateWithoutCache(pattern string) (matcher *regexp.Regexp, err error) {
	if err := prevalidate(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(ToAnchoredRegexp(pattern))
}

func prevalidate(pattern string) error {
	if len(pattern) > MaxFQDNLength {
		return fmt.Errorf("Invalid MatchPattern: %q. Must be <= %d characters long.", pattern, MaxFQDNLength)
	}
	if len(pattern) > 0 && !allowedPatternChars.MatchString(pattern) {
		return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", pattern)
	}

	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// error check
	if strings.ContainsAny(pattern, "[]+{},") {
		return errors.New(`Only alphanumeric ASCII characters, the hyphen "-", underscore "_", "." and "*" are allowed in a matchPattern`)
	}

	return nil
}

// Sanitize canonicalized the pattern for use by ToAnchoredRegexp
func Sanitize(pattern string) string {
	if pattern == "*" {
		return pattern
	}

	return dns.FQDN(pattern)
}

// ToAnchoredRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern. It also adds anchors to ensure it match the whole string.
// It supports:
// * to select 0 or more DNS valid characters
func ToAnchoredRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if pattern == "*" {
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	pattern = escapeRegexpCharacters(pattern)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}

// ToUnAnchoredRegexp converts a MatchPattern field into a regexp string. It does not
// validate the pattern. It does not add regexp anchors.
// It supports:
// * to select 0 or more DNS valid characters
func ToUnAnchoredRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)
	// handle the * match-all case. This will filter down to the end.
	if pattern == "*" {
		return MatchAllUnAnchoredPattern
	}
	pattern = escapeRegexpCharacters(pattern)
	return pattern
}

func escapeRegexpCharacters(pattern string) string {
	// base case. "." becomes a literal .
	pattern = strings.ReplaceAll(pattern, ".", "[.]")

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.ReplaceAll(pattern, "*", allowedDNSCharsREGroup+"*")
	return pattern
}
