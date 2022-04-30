// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
)

var (
	// allowedMatchNameChars tests that MatchName contains only valid DNS characters
	allowedMatchNameChars = regexp.MustCompile("^[-a-zA-Z0-9_.]+$")

	// allowedPatternChars tests that the MatchPattern field contains only the
	// characters we want in our wilcard scheme.
	allowedPatternChars = regexp.MustCompile("^[-a-zA-Z0-9_.*]+$") // the * inside the [] is a literal *

	// FQDNMatchNameRegexString is a regex string which matches what's expected
	// in the MatchName field in the FQDNSelector. This should be kept in-sync
	// with the marker comment for validation. There's no way to use a Golang
	// variable in the marker comment, so it's left up to the developer.
	FQDNMatchNameRegexString = `^([-a-zA-Z0-9_]+[.]?)+$`

	// FQDNMatchPatternRegexString is a regex string which matches what's expected
	// in the MatchPattern field in the FQDNSelector. This should be kept in-sync
	// with the marker comment for validation. There's no way to use a Golang
	// variable in the marker comment, so it's left up to the developer.
	FQDNMatchPatternRegexString = `^([-a-zA-Z0-9_*]+[.]?)+$`
)

type FQDNSelector struct {
	// MatchName matches literal DNS names. A trailing "." is automatically added
	// when missing.
	//
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_]+[.]?)+$`
	MatchName string `json:"matchName,omitempty"`

	// MatchPattern allows using wildcards to match DNS names. All wildcards are
	// case insensitive. The wildcards are:
	// - "*" matches 0 or more DNS valid characters, and may occur anywhere in
	// the pattern. As a special case a "*" as the leftmost character, without a
	// following "." matches all subdomains as well as the name to the right.
	// A trailing "." is automatically added when missing.
	//
	// Examples:
	// `*.cilium.io` matches subomains of cilium at that level
	//   www.cilium.io and blog.cilium.io match, cilium.io and google.com do not
	// `*cilium.io` matches cilium.io and all subdomains 1 level below
	//   www.cilium.io, blog.cilium.io and cilium.io match, google.com does not
	// sub*.cilium.io matches subdomains of cilium where the subdomain component
	// begins with "sub"
	//   sub.cilium.io and subdomain.cilium.io match, www.cilium.io,
	//   blog.cilium.io, cilium.io and google.com do not
	//
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_*]+[.]?)+$`
	MatchPattern string `json:"matchPattern,omitempty"`
}

func (s *FQDNSelector) String() string {
	const m = "MatchName: "
	const mm = ", MatchPattern: "
	var str strings.Builder
	str.Grow(len(m) + len(mm) + len(s.MatchName) + len(s.MatchPattern))
	str.WriteString(m)
	str.WriteString(s.MatchName)
	str.WriteString(mm)
	str.WriteString(s.MatchPattern)
	return str.String()
}

// sanitize for FQDNSelector is a little wonky. While we do more processing
// when using MatchName the basic requirement is that is a valid regexp. We
// test that it can compile here.
func (s *FQDNSelector) sanitize() error {
	if len(s.MatchName) > 0 && len(s.MatchPattern) > 0 {
		return fmt.Errorf("only one of MatchName or MatchPattern is allowed in an FQDNSelector")
	}
	if len(s.MatchName) > 0 && !allowedMatchNameChars.MatchString(s.MatchName) {
		return fmt.Errorf("Invalid characters in MatchName: \"%s\". Only 0-9, a-z, A-Z and . and - characters are allowed", s.MatchName)
	}

	if len(s.MatchPattern) > 0 && !allowedPatternChars.MatchString(s.MatchPattern) {
		return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", s.MatchPattern)
	}
	_, err := matchpattern.Validate(s.MatchPattern)
	return err
}

// ToRegex converts the given FQDNSelector to its corresponding regular
// expression. If the MatchName field is set in the selector, it performs all
// needed formatting to ensure that the field is a valid regular expression.
func (s *FQDNSelector) ToRegex() (*regexp.Regexp, error) {
	var preparedMatch string
	if s.MatchName != "" {
		preparedMatch = dns.FQDN(s.MatchName)
	} else {
		preparedMatch = matchpattern.Sanitize(s.MatchPattern)
	}

	regex, err := matchpattern.Validate(preparedMatch)
	return regex, err
}

// PortRuleDNS is a list of allowed DNS lookups.
type PortRuleDNS FQDNSelector

// Sanitize checks that the matchName in the portRule can be compiled as a
// regex. It does not check that a DNS name is a valid DNS name.
func (r *PortRuleDNS) Sanitize() error {
	if len(r.MatchName) > 0 && !allowedMatchNameChars.MatchString(r.MatchName) {
		return fmt.Errorf("Invalid characters in MatchName: \"%s\". Only 0-9, a-z, A-Z and . and - characters are allowed", r.MatchName)
	}

	if len(r.MatchPattern) > 0 && !allowedPatternChars.MatchString(r.MatchPattern) {
		return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", r.MatchPattern)
	}
	_, err := matchpattern.Validate(r.MatchPattern)
	return err
}

// GetAsEndpointSelectors returns a FQDNSelector as a single EntityNone
// EndpointSelector slice.
// Note that toFQDNs behaves differently than most other rules. The presence of
// any toFQDNs rules means the endpoint must enforce policy, but the IPs are later
// added as toCIDRSet entries and processed as such.
func (s *FQDNSelector) GetAsEndpointSelectors() EndpointSelectorSlice {
	return []EndpointSelector{EndpointSelectorNone}
}

// FQDNSelectorSlice is a wrapper type for []FQDNSelector to make is simpler to
// bind methods.
type FQDNSelectorSlice []FQDNSelector

// GetAsEndpointSelectors will return a single EntityNone if any
// toFQDNs rules exist, and a nil slice otherwise.
func (s FQDNSelectorSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	for _, rule := range s {
		return rule.GetAsEndpointSelectors()
	}
	return nil
}
