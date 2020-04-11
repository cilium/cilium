// Copyright 2018-2019 Authors of Cilium
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

package api

import (
	"fmt"
	"regexp"

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
)

var (
	// allowedMatchNameChars tests that MatchName contains only valid DNS characters
	allowedMatchNameChars = regexp.MustCompile("^[-a-zA-Z0-9.]+$")

	// allowedPatternChars tests that the MatchPattern field contains only the
	// characters we want in our wilcard scheme.
	allowedPatternChars = regexp.MustCompile("^[-a-zA-Z0-9.*]+$") // the * inside the [] is a literal *
)

// FQDNSelectorString is the canonical string used as a map key
type FQDNSelectorString string

// 'MatchName' and 'MatchPattern' are mutually exclusive
type FQDNSelector struct {
	// MatchName matches literal DNS names. A trailing "." is automatically added
	// when missing.
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
	MatchPattern string `json:"matchPattern,omitempty"`

	// Regexp pattern pre-computed at Sanitize()
	// TODO: Move this to the policy package (https://github.com/cilium/cilium/issues/8353)
	matchRE *regexp.Regexp
}

func (s *FQDNSelector) String() string {
	return fmt.Sprintf("MatchName: %s, MatchPattern: %s", s.MatchName, s.MatchPattern)
}

// Sanitize for FQDNSelector is a little wonky. While we do more processing
// when using MatchName the basic requirement is that is a valid regexp. We
// test that it can compile here.
func (s *FQDNSelector) Sanitize() error {
	// MatchName and MatchPattern are mutually exclusive in an FQDNSelector (but not in a PortRuleDNS)
	if len(s.MatchName) > 0 && len(s.MatchPattern) > 0 {
		return fmt.Errorf("only one of MatchName or MatchPattern is allowed in an FQDNSelector")
	}
	var match string
	if len(s.MatchName) > 0 {
		if !allowedMatchNameChars.MatchString(s.MatchName) {
			return fmt.Errorf("Invalid characters in MatchName: \"%s\". Only 0-9, a-z, A-Z and . and - characters are allowed", s.MatchName)
		}
		match = s.MatchName
	}

	if len(s.MatchPattern) > 0 {
		if !allowedPatternChars.MatchString(s.MatchPattern) {
			return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", s.MatchPattern)
		}
		match = s.MatchPattern
	}
	var err error
	s.matchRE, err = matchpattern.Validate(match)
	return err
}

// ToRegex returns the pre-computed regular expression.
func (s *FQDNSelector) ToRegex() *regexp.Regexp {
	if s.matchRE == nil {
		panic(fmt.Sprintf("Internal error: ToFQDN (%s) not Sanitized!", s.String()))
	}
	return s.matchRE
}

func (s *FQDNSelector) MapKey() FQDNSelectorString {
	return FQDNSelectorString(s.String())
}

// PortRuleDNS is an allowed DNS lookup.
// Both 'MatchName' and 'MatchPattern' can be present.
type PortRuleDNS struct {
	// MatchName matches literal DNS names. A trailing "." is automatically added
	// when missing.
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
	MatchPattern string `json:"matchPattern,omitempty"`

	// Regexp patterns pre-computed at Sanitize()
	// TODO: Move this to the policy package (https://github.com/cilium/cilium/issues/8353)
	nameRE    *regexp.Regexp
	patternRE *regexp.Regexp
}

// Sanitize checks that the matchName in the portRule can be compiled as a
// regex. It does not check that a DNS name is a valid DNS name.
func (r *PortRuleDNS) Sanitize() error {
	var err error
	if len(r.MatchName) > 0 {
		if !allowedMatchNameChars.MatchString(r.MatchName) {
			return fmt.Errorf("Invalid characters in MatchName: \"%s\". Only 0-9, a-z, A-Z and . and - characters are allowed", r.MatchName)
		}
		r.nameRE, err = matchpattern.Validate(r.MatchName)
		if err != nil {
			return err
		}
	}
	if len(r.MatchPattern) > 0 {
		if !allowedPatternChars.MatchString(r.MatchPattern) {
			return fmt.Errorf("Invalid characters in MatchPattern: \"%s\". Only 0-9, a-z, A-Z and ., - and * characters are allowed", r.MatchPattern)
		}
		r.patternRE, err = matchpattern.Validate(r.MatchPattern)
	}
	return err
}

// ToRegex returns the pre-computed regular expression(s).
func (r *PortRuleDNS) ToRegexes() (res []*regexp.Regexp) {
	if len(r.MatchName) > 0 {
		if r.nameRE == nil {
			panic("Internal error: PortRuleDNS not Sanitized!")
		}
		res = append(res, r.nameRE)
	}
	if len(r.MatchPattern) > 0 {
		if r.patternRE == nil {
			panic("Internal error: PortRuleDNS not Sanitized!")
		}
		res = append(res, r.patternRE)
	}
	return res
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
