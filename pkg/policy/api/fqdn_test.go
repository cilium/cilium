// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// TestFQDNSelectorSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func (s *PolicyAPITestSuite) TestFQDNSelectorSanitize(c *C) {
	for _, accept := range []FQDNSelector{
		{MatchName: "cilium.io."},
		{MatchName: "get-cilium.io."},
		{MatchName: "foo.cilium.io."},
		{MatchName: "cilium.io"},
		{MatchName: "_cilium.io"},
		{MatchPattern: "*.cilium.io"},
		{MatchPattern: "*._cilium.io"},
		{MatchPattern: "*cilium.io"},
		{MatchPattern: "cilium.io"},
	} {
		err := accept.sanitize()
		c.Assert(err, IsNil, Commentf("FQDNSelector %+v was rejected but it should be valid", accept))
	}

	for _, reject := range []FQDNSelector{
		{MatchName: "a{1,2}.cilium.io."},
		{MatchPattern: "[a-z]*.cilium.io."},
		{MatchName: "cilium.io", MatchPattern: "*cilium.io"},
	} {
		err := reject.sanitize()
		c.Assert(err, Not(IsNil), Commentf("FQDNSelector %+v was accepted but it should be invalid", reject))
	}
}

// TestPortRuleDNSSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func (s *PolicyAPITestSuite) TestPortRuleDNSSanitize(c *C) {
	for _, accept := range []PortRuleDNS{
		{MatchName: "cilium.io."},
		{MatchName: "get-cilium.io."},
		{MatchName: "foo.cilium.io."},
		{MatchName: "cilium.io"},
		{MatchName: "_cilium.io"},
		{MatchPattern: "*.cilium.io"},
		{MatchPattern: "*._cilium.io"},
		{MatchPattern: "*cilium.io"},
		{MatchPattern: "cilium.io"},
	} {
		err := accept.Sanitize()
		c.Assert(err, IsNil, Commentf("PortRuleDNS %+v was rejected but it should be valid", accept))
	}

	for _, reject := range []PortRuleDNS{
		{MatchName: "a{1,2}.cilium.io."},
		{MatchPattern: "[a-z]*.cilium.io."},
		{MatchName: "a{1,2}.cilium.io.", MatchPattern: "[a-z]*.cilium.io."},
	} {
		err := reject.Sanitize()
		c.Assert(err, Not(IsNil), Commentf("PortRuleDNS %+v was accepted but it should be invalid", reject))
	}
}

// TestPortRuleDNSSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func BenchmarkFQDNSelectorString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range []FQDNSelector{
			{MatchName: "cilium.io"},
			{MatchPattern: "[a-z]*.cilium.io"},
			{MatchName: "a{1,2}.cilium.io", MatchPattern: "[a-z]*.cilium.io"},
			{MatchPattern: "*.cilium.io"},
		} {
			_ = s.String()
		}
	}
}
