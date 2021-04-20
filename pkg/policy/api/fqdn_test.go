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

// +build !privileged_tests

package api

import (
	. "gopkg.in/check.v1"
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
