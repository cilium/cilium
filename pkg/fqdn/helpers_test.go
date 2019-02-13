// Copyright 2019 Authors of Cilium
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

package fqdn

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
	"github.com/cilium/cilium/pkg/policy/api"
	. "gopkg.in/check.v1"
)

func (ds *DNSCacheTestSuite) TestKeepUniqueNames(c *C) {
	testData := []struct {
		argument []string
		expected []string
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "b", "a", "c"}, []string{"a", "b", "c"}},
		{[]string{""}, []string{""}},
		{[]string{}, []string{}},
	}

	for _, item := range testData {
		val := KeepUniqueNames(item.argument)
		c.Assert(val, checker.DeepEquals, item.expected)
	}
}

func (ds *DNSCacheTestSuite) TestInjectCIDRSetRulesWithOtherCIDRSet(c *C) {
	// Validate that if empty cache the ToCidrRule is always empty
	rule := makeRule("cilium.io", "cilium.io")
	cache := NewDNSCache()
	cache.Update(now, "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 1)
	rule.Egress = append(rule.Egress, api.EgressRule{
		ToCIDRSet: api.IPsToCIDRRules([]net.IP{net.ParseIP("4.4.4.4")})})

	injectToCIDRSetRules(rule, cache, nil)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 1)
	c.Assert(rule.Egress[1].ToCIDRSet, HasLen, 1)
}

func (ds *DNSCacheTestSuite) TestInjectCIDRSetRulesInvalidCache(c *C) {
	// Validate that if empty cache the ToCidrRule is always empty
	rule := makeRule("cilium.io", "cilium.io")
	EmptyCache := NewDNSCache()
	injectToCIDRSetRules(rule, EmptyCache, nil)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 0)

	// Validate that if empty cache the ToCidrRule is cleared correctly
	rule.Egress[0].ToCIDRSet = api.IPsToCIDRRules([]net.IP{net.ParseIP("1.1.1.1")})
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 1)
	injectToCIDRSetRules(rule, EmptyCache, nil)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 0)
}

func (ds *DNSCacheTestSuite) TestInjectCIDRSetRulesByMatchName(c *C) {
	rule := makeRule("cilium.io", "cilium.io")
	cache := NewDNSCache()
	cache.Update(now, "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 1)

	injectToCIDRSetRules(rule, cache, nil)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 1)
}

func (ds *DNSCacheTestSuite) TestInjectCIDRSetRulesByMatchPattern(c *C) {

	rule := makeRule("cilium.io")
	rule.Egress[0].ToFQDNs = api.FQDNSelectorSlice{
		{MatchPattern: "cilium.io"},
	}
	cache := NewDNSCache()
	cache.Update(now, "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 1)
	reg := regexpmap.NewRegexpMap()
	reg.Add("cilium.io", "cilium.io")

	injectToCIDRSetRules(rule, cache, reg)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 1)

	rule = makeRule("cilium.io")
	rule.Egress[0].ToFQDNs = api.FQDNSelectorSlice{
		{MatchPattern: "ciliumtest.io"},
	}

	injectToCIDRSetRules(rule, cache, reg)
	c.Assert(rule.Egress[0].ToCIDRSet, HasLen, 0)

}
