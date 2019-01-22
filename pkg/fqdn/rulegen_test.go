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

package fqdn

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/dns"

	. "gopkg.in/check.v1"
)

// force a fail if something calls this function
func lookupFail(c *C, dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
	c.Error("Lookup function called when it should not")
	return nil, nil
}

// TestRuleGenCIDRGeneration tests rule generation output:
// add a rule, get correct IP4/6 in ToCIDRSet
// add a rule, lookup twice, get correct IP4/6 in TOCIDRSet after change
// add a rule w/ToCIDRSet, get correct IP4/6 and old rules
// add a rule, get same UUID label on repeat generations
func (ds *FQDNTestSuite) TestRuleGenCIDRGeneration(c *C) {
	var (
		generatedRules = make([]*api.Rule, 0)

		gen = NewRuleGen(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// add rules
	rulesToAdd := []*api.Rule{rule1.DeepCopy()}
	gen.MarkToFQDNRules(rulesToAdd)
	gen.StartManageDNSName(rulesToAdd)

	// store original UUID
	uuidOrig := getRuleUUIDLabel(rulesToAdd[0])
	c.Assert(uuidOrig, Not(Equals), "", Commentf("UUID label not set on rule, or not recovered correctly"))

	// poll DNS once, check that we only generate 1 rule (for 1 IP) and that we
	// still have 1 ToFQDN rule, and that the IP is correct
	generatedRules = nil
	err := gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Incorrect number of generated rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToFQDNs), Equals, len(generatedRules[0].Egress[0].ToCIDRSet), Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	// Check that the UUID has not changed
	uuid1 := getRuleUUIDLabel(generatedRules[0])
	c.Assert(uuid1, Equals, uuidOrig, Commentf("UUID label has changed on rule since original insert"))

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	generatedRules = nil
	err = gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToFQDNs), Equals, 1, Commentf("toFQDNs rule count changed when it should not"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 2, Commentf("Generated CIDR count is not the same as inserted IPs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))

	// check that the UUID has not changed
	uuid2 := getRuleUUIDLabel(generatedRules[0])
	c.Assert(uuid2, Equals, uuidOrig, Commentf("UUID label has changed on rule since original insert"))
	c.Assert(uuid2, Equals, uuid1, Commentf("UUID label has changed on rule since previous generation"))
}

// TestRuleGenDropCIDROnReinsert tests that we correctly guard against
// pre-existing toCIDRSet sections:
// - when we initially insert
// - when we re-insert a generated rule
func (ds *FQDNTestSuite) TestRuleGenDropCIDROnReinsert(c *C) {
	var (
		generatedRules = make([]*api.Rule, 0)

		gen = NewRuleGen(Config{
			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// Add a fake "generated" CIDR entry, it should not come back later when generated
	rulesToAdd := []*api.Rule{rule1.DeepCopy()}
	gen.MarkToFQDNRules(rulesToAdd)
	rulesToAdd[0].Egress[0].ToCIDRSet = append(rulesToAdd[0].Egress[0].ToCIDRSet, api.CIDRRule{Cidr: api.CIDR("2.2.2.2/32")})
	gen.StartManageDNSName(rulesToAdd)
	err := gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Generated an unexpected number of rules"))
	c.Assert(len(rulesToAdd[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("existing toCIDRSet section not stripped by GenerateRules"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestRuleGenMultiIPUpdate(c *C) {
	var (
		generatedRules = make([]*api.Rule, 0)

		gen = NewRuleGen(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// add rules
	rulesToAdd := []*api.Rule{rule3.DeepCopy()}
	gen.MarkToFQDNRules(rulesToAdd)
	gen.StartManageDNSName(rulesToAdd)

	// poll DNS once, check that we only generate 1 IP for cilium.io
	generatedRules = nil
	err := gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Incorrect number of generated rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	generatedRules = nil
	err = gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("3.3.3.3")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 3, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[2].Cidr, Equals, api.CIDR("3.3.3.3/32"), Commentf("Incorrect IP CIDR generated"))

	// poll DNS once, check that we only generate 4 IPs, 2 cilium.io cached IPs, 1 cached gituhub.com IP, 1 new github.com IP
	generatedRules = nil
	err = gen.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("4.4.4.4")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 4, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[2].Cidr, Equals, api.CIDR("3.3.3.3/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[3].Cidr, Equals, api.CIDR("4.4.4.4/32"), Commentf("Incorrect IP CIDR generated"))
}

// TestRuleGenUpdatesOnReplace tests updates without deletion:
// add 1 matchname, poll. re-add it. See the correct output on MarkToFQDNRules
// add 2 matchnames with the different names, replace one, then back. See the correct output on MarkToFQDNRules
// re-add the original rule with only 1 matchname. It is not cached because that name was deleted
func (ds *FQDNTestSuite) TestRuleGenUpdatesOnReplace(c *C) {

	var (
		lookups = make(map[string]int)
		dnsIPs  = map[string]*DNSIPRecords{
			dns.Fqdn("cilium.io"):         {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}},
			dns.Fqdn("github.com"):        {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
			dns.Fqdn("anotherdomain.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("3.3.3.3")}},
		}

		gen = NewRuleGen(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				return nil
			},
		})
	)

	// Add 1 rules and poll
	rules := []*api.Rule{makeRule("testRule", "cilium.io")}
	// MarkToFQDNRules adds nothing on the first try
	gen.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 0, Commentf("Generated CIDR count is 0 when no CIDRs should have been added"))

	gen.StartManageDNSName(rules)
	gen.UpdateGenerateDNS(time.Now(), lookupDNSNames(dnsIPs, lookups, []string{dns.Fqdn("cilium.io")}))

	// Add another rule with the same FQDN. We should see IPs in-place BEFORE StartManageDNSName.
	// MarkToFQDNRules adds the IP from the cache
	rules = []*api.Rule{makeRule("testRule2", "cilium.io")}
	gen.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	gen.StartManageDNSName(rules)
	gen.UpdateGenerateDNS(time.Now(), lookupDNSNames(dnsIPs, lookups, []string{dns.Fqdn("cilium.io")}))

	// Add 2 rules and poll
	rules = []*api.Rule{makeRule("testRule3", "cilium.io", "github.com")}
	gen.MarkToFQDNRules(rules)
	gen.StartManageDNSName(rules)
	gen.UpdateGenerateDNS(time.Now(), lookupDNSNames(dnsIPs, lookups, []string{dns.Fqdn("cilium.io"), dns.Fqdn("github.com")}))

	// Add a 2 matchnames, only one overlaps
	// MarkToFQDNRules should add only 1 entry
	rules = []*api.Rule{makeRule("testRule4", "cilium.io", "anotherdomain.com")}
	gen.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	gen.StartManageDNSName(rules)
	gen.UpdateGenerateDNS(time.Now(), lookupDNSNames(dnsIPs, lookups, []string{dns.Fqdn("cilium.io"), dns.Fqdn("anotherdomain.com")}))

	// Add the original 2 matchnames without deleting
	// MarkToFQDNRules should add 2 entries, as those should be in the gen cache
	rules = []*api.Rule{makeRule("testRule5", "cilium.io", "github.com")}
	gen.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 2, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect first IP CIDR generated from cache"))

	gen.StartManageDNSName(rules)
	gen.UpdateGenerateDNS(time.Now(), lookupDNSNames(dnsIPs, lookups, []string{dns.Fqdn("cilium.io"), dns.Fqdn("github.com")}))

	// Add a rule with 1 old matchname
	// MarkToFQDNRules should add one entry
	rules = []*api.Rule{makeRule("testRule6", "anotherdomain.com")}
	gen.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
}
