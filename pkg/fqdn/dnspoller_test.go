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

package fqdn

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func makeRule(key string, dnsNames ...string) *api.Rule {
	matchNames := []string{}
	for _, name := range dnsNames {
		matchNames = append(matchNames,
			fmt.Sprintf(`{"matchName": "%s"}`, name))
	}

	rule := fmt.Sprintf(`{
	"labels": [{ "key": "%s" }],
  "endpointSelector": {
    "matchLabels": {
      "class": "xwing"
    }
  },
  "egress": [
    {
      "toFQDNs": [
      %s
      ]
    }
  ]
}`, key, strings.Join(matchNames, ",\n"))
	//fmt.Print(rule)
	return mustParseRule(rule)
}

func parseRule(rule string) (parsedRule *api.Rule, err error) {
	if err := json.Unmarshal([]byte(rule), &parsedRule); err != nil {
		return nil, err
	}

	if err := parsedRule.Sanitize(); err != nil {
		return nil, err
	}

	return parsedRule, nil
}

func mustParseRule(rule string) (parsedRule *api.Rule) {
	parsedRule, err := parseRule(rule)
	if err != nil {
		panic(fmt.Sprintf("Error parsing FQDN test rules: %s", err))
	}
	return parsedRule
}

var (
	// cilium.io dns target
	rule1 = makeRule("rule1", "cilium.io")

	// cilium.io dns target
	rule2 = makeRule("rule2", "cilium.io")

	// cilium.io, github.com dns targets
	rule3 = makeRule("rule3", "cilium.io", "github.com")

	// github.com dns target
	rule4 = makeRule("rule4", "github.com")

	ipLookups = map[string][]net.IP{
		"cilium.io": {
			net.ParseIP("172.217.18.174"),
			net.ParseIP("2a00:1450:4001:811::200e")},
		"github.com": {
			net.ParseIP("98.138.219.231"),
			net.ParseIP("72.30.35.10"),
			net.ParseIP("001:4998:c:1023::4"),
			net.ParseIP("001:4998:58:1836::10")},
	}
)

// LookupDNSNames is a wrappable dummy used by the tests. It counts the number
// of times a name is looked up in lookups, and uses ipData as a source for the
// "response"
func lookupDNSNames(ipData map[string][]net.IP, lookups map[string]int, dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
	DNSIPs = make(map[string][]net.IP)
	for _, dnsName := range dnsNames {
		lookups[dnsName] += 1
		DNSIPs[dnsName] = ipData[dnsName]
	}
	return DNSIPs, errorDNSNames
}

// TestDNSPollerRuleHandling tests these cases:
// add a rule, get one poll for that name
// add 2 rules, get one lookup for each name
// add 2 rules with the same name, get one lookup for that name
// add 1 rule, remove 1 rule. No lookups
// add 2 rules with the same name, remove 1 rule. One lookup
// add 2 rules with the different names, remove 1 rule. One lookup
//
// Each case follows the same steps:
// 1- insert rulesToAdd, ensure that we return the same number of rules
// 2- run lookupIterationsAfterAdd DNS lookups
// 3- remove rulesToDelete
// 4- rule lookupIterationsAfterDelete DNS lookups
// 5- call the testCase checkFunc
func (ds *FQDNTestSuite) TestDNSPollerRuleHandling(c *C) {
	var testCases = []struct {
		desc                        string
		rulesToAdd                  []*api.Rule
		rulesToDelete               []*api.Rule
		lookupIterationsAfterAdd    int // # of times to call LookupUpdateDNS after add but before delete
		lookupIterationsAfterDelete int // # of times to call LookupUpdateDNS after delete
		checkFunc                   func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller)
	}{
		{
			desc: "Lookup a name when added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{"cilium.io"} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1},
			rulesToDelete: nil,
		},

		{
			desc: "Lookup each name once when 2 are added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 2, Commentf("More than two DNS names was looked up for a rule with 2 DNS name"))
				for _, name := range []string{"cilium.io", "github.com"} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule3},
			rulesToDelete: nil,
		},

		{
			desc: "Lookup name once when two rules refer to it",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{"cilium.io"} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1, rule2},
			rulesToDelete: nil,
		},

		{
			desc: "No lookups after removing all rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 0, Commentf("DNS lookups occurred after removing all rules"))
			},
			rulesToAdd:    []*api.Rule{rule1},
			rulesToDelete: []*api.Rule{rule1},
		},

		{
			desc: "One lookup for a name after removing one of two referring rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(poller.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{"cilium.io"} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1, rule2},
			rulesToDelete: []*api.Rule{rule2},
		},

		{
			desc: "One lookup for a name after removing an unrelated rule",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(poller.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{"cilium.io"} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1, rule4},
			rulesToDelete: []*api.Rule{rule4},
		},
	}

	for _, testCase := range testCases {
		c.Logf("Testcase: %s", testCase.desc)
		var (
			lookups        = make(map[string]int)
			generatedRules = make([]*api.Rule, 0)

			poller = NewDNSPoller(DNSPollerConfig{
				MinTTL: 1,
				Cache:  NewDNSCache(),

				LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
					return lookupDNSNames(ipLookups, lookups, dnsNames)
				},

				AddGeneratedRules: func(rules []*api.Rule) error {
					generatedRules = append(generatedRules, rules...)
					return nil
				},
			})
		)

		rulesToAdd := []*api.Rule{}
		for _, rule := range testCase.rulesToAdd {
			rulesToAdd = append(rulesToAdd, rule.DeepCopy())
		}
		rulesToDelete := []*api.Rule{}
		for _, rule := range testCase.rulesToDelete {
			rulesToDelete = append(rulesToDelete, rule.DeepCopy())
		}

		// add rules and run basic checks
		poller.MarkToFQDNRules(rulesToAdd)
		poller.MarkToFQDNRules(rulesToDelete)
		for _, rule := range rulesToAdd {
			c.Assert(len(getUUIDFromRuleLabels(rule)), Not(Equals), 0, Commentf("Added a FQDN label to each marked rule"))
		}
		poller.StartPollForDNSName(rulesToAdd)
		for i := testCase.lookupIterationsAfterAdd; i > 0; i-- {
			err := poller.LookupUpdateDNS()
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// delete rules listed in the test case (note: we don't delete any unless
		// they are listed)
		poller.StopPollForDNSName(rulesToDelete)
		for i := testCase.lookupIterationsAfterDelete; i > 0; i-- {
			err := poller.LookupUpdateDNS()
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// call the testcase checkFunc, it will assert everything relevant to the test
		testCase.checkFunc(lookups, generatedRules, poller)
	}
}

// TestDNSPollerCIDRGeneration tests rule generation output:
// add a rule, get correct IP4/6 in ToCIDRSet
// add a rule, lookup twice, get correct IP4/6 in TOCIDRSet after change
// add a rule w/ToCIDRSet, get correct IP4/6 and old rules
// add a rule, get same UUID label on repeat generations
func (ds *FQDNTestSuite) TestDNSPollerCIDRGeneration(c *C) {
	var (
		pollCount      = 0
		generatedRules = make([]*api.Rule, 0)

		poller = NewDNSPoller(DNSPollerConfig{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
				switch pollCount {
				case 1:
					return map[string][]net.IP{"cilium.io": {net.ParseIP("1.1.1.1")}}, nil
				case 2:
					return map[string][]net.IP{"cilium.io": {net.ParseIP("2.2.2.2")}}, nil
				}
				return nil, nil
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// add rules
	rulesToAdd := []*api.Rule{rule1.DeepCopy()}
	poller.MarkToFQDNRules(rulesToAdd)
	poller.StartPollForDNSName(rulesToAdd)

	// store original UUID
	uuidOrig := getUUIDFromRuleLabels(rulesToAdd[0])
	c.Assert(uuidOrig, Not(Equals), "", Commentf("UUID label not set on rule, or not recovered correctly"))

	// poll DNS once, check that we only generate 1 rule (for 1 IP) and that we
	// still have 1 ToFQDN rule, and that the IP is correct
	generatedRules = nil
	pollCount++
	err := poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Incorrect number of generated rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToFQDNs), Equals, len(generatedRules[0].Egress[0].ToCIDRSet), Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	// Check that the UUID has not changed
	uuid1 := getUUIDFromRuleLabels(generatedRules[0])
	c.Assert(uuid1, Equals, uuidOrig, Commentf("UUID label has changed on rule since original insert"))

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	generatedRules = nil
	pollCount++
	err = poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToFQDNs), Equals, 1, Commentf("toFQDNs rule count changed when it should not"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 2, Commentf("Generated CIDR count is not the same as inserted IPs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))

	// check that the UUID has not changed
	uuid2 := getUUIDFromRuleLabels(generatedRules[0])
	c.Assert(uuid2, Equals, uuidOrig, Commentf("UUID label has changed on rule since original insert"))
	c.Assert(uuid2, Equals, uuid1, Commentf("UUID label has changed on rule since previous generation"))
}

// TestDNSPollerDropCIDROnReinsert tests that we correctly guard against
// pre-existing toCIDRSet sections:
// - when we initially insert
// - when we re-insert a generated rule
func (ds *FQDNTestSuite) TestDNSPollerDropCIDROnReinsert(c *C) {
	var (
		generatedRules = make([]*api.Rule, 0)

		poller = NewDNSPoller(DNSPollerConfig{

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
				return map[string][]net.IP{"cilium.io": {net.ParseIP("1.1.1.1")}}, nil
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// ensure we strip on MarkToFQDNRules
	rulesToAdd := []*api.Rule{rule1.DeepCopy()}
	rulesToAdd[0].Egress[0].ToCIDRSet = append(rulesToAdd[0].Egress[0].ToCIDRSet, api.CIDRRule{Cidr: api.CIDR("2.2.2.2/32")})
	poller.MarkToFQDNRules(rulesToAdd)
	c.Assert(len(rulesToAdd[0].Egress[0].ToCIDRSet), Equals, 0, Commentf("existing toCIDRSet section not stripped by MarkToFQDNRules"))

	// Add a fake "generated" CIDR entry, it should not come back later when generated
	rulesToAdd[0].Egress[0].ToCIDRSet = append(rulesToAdd[0].Egress[0].ToCIDRSet, api.CIDRRule{Cidr: api.CIDR("2.2.2.2/32")})
	poller.StartPollForDNSName(rulesToAdd)
	err := poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Generated an unexpected number of rules"))
	c.Assert(len(rulesToAdd[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("existing toCIDRSet section not stripped by GenerateRules"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestDNSPollerMultiIPUpdate(c *C) {
	var (
		pollCount      = 0
		generatedRules = make([]*api.Rule, 0)

		poller = NewDNSPoller(DNSPollerConfig{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
				switch pollCount {
				case 1:
					return map[string][]net.IP{"cilium.io": {net.ParseIP("1.1.1.1")}}, nil
				case 2:
					return map[string][]net.IP{
						"cilium.io":  {net.ParseIP("2.2.2.2")},
						"github.com": {net.ParseIP("3.3.3.3")}}, nil
				case 3:
					return map[string][]net.IP{
						"cilium.io":  {net.ParseIP("2.2.2.2")},
						"github.com": {net.ParseIP("4.4.4.4")}}, nil
				}
				return nil, nil
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				generatedRules = append(generatedRules, rules...)
				return nil
			},
		})
	)

	// add rules
	rulesToAdd := []*api.Rule{rule3.DeepCopy()}
	poller.MarkToFQDNRules(rulesToAdd)
	poller.StartPollForDNSName(rulesToAdd)

	// poll DNS once, check that we only generate 1 IP for cilium.io
	generatedRules = nil
	pollCount++
	err := poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("Incorrect number of generated rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	generatedRules = nil
	pollCount++
	err = poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 3, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[2].Cidr, Equals, api.CIDR("3.3.3.3/32"), Commentf("Incorrect IP CIDR generated"))

	// poll DNS once, check that we only generate 4 IPs, 2 cilium.io cached IPs, 1 cached gituhub.com IP, 1 new github.com IP
	generatedRules = nil
	pollCount++
	err = poller.LookupUpdateDNS()
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(generatedRules), Equals, 1, Commentf("More than 1 generated rule for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(generatedRules[0].Egress[0].ToCIDRSet), Equals, 4, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[1].Cidr, Equals, api.CIDR("2.2.2.2/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[2].Cidr, Equals, api.CIDR("3.3.3.3/32"), Commentf("Incorrect IP CIDR generated"))
	c.Assert(generatedRules[0].Egress[0].ToCIDRSet[3].Cidr, Equals, api.CIDR("4.4.4.4/32"), Commentf("Incorrect IP CIDR generated"))
}

// TestDNSPollerUpdatesOnReplace tests updates without deletion:
// add 1 matchname, poll. re-add it. See the correct output on MarkToFQDNRules
// add 2 matchnames with the different names, replace one, then back. See the correct output on MarkToFQDNRules
// re-add the original rule with only 1 matchname. It is not cached because that name was deleted
func (ds *FQDNTestSuite) TestDNSPollerUpdatesOnReplace(c *C) {

	var (
		dnsIPs = map[string][]net.IP{
			"cilium.io":         {net.ParseIP("1.1.1.1")},
			"github.com":        {net.ParseIP("2.2.2.2")},
			"anotherdomain.com": {net.ParseIP("3.3.3.3")},
		}

		poller = NewDNSPoller(DNSPollerConfig{
			MinTTL: 1,
			Cache:  NewDNSCache(),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
				lookups := make(map[string]int) // dummy
				return lookupDNSNames(dnsIPs, lookups, dnsNames)
			},

			AddGeneratedRules: func(rules []*api.Rule) error {
				return nil
			},
		})
	)

	// Add 1 rules and poll
	rules := []*api.Rule{makeRule("testRule", "cilium.io")}
	// MarkToFQDNRules adds nothing on the first try
	poller.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 0, Commentf("Generated CIDR count is 0 when no CIDRs should have been added"))

	poller.StartPollForDNSName(rules)
	poller.LookupUpdateDNS()

	// re-add. We should see IPs in-place BEFORE StartPollForDNSName.
	// MarkToFQDNRules adds the IP from the cache
	rules = []*api.Rule{makeRule("testRule", "cilium.io")}
	poller.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single ToFQDNs entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	poller.StartPollForDNSName(rules)
	poller.LookupUpdateDNS()

	// Add 2 rules and poll
	rules = []*api.Rule{makeRule("testRule", "cilium.io", "github.com")}
	poller.MarkToFQDNRules(rules)
	poller.StartPollForDNSName(rules)
	poller.LookupUpdateDNS()

	// Add a 2 matchnames without deleting, only one overlaps
	// MarkToFQDNRules should add only 1 entry
	rules = []*api.Rule{makeRule("testRule", "cilium.io", "anotherdomain.com")}
	poller.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect IP CIDR generated"))

	poller.StartPollForDNSName(rules)
	poller.LookupUpdateDNS()

	fmt.Printf("%#v\n", poller.IPs)
	// Add the original 2 matchnames without deleting
	// MarkToFQDNRules should add only 1 entry
	rules = []*api.Rule{makeRule("testRule", "cilium.io", "github.com")}
	poller.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 1, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
	c.Assert(rules[0].Egress[0].ToCIDRSet[0].Cidr, Equals, api.CIDR("1.1.1.1/32"), Commentf("Incorrect first IP CIDR generated from cache"))

	poller.StartPollForDNSName(rules)
	poller.LookupUpdateDNS()

	// Replace with 1 old matchname without deleting
	// MarkToFQDNRules should not add an entry
	rules = []*api.Rule{makeRule("testRule", "anotherdomain.com")}
	poller.MarkToFQDNRules(rules)
	c.Assert(len(rules[0].Egress), Equals, 1, Commentf("Incorrect number of generated egress rules for testCase with single cached ToFQDNs DNS entry"))
	c.Assert(len(rules[0].Egress[0].ToCIDRSet), Equals, 0, Commentf("Generated CIDR count is not the same as ToFQDNs DNS entries in cache"))
}
