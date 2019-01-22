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
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/dns"

	. "gopkg.in/check.v1"
)

// TestRuleGenRuleHandling tests these cases:
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
func (ds *FQDNTestSuite) TestRuleGenRuleHandling(c *C) {
	var testCases = []struct {
		desc                        string
		rulesToAdd                  []*api.Rule
		rulesToDelete               []*api.Rule
		lookupIterationsAfterAdd    int // # of times to call LookupUpdateDNS after add but before delete
		lookupIterationsAfterDelete int // # of times to call LookupUpdateDNS after delete
		checkFunc                   func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen)
	}{
		{
			desc:                        "Lookup a name when added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1},
			rulesToDelete: nil,
		},

		{
			desc:                        "Lookup each name once when 2 are added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(lookups), Equals, 2, Commentf("More than two DNS names was looked up for a rule with 2 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io"), dns.Fqdn("github.com")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule3},
			rulesToDelete: nil,
		},

		{
			desc:                        "Lookup name once when two rules refer to it",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1, rule2},
			rulesToDelete: nil,
		},

		{
			desc:                        "No lookups after removing all rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(lookups), Equals, 0, Commentf("DNS lookups occurred after removing all rules"))
			},
			rulesToAdd:    []*api.Rule{rule1},
			rulesToDelete: []*api.Rule{rule1},
		},

		{
			desc:                        "One lookup for a name after removing one of two referring rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(gen.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			rulesToAdd:    []*api.Rule{rule1, rule2},
			rulesToDelete: []*api.Rule{rule2},
		},

		{
			desc:                        "One lookup for a name after removing an unrelated rule",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, generatedRules []*api.Rule, gen *RuleGen) {
				c.Assert(len(gen.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
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

			cfg = Config{
				MinTTL: 1,
				Cache:  NewDNSCache(),

				LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
					return lookupDNSNames(ipLookups, lookups, dnsNames), nil
				},

				AddGeneratedRules: func(rules []*api.Rule) error {
					generatedRules = append(generatedRules, rules...)
					return nil
				},
			}

			gen    = NewRuleGen(cfg)
			poller = NewDNSPoller(cfg, gen)
		)

		rulesToAdd := []*api.Rule{}
		for _, rule := range testCase.rulesToAdd {
			rulesToAdd = append(rulesToAdd, rule.DeepCopy())
		}
		rulesToDelete := []*api.Rule{}
		for _, rule := range testCase.rulesToDelete {
			// Copy the pointer to an added rule if any
			for i := range testCase.rulesToAdd {
				if rule == testCase.rulesToAdd[i] {
					rulesToDelete = append(rulesToDelete, rulesToAdd[i])
				}
			}
		}

		// add rules and run basic checks
		gen.MarkToFQDNRules(rulesToAdd)
		for i, rule := range rulesToAdd {
			c.Assert(len(getRuleUUIDLabel(rule)), Not(Equals), 0, Commentf("Added a FQDN label to each marked rule"))
			if i > 0 {
				c.Assert(getRuleUUIDLabel(rule), Not(Equals), getRuleUUIDLabel(rulesToAdd[0]), Commentf("Each rule must have a unique UUID"))
			}
		}
		for _, rule := range rulesToDelete {
			c.Assert(len(getRuleUUIDLabel(rule)), Not(Equals), 0, Commentf("Added a FQDN label to each marked rule"))
		}

		gen.StartManageDNSName(rulesToAdd)
		for i := testCase.lookupIterationsAfterAdd; i > 0; i-- {
			err := poller.LookupUpdateDNS()
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// delete rules listed in the test case (note: we don't delete any unless
		// they are listed)
		gen.StopManageDNSName(rulesToDelete)
		for i := testCase.lookupIterationsAfterDelete; i > 0; i-- {
			err := poller.LookupUpdateDNS()
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// call the testcase checkFunc, it will assert everything relevant to the test
		testCase.checkFunc(lookups, generatedRules, gen)
	}
}
