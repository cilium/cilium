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

	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

// add a rule, get one poll for that name
// add 2 rules, get one lookup for each name
// add 2 rules with the same name, get one lookup for that name
// add 1 rule, remove 1 rule. No lookups
// add 2 rules with the same name, remove 1 rule. One lookup
// add 2 rules with the different names, remove 1 rule. One lookup

// add a rule, get correct IP4/6 in TOCIDRSet
// add a rule, lookup twice, get correct IP4/6 in TOCIDRSet after change
// add a rule w/ToCIDRSet, get correct IP4/6 and old rules
// add a rule, get same UUID label on repeat generations

func parseRule(rule string) (parsedRule *api.Rule, err error) {
	var parsedRules = []api.Rule{}
	if err := json.Unmarshal([]byte(rule), &parsedRules); err != nil {
		return nil, err
	}

	parsedRule = &parsedRules[0]
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
	// google.com dns target
	rule1 = mustParseRule(`
[
  {
		"labels": [{ "key": "rule1" }],
    "endpointSelector": {
      "matchLabels": {
        "class": "xwing"
      }
    },
    "egress": [
      {
        "toFQDN": [
          {
            "fqdn": [
              "google.com"
            ]
          }
        ]
      }
    ]
  }
]`)

	// google.com dns target
	rule2 = mustParseRule(`
[
  {
		"labels": [{ "key": "rule2" }],
    "endpointSelector": {
      "matchLabels": {
        "class": "xwing"
      }
    },
    "egress": [
      {
        "toFQDN": [
          {
            "fqdn": [
              "google.com"
            ]
          }
        ]
      }
    ]
  }
]`)

	// google.com, yahoo.com dns targets
	rule3 = mustParseRule(`
[
  {
		"labels": [{ "key": "rule3" }],
    "endpointSelector": {
      "matchLabels": {
        "class": "xwing"
      }
    },
    "egress": [
      {
        "toFQDN": [
          {
            "fqdn": [
              "google.com",
              "yahoo.com"
            ]
          }
        ]
      }
    ]
  }
]`)

	// yahoo.com dns target
	rule4 = mustParseRule(`
[
  {
		"labels": [{ "key": "rule4" }],
    "endpointSelector": {
      "matchLabels": {
        "class": "xwing"
      }
    },
    "egress": [
      {
        "toFQDN": [
          {
            "fqdn": [
              "yahoo.com"
            ]
          }
        ]
      }
    ]
  }
]`)

	ipLookups = map[string][]net.IP{
		"google.com": []net.IP{
			net.ParseIP("172.217.18.174"),
			net.ParseIP("2a00:1450:4001:811::200e")},
		"yahoo.com": []net.IP{
			net.ParseIP("98.138.219.231"),
			net.ParseIP("72.30.35.10"),
			net.ParseIP("001:4998:c:1023::4"),
			net.ParseIP("001:4998:58:1836::10")},
	}
)

func (ds *FQDNTestSuite) TestDNSPoller(c *C) {
	var testCases = []struct {
		desc                        string
		rulesToAdd                  []*api.Rule
		rulesToDelete               []*api.Rule
		lookupIterationsAfterAdd    int // # of times to call LookupUpdateDNS after add but before delete
		lookupIterationsAfterDelete int // # of times to call LookupUpdateDNS after delete
		check                       func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller)
	}{
		{
			desc: "Lookup a name when added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{"google.com"} {
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
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 2, Commentf("More than two DNS names was looked up for a rule with 2 DNS name"))
				for _, name := range []string{"google.com", "yahoo.com"} {
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
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{"google.com"} {
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
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(lookups), Equals, 0, Commentf("DNS lookups occurred after removing all rules"))
			},
			rulesToAdd:    []*api.Rule{rule1},
			rulesToDelete: []*api.Rule{rule1},
		},

		{
			desc: "One lookup for a name after removing one of two referring rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(poller.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{"google.com"} {
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
			check: func(lookups map[string]int, generatedRules []*api.Rule, poller *DNSPoller) {
				c.Assert(len(poller.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{"google.com"} {
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
			poller         = NewDNSPoller(DNSPollerConfig{
				LookupDNSNames: func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error) {
					for _, dnsName := range dnsNames {
						lookups[dnsName] += 1
						DNSIPs = make(map[string][]net.IP)
						DNSIPs[dnsName] = ipLookups[dnsName]
					}

					return DNSIPs, errorDNSNames
				},
				AddGeneratedRules: func(rules []*api.Rule) error {
					generatedRules = append(generatedRules, rules...)
					return nil
				},
			})
		)

		// copy rules in case they are edited in-place
		rulesToAdd := make([]*api.Rule, 0, len(testCase.rulesToAdd))
		for _, rule := range testCase.rulesToAdd {
			rulesToAdd = append(rulesToAdd, rule.DeepCopy())
		}

		// copy rules in case they are edited in-place
		rulesToDelete := make([]*api.Rule, 0, len(testCase.rulesToDelete))
		for _, rule := range testCase.rulesToDelete {
			rulesToDelete = append(rulesToDelete, rule.DeepCopy())
		}

		// add rules and run basic checks
		fqdnMarkedRules, err := poller.StartPollForDNSName(rulesToAdd)
		c.Assert(err, IsNil, Commentf("Error adding ToFQDN rules during test"))
		c.Assert(len(fqdnMarkedRules), Equals, len(rulesToAdd), Commentf("Number of FQDN marked rules is the same as original list"))
		for _, rule := range fqdnMarkedRules {
			c.Assert(len(getUUIDFromRuleLabels(rule)), Not(Equals), 0, Commentf("Added a FQDN label to each marked rule"))
		}
		for i := testCase.lookupIterationsAfterAdd; i > 0; i-- {
			poller.LookupUpdateDNS()
		}

		// find the rules to delete in the list of fqdnMarked rules. We must do
		// this because StopPollForDNSName uses the ToFQDN-UUID label to track
		// rules
		markedRulesToDelete := make([]*api.Rule, 0, len(rulesToDelete))
		for _, toDeleteRule := range rulesToDelete {
			for _, markedRule := range fqdnMarkedRules {
				if markedRule.Labels.Contains(toDeleteRule.Labels) {
					markedRulesToDelete = append(markedRulesToDelete, markedRule)
				}
			}
		}

		// delete rules listed in the test case (note: we don't delete any unless
		// they are listed)
		poller.StopPollForDNSName(markedRulesToDelete)
		for i := testCase.lookupIterationsAfterDelete; i > 0; i-- {
			poller.LookupUpdateDNS()
		}

		// call the testcase check function, it will assert everything
		testCase.check(lookups, generatedRules, poller)
	}
}
