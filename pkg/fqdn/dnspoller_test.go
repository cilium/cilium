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
	"context"
	"net"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/miekg/dns"

	. "gopkg.in/check.v1"
)

var (
	ciliumIOSel = api.FQDNSelector{
		MatchName: "cilium.io",
	}

	githubSel = api.FQDNSelector{
		MatchName: "github.com",
	}

	ciliumIOSelMatchPattern = api.FQDNSelector{
		MatchPattern: "*cilium.io.",
	}
)

func (ds *FQDNTestSuite) TestNameManagerSelectorHandling(c *C) {
	var testCases = []struct {
		desc                        string
		selectorsToAdd              api.FQDNSelectorSlice
		selectorsToDelete           api.FQDNSelectorSlice
		lookupIterationsAfterAdd    int // # of times to call LookupUpdateDNS after add but before delete
		lookupIterationsAfterDelete int // # of times to call LookupUpdateDNS after delete
		checkFunc                   func(lookups map[string]int, nameManager *NameManager)
	}{
		{
			desc:                        "Lookup a name when added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel},
			selectorsToDelete: nil,
		},
		{
			desc:                        "Lookup each name once when 2 are added in a rule",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(lookups), Equals, 2, Commentf("More than two DNS names was looked up for a rule with 2 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io"), dns.Fqdn("github.com")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel, githubSel},
			selectorsToDelete: nil,
		},
		{
			desc:                        "Lookup name once when two rules refer to it",
			lookupIterationsAfterAdd:    1,
			lookupIterationsAfterDelete: 0,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(lookups), Equals, 1, Commentf("More than one DNS name was looked up for a rule with 1 DNS name"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSel},
			selectorsToDelete: nil,
		},
		{
			desc:                        "No lookups after removing all rules",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(lookups), Equals, 0, Commentf("DNS lookups occurred after removing all rules"))
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel},
			selectorsToDelete: api.FQDNSelectorSlice{ciliumIOSel},
		},
		{
			desc:                        "One lookup for a name after removing one of two referring FQDNSelectors",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(nameManager.GetDNSNames()), Equals, 0, Commentf("No more DNS names should be present since tracking of FQDNSelectors is done via set (adding two of the same selector is equivalent to adding one)"))
				c.Assert(len(lookups), Equals, 0, Commentf("Incorrect number of lookups for single name with a single FQDNSelector"))
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSel},
			selectorsToDelete: api.FQDNSelectorSlice{ciliumIOSel},
		},
		{
			desc:                        "One lookup for a name after removing an unrelated rule",
			lookupIterationsAfterAdd:    0,
			lookupIterationsAfterDelete: 1,
			checkFunc: func(lookups map[string]int, nameManager *NameManager) {
				c.Assert(len(nameManager.GetDNSNames()), Equals, 1, Commentf("Incorrect number of DNS targets for single name with a single referring rule"))
				c.Assert(len(lookups), Equals, 1, Commentf("Incorrect number of lookups for single name with a single referring rule"))
				for _, name := range []string{dns.Fqdn("cilium.io")} {
					c.Assert(lookups[name], Not(Equals), 0, Commentf("No lookups for DNS name %s in rule", name))
					c.Assert(lookups[name], Equals, 1, Commentf("More than one DNS lookup was triggered for the same DNS name %s", name))
				}
			},
			selectorsToAdd:    api.FQDNSelectorSlice{ciliumIOSel, githubSel},
			selectorsToDelete: api.FQDNSelectorSlice{githubSel},
		},
	}

	for _, testCase := range testCases {
		c.Logf("Testcase: %s", testCase.desc)
		var (
			lookups = make(map[string]int)

			cfg = Config{
				MinTTL: 1,
				Cache:  NewDNSCache(0),

				LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
					return lookupDNSNames(ipLookups, lookups, dnsNames), nil
				},

				UpdateSelectors: func(map[api.FQDNSelector][]net.IP, []api.FQDNSelector) error {
					return nil
				},
			}

			nameManager = NewNameManager(cfg)
			poller      = NewDNSPoller(cfg, nameManager)
		)

		for _, fqdnSel := range testCase.selectorsToAdd {
			nameManager.RegisterForIdentityUpdates(fqdnSel)
		}
		for i := testCase.lookupIterationsAfterAdd; i > 0; i-- {
			err := poller.LookupUpdateDNS(context.Background())
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// delete rules listed in the test case (note: we don't delete any unless
		// they are listed)
		for _, fqdnSel := range testCase.selectorsToDelete {
			nameManager.UnregisterForIdentityUpdates(fqdnSel)
		}
		for i := testCase.lookupIterationsAfterDelete; i > 0; i-- {
			err := poller.LookupUpdateDNS(context.Background())
			c.Assert(err, IsNil, Commentf("Error running DNS lookups"))
		}

		// call the testcase checkFunc, it will assert everything relevant to the test
		testCase.checkFunc(lookups, nameManager)
	}
}
