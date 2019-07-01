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
	"github.com/miekg/dns"

	. "gopkg.in/check.v1"
)

// force a fail if something calls this function
func lookupFail(c *C, dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
	c.Error("Lookup function called when it should not")
	return nil, nil
}

// TestNameManagerCIDRGeneration tests rule generation output:
// add a rule, get correct IP4/6 in ToCIDRSet
// add a rule, lookup twice, get correct IP4/6 in TOCIDRSet after change
// add a rule w/ToCIDRSet, get correct IP4/6 and old rules
// add a rule, get same UUID label on repeat generations
func (ds *FQDNTestSuite) TestNameManagerCIDRGeneration(c *C) {
	var (
		selIPMap map[api.FQDNSelector][]net.IP

		nameManager = NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(selectorIPMapping map[api.FQDNSelector][]net.IP, selectorsWithoutIPs []api.FQDNSelector) error {
				for k, v := range selectorIPMapping {
					selIPMap[k] = v
				}
				return nil
			},
		})
	)

	// add rules
	ids := nameManager.RegisterForIdentityUpdates(ciliumIOSel)
	c.Assert(len(ids), Equals, 0)
	c.Assert(ids, Not(IsNil))

	// poll DNS once, check that we only generate 1 rule (for 1 IP) and that we
	// still have 1 ToFQDN rule, and that the IP is correct
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	err := nameManager.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect length for testCase with single ToFQDNs entry"))

	expectedIPs := []net.IP{net.ParseIP("1.1.1.1")}
	ips, _ := selIPMap[ciliumIOSel]
	c.Assert(ips[0].Equal(expectedIPs[0]), Equals, true)

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	err = nameManager.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Only one entry per FQDNSelector should be present"))
	expectedIPs = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}
	c.Assert(selIPMap[ciliumIOSel][0].Equal(expectedIPs[0]), Equals, true)
	c.Assert(selIPMap[ciliumIOSel][1].Equal(expectedIPs[1]), Equals, true)
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestNameManagerMultiIPUpdate(c *C) {
	var (
		selIPMap map[api.FQDNSelector][]net.IP

		nameManager = NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(selectorIPMapping map[api.FQDNSelector][]net.IP, selectorsWithoutIPs []api.FQDNSelector) error {
				for k, v := range selectorIPMapping {
					selIPMap[k] = v
				}
				return nil
			},
		})
	)

	// add rules
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, githubSel}
	for _, sel := range selectorsToAdd {
		ids := nameManager.RegisterForIdentityUpdates(sel)
		c.Assert(ids, Not(IsNil))
	}

	// poll DNS once, check that we only generate 1 IP for cilium.io
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	err := nameManager.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect number of plumbed FQDN selectors"))
	c.Assert(selIPMap[ciliumIOSel][0].Equal(net.ParseIP("1.1.1.1")), Equals, true)

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	err = nameManager.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("3.3.3.3")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap), Equals, 2, Commentf("More than 2 FQDN selectors while only 2 were added"))
	c.Assert(len(selIPMap[ciliumIOSel]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIPMap[githubSel]), Equals, 1, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(selIPMap[ciliumIOSel][0].Equal(net.ParseIP("1.1.1.1")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[ciliumIOSel][1].Equal(net.ParseIP("2.2.2.2")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][0].Equal(net.ParseIP("3.3.3.3")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))

	// poll DNS once, check that we only generate 4 IPs, 2 cilium.io cached IPs, 1 cached github.com IP, 1 new github.com IP
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	err = nameManager.UpdateGenerateDNS(time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("4.4.4.4")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap[ciliumIOSel]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIPMap[githubSel]), Equals, 2, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(selIPMap[ciliumIOSel][0].Equal(net.ParseIP("1.1.1.1")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[ciliumIOSel][1].Equal(net.ParseIP("2.2.2.2")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][0].Equal(net.ParseIP("3.3.3.3")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][1].Equal(net.ParseIP("4.4.4.4")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))

	// Second registration returns nil
	ids := nameManager.RegisterForIdentityUpdates(githubSel)
	c.Assert(ids, IsNil)

	nameManager.UnregisterForIdentityUpdates(githubSel)
	_, exists := nameManager.allSelectors[githubSel]
	c.Assert(exists, Equals, false)

	nameManager.UnregisterForIdentityUpdates(ciliumIOSel)
	_, exists = nameManager.allSelectors[ciliumIOSel]
	c.Assert(exists, Equals, false)

}
