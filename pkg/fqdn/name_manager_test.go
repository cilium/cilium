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
	"sort"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/identity"
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
		selIDMap map[api.FQDNSelectorString][]identity.NumericIdentity

		nameManager = NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(ctx context.Context, selectorIDs map[api.FQDNSelectorString][]identity.NumericIdentity) (*sync.WaitGroup, error) {
				for k, v := range selectorIDs {
					sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
					selIDMap[k] = v
				}
				return &sync.WaitGroup{}, nil
			},
		})
	)

	// add rules
	nameManager.Lock()
	ids := nameManager.RegisterForIdentityUpdatesLocked(ciliumIOSel)
	nameManager.Unlock()
	c.Assert(len(ids), Equals, 0)
	c.Assert(ids, Not(IsNil))

	// poll DNS once, check that we only generate 1 rule (for 1 IP) and that we
	// still have 1 ToFQDN rule, and that the IP is correct
	selIDMap = make(map[api.FQDNSelectorString][]identity.NumericIdentity)
	_, err := nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIDMap), Equals, 1, Commentf("Incorrect length for testCase with single ToFQDNs entry"))

	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][0]), Equals, 16777217)

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	selIDMap = make(map[api.FQDNSelectorString][]identity.NumericIdentity)
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(selIDMap), Equals, 1, Commentf("Only one entry per FQDNSelector should be present"))
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][0]), Equals, 16777217)
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][1]), Equals, 16777218)
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestNameManagerMultiIPUpdate(c *C) {
	var (
		selIDMap map[api.FQDNSelectorString][]identity.NumericIdentity

		nameManager = NewNameManager(Config{
			MinTTL: 1,
			Cache:  NewDNSCache(0),

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(ctx context.Context, selectorIDs map[api.FQDNSelectorString][]identity.NumericIdentity) (*sync.WaitGroup, error) {
				for k, v := range selectorIDs {
					sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
					selIDMap[k] = v
				}
				return &sync.WaitGroup{}, nil
			},
		})
	)

	// add rules
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, githubSel}
	nameManager.Lock()
	for _, sel := range selectorsToAdd {
		ids := nameManager.RegisterForIdentityUpdatesLocked(sel)
		c.Assert(ids, Not(IsNil))
	}
	nameManager.Unlock()

	// poll DNS once, check that we only generate 1 IP for cilium.io
	selIDMap = make(map[api.FQDNSelectorString][]identity.NumericIdentity)
	_, err := nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIDMap), Equals, 1, Commentf("Incorrect number of plumbed FQDN selectors"))
	//c.Assert(selIPMap[ciliumIOSel.MapKey()][0].Equal(net.ParseIP("1.1.1.1")), Equals, true)

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	selIDMap = make(map[api.FQDNSelectorString][]identity.NumericIdentity)
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("3.3.3.3")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIDMap), Equals, 2, Commentf("More than 2 FQDN selectors while only 2 were added"))
	c.Assert(len(selIDMap[ciliumIOSel.MapKey()]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIDMap[githubSel.MapKey()]), Equals, 1, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][0]), Equals, 16777217, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][1]), Equals, 16777218, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(int(selIDMap[githubSel.MapKey()][0]), Equals, 16777219, Commentf("Incorrect IP mapping to FQDN"))

	// poll DNS once, check that we only generate 4 IPs, 2 cilium.io cached IPs, 1 cached github.com IP, 1 new github.com IP
	selIDMap = make(map[api.FQDNSelectorString][]identity.NumericIdentity)
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("4.4.4.4")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIDMap[ciliumIOSel.MapKey()]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIDMap[githubSel.MapKey()]), Equals, 2, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][0]), Equals, 16777217, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(int(selIDMap[ciliumIOSel.MapKey()][1]), Equals, 16777218, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(int(selIDMap[githubSel.MapKey()][0]), Equals, 16777219, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(int(selIDMap[githubSel.MapKey()][1]), Equals, 16777220, Commentf("Incorrect IP mapping to FQDN"))

	// Second registration fails because IdenitityAllocator is not initialized
	nameManager.Lock()
	ids := nameManager.RegisterForIdentityUpdatesLocked(githubSel)
	c.Assert(ids, IsNil)

	nameManager.UnregisterForIdentityUpdatesLocked(githubSel)
	_, exists := nameManager.allSelectors[githubSel.MapKey()]
	c.Assert(exists, Equals, false)

	nameManager.UnregisterForIdentityUpdatesLocked(ciliumIOSel)
	_, exists = nameManager.allSelectors[ciliumIOSel.MapKey()]
	c.Assert(exists, Equals, false)
	nameManager.Unlock()

}
