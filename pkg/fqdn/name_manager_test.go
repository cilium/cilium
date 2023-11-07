// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/policy/api"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// TestNameManagerCIDRGeneration tests rule generation output:
// add a rule, get correct IP4/6 in ToCIDRSet
// add a rule, lookup twice, get correct IP4/6 in TOCIDRSet after change
// add a rule w/ToCIDRSet, get correct IP4/6 and old rules
// add a rule, get same UUID label on repeat generations
func (ds *FQDNTestSuite) TestNameManagerCIDRGeneration(c *C) {
	var (
		selIPMap map[api.FQDNSelector][]netip.Addr

		nameManager = NewNameManager(Config{
			MinTTL:  1,
			Cache:   NewDNSCache(0),
			IPCache: testipcache.NewMockIPCache(),

			UpdateSelectors: func(ctx context.Context, selectorIPMapping map[api.FQDNSelector][]netip.Addr, _ uint64) *sync.WaitGroup {
				for k, v := range selectorIPMapping {
					selIPMap[k] = v
				}
				return &sync.WaitGroup{}
			},
		})
	)

	// add rules
	nameManager.Lock()
	nameManager.RegisterForIPUpdatesLocked(ciliumIOSel)
	nameManager.Unlock()

	// poll DNS once, check that we only generate 1 rule (for 1 IP) and that we
	// still have 1 ToFQDN rule, and that the IP is correct
	selIPMap = make(map[api.FQDNSelector][]netip.Addr)
	nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.FQDN("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect length for testCase with single ToFQDNs entry"))

	expectedIPs := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	ips := selIPMap[ciliumIOSel]
	c.Assert(ips[0], Equals, expectedIPs[0])

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	selIPMap = make(map[api.FQDNSelector][]netip.Addr)
	nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.FQDN("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("10.0.0.2")}}})
	c.Assert(len(selIPMap), Equals, 1, Commentf("Only one entry per FQDNSelector should be present"))
	expectedIPs = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.2")}
	c.Assert(selIPMap[ciliumIOSel], checker.DeepEquals, expectedIPs)
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestNameManagerMultiIPUpdate(c *C) {
	var (
		selIPMap map[api.FQDNSelector][]netip.Addr

		nameManager = NewNameManager(Config{
			MinTTL:  1,
			Cache:   NewDNSCache(0),
			IPCache: testipcache.NewMockIPCache(),

			UpdateSelectors: func(ctx context.Context, selectorIPMapping map[api.FQDNSelector][]netip.Addr, _ uint64) *sync.WaitGroup {
				for k, v := range selectorIPMapping {
					selIPMap[k] = v
				}
				return &sync.WaitGroup{}
			},
		})
	)

	// add rules
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, githubSel}
	nameManager.Lock()
	for _, sel := range selectorsToAdd {
		nameManager.RegisterForIPUpdatesLocked(sel)
	}
	nameManager.Unlock()

	// poll DNS once, check that we only generate 1 IP for cilium.io
	selIPMap = make(map[api.FQDNSelector][]netip.Addr)
	nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.FQDN("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect number of plumbed FQDN selectors"))
	c.Assert(selIPMap[ciliumIOSel][0], Equals, netip.MustParseAddr("1.1.1.1"))

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	selIPMap = make(map[api.FQDNSelector][]netip.Addr)
	nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
		dns.FQDN("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("10.0.0.2")}},
		dns.FQDN("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("10.0.0.3")}}})
	c.Assert(len(selIPMap), Equals, 2, Commentf("More than 2 FQDN selectors while only 2 were added"))
	c.Assert(len(selIPMap[ciliumIOSel]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIPMap[githubSel]), Equals, 1, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(selIPMap[ciliumIOSel][0], Equals, netip.MustParseAddr("1.1.1.1"), Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[ciliumIOSel][1], Equals, netip.MustParseAddr("10.0.0.2"), Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][0], Equals, netip.MustParseAddr("10.0.0.3"), Commentf("Incorrect IP mapping to FQDN"))

	// poll DNS once, check that we only generate 4 IPs, 2 cilium.io cached IPs, 1 cached github.com IP, 1 new github.com IP
	selIPMap = make(map[api.FQDNSelector][]netip.Addr)
	nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
		dns.FQDN("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("10.0.0.2")}},
		dns.FQDN("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("10.0.0.4")}}})
	c.Assert(len(selIPMap[ciliumIOSel]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIPMap[githubSel]), Equals, 2, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(selIPMap[ciliumIOSel][0], Equals, netip.MustParseAddr("1.1.1.1"), Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[ciliumIOSel][1], Equals, netip.MustParseAddr("10.0.0.2"), Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][0], Equals, netip.MustParseAddr("10.0.0.3"), Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][1], Equals, netip.MustParseAddr("10.0.0.4"), Commentf("Incorrect IP mapping to FQDN"))

	// Second registration fails because IdenitityAllocator is not initialized
	nameManager.Lock()
	nameManager.RegisterForIPUpdatesLocked(githubSel)

	nameManager.UnregisterForIPUpdatesLocked(githubSel)
	_, exists := nameManager.allSelectors[githubSel]
	c.Assert(exists, Equals, false)

	nameManager.UnregisterForIPUpdatesLocked(ciliumIOSel)
	_, exists = nameManager.allSelectors[ciliumIOSel]
	c.Assert(exists, Equals, false)
	nameManager.Unlock()

}
