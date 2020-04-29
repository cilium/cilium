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
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	fakeConfig "github.com/cilium/cilium/pkg/option/fake"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/miekg/dns"

	. "gopkg.in/check.v1"
)

// IPRegexp matches IPv4 or IPv6 addresses. It was stolen from the internet.
var IPRegexp = regexp.MustCompile(`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`)

func extractIPFromLabels(lbls labels.Labels) net.IP {
	for lbl := range lbls {
		if ipStr := IPRegexp.FindString(lbl); ipStr != "" {
			return net.ParseIP(ipStr)
		}
	}

	return nil
}

func setupTestAllocator() *cache.CachingIdentityAllocator {
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore
	kvstore.SetupDummy("etcd")

	owner := newDummyOwner()
	identity.InitWellKnownIdentities(&fakeConfig.Config{})
	// The nils are only used by k8s CRD identities. We default to kvstore.
	allocator := cache.NewCachingIdentityAllocator(owner)
	<-allocator.InitIdentityAllocator(nil, nil)
	return allocator
}

func tearDownTestAllocator(mgr *cache.CachingIdentityAllocator) {
	mgr.Close()
	//mgr.IdentityAllocator.DeleteAllKeys()
}

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
	allocator := setupTestAllocator()
	defer tearDownTestAllocator(allocator)

	var (
		selIPMap map[api.FQDNSelector][]net.IP

		nameManager = NewNameManager(Config{
			MinTTL:            1,
			Cache:             NewDNSCache(0),
			IdentityAllocator: allocator,

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(ctx context.Context, selectorIdentitySliceMapping map[api.FQDNSelector][]*identity.Identity, selectorsWithoutIPs []api.FQDNSelector) (*sync.WaitGroup, error) {
				fmt.Printf("FML UpdateSelectors called on %+v", selectorIdentitySliceMapping)
				for selector, v := range selectorIdentitySliceMapping {
					for _, ident := range v {
						if ip := extractIPFromLabels(ident.Labels); ip != nil {
							fmt.Printf("FML saw IP %v for labels %+v\n", ip, ident.Labels)
							selIPMap[selector] = append(selIPMap[selector], ip)
						}
					}
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
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	_, err := nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect length for testCase with single ToFQDNs entry"))

	expectedIPs := []net.IP{net.ParseIP("1.1.1.1")}
	ips, _ := selIPMap[ciliumIOSel]
	c.Assert(ips[0].Equal(expectedIPs[0]), Equals, true)

	// poll DNS once, check that we only generate 1 rule (for 2 IPs that we
	// inserted) and that we still have 1 ToFQDN rule, and that the IP, now
	// different, is correct
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}}})
	c.Assert(err, IsNil, Commentf("Error generating IP CIDR rules"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Only one entry per FQDNSelector should be present"))
	expectedIPs = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}
	c.Assert(selIPMap[ciliumIOSel][0].Equal(expectedIPs[0]), Equals, true)
	c.Assert(selIPMap[ciliumIOSel][1].Equal(expectedIPs[1]), Equals, true)
}

// Test that all IPs are updated when one is
func (ds *FQDNTestSuite) TestNameManagerMultiIPUpdate(c *C) {
	allocator := setupTestAllocator()
	defer tearDownTestAllocator(allocator)

	var (
		selIPMap map[api.FQDNSelector][]net.IP

		nameManager = NewNameManager(Config{
			MinTTL:            1,
			Cache:             NewDNSCache(0),
			IdentityAllocator: allocator,

			LookupDNSNames: func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error) {
				return lookupFail(c, dnsNames)
			},

			UpdateSelectors: func(ctx context.Context, selectorIdentitySliceMapping map[api.FQDNSelector][]*identity.Identity, selectorsWithoutIPs []api.FQDNSelector) (*sync.WaitGroup, error) {
				for selector, v := range selectorIdentitySliceMapping {
					for _, ident := range v {
						if ip := extractIPFromLabels(ident.Labels); ip != nil {
							selIPMap[selector] = append(selIPMap[selector], ip)
						}
					}
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
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	_, err := nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{dns.Fqdn("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("1.1.1.1")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap), Equals, 1, Commentf("Incorrect number of plumbed FQDN selectors"))
	c.Assert(selIPMap[ciliumIOSel][0].Equal(net.ParseIP("1.1.1.1")), Equals, true)

	// poll DNS once, check that we only generate 3 IPs, 2 cached from before and 1 new one for github.com
	selIPMap = make(map[api.FQDNSelector][]net.IP)
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
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
	_, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"):  {TTL: 60, IPs: []net.IP{net.ParseIP("2.2.2.2")}},
		dns.Fqdn("github.com"): {TTL: 60, IPs: []net.IP{net.ParseIP("4.4.4.4")}}})
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(selIPMap[ciliumIOSel]), Equals, 2, Commentf("Incorrect number of IPs for cilium.io selector"))
	c.Assert(len(selIPMap[githubSel]), Equals, 2, Commentf("Incorrect number of IPs for github.com selector"))
	c.Assert(selIPMap[ciliumIOSel][0].Equal(net.ParseIP("1.1.1.1")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[ciliumIOSel][1].Equal(net.ParseIP("2.2.2.2")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][0].Equal(net.ParseIP("3.3.3.3")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))
	c.Assert(selIPMap[githubSel][1].Equal(net.ParseIP("4.4.4.4")), Equals, true, Commentf("Incorrect IP mapping to FQDN"))

	// Second registration fails because IdenitityAllocator is not initialized
	nameManager.Lock()
	ids := nameManager.RegisterForIdentityUpdatesLocked(githubSel)
	c.Assert(ids, IsNil)

	nameManager.UnregisterForIdentityUpdatesLocked(githubSel)
	_, exists := nameManager.allSelectors[githubSel]
	c.Assert(exists, Equals, false)

	nameManager.UnregisterForIdentityUpdatesLocked(ciliumIOSel)
	_, exists = nameManager.allSelectors[ciliumIOSel]
	c.Assert(exists, Equals, false)
	nameManager.Unlock()

}

// IdentityCache is a cache of identity to labels mapping
type IdentityCache map[identity.NumericIdentity]labels.LabelArray

type dummyOwner struct {
	updated chan identity.NumericIdentity
	mutex   lock.Mutex
	cache   IdentityCache
}

func newDummyOwner() *dummyOwner {
	return &dummyOwner{
		cache:   IdentityCache{},
		updated: make(chan identity.NumericIdentity, 1024),
	}
}

func (d *dummyOwner) UpdateIdentities(added, deleted cache.IdentityCache) {
	d.mutex.Lock()
	log.Debugf("Dummy UpdateIdentities(added: %v, deleted: %v)", added, deleted)
	for id, lbls := range added {
		d.cache[id] = lbls
		d.updated <- id
	}
	for id := range deleted {
		delete(d.cache, id)
		d.updated <- id
	}
	d.mutex.Unlock()
}

func (d *dummyOwner) GetIdentity(id identity.NumericIdentity) labels.LabelArray {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.cache[id]
}

func (d *dummyOwner) GetNodeSuffix() string {
	return "foo"
}

// WaitUntilID waits until an update event is received for the
// 'target' identity and returns the number of events processed to get
// there. Returns 0 in case of 'd.updated' channel is closed or
// nothing is received from that channel in 60 seconds.
func (d *dummyOwner) WaitUntilID(target identity.NumericIdentity) int {
	rounds := 0
	for {
		select {
		case nid, ok := <-d.updated:
			if !ok {
				// updates channel closed
				return 0
			}
			rounds++
			if nid == target {
				return rounds
			}
		case <-time.After(60 * time.Second):
			// Timed out waiting for KV-store events
			return 0
		}
	}
}
