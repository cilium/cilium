// Copyright 2019-2020 Authors of Cilium
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

package cmd

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	. "gopkg.in/check.v1"
	k8sCache "k8s.io/client-go/tools/cache"
)

type DaemonFQDNSuite struct {
	d *Daemon
}

var _ = Suite(&DaemonFQDNSuite{})

type FakeRefcountingIdentityAllocator struct {
	*testidentity.FakeIdentityAllocator

	// We create a simple identity allocator here to validate that identity
	// allocation and release are balanced.
	currentID     int
	ipToIdentity  map[string]int
	identityCount counter.IntCounter
}

func NewFakeIdentityAllocator(c cache.IdentityCache) *FakeRefcountingIdentityAllocator {
	return &FakeRefcountingIdentityAllocator{
		FakeIdentityAllocator: testidentity.NewFakeIdentityAllocator(c),
		currentID:             1000,
		ipToIdentity:          make(map[string]int),
		identityCount:         make(counter.IntCounter),
	}
}

// AllocateCIDRsForIPs performs reference counting for IP/identity allocation,
// but doesn't interact with pkg/identity or pkg/ipcache.
// 'newlyAllocatedIdentities' is not properly mocked out.
//
// The resulting identities are not guaranteed to have all fields populated.
func (f *FakeRefcountingIdentityAllocator) AllocateCIDRsForIPs(IPs []net.IP, newlyAllocatedIdentities map[string]*identity.Identity) ([]*identity.Identity, error) {
	result := make([]*identity.Identity, 0, len(IPs))
	for _, ip := range IPs {
		id, ok := f.ipToIdentity[ip.String()]
		if !ok {
			id = f.currentID
			f.ipToIdentity[ip.String()] = id
			f.currentID = id + 1
		}
		f.identityCount.Add(id)
		cidrLabels := append([]string{}, ip.String())
		result = append(result, &identity.Identity{
			ID:        identity.NumericIdentity(id),
			CIDRLabel: labels.NewLabelsFromModel(cidrLabels),
		})
	}
	return result, nil
}

// ReleaseCIDRIdentitiesByID performs reference counting for IP/identity
// allocation, but doesn't interact with pkg/identity or pkg/ipcache.
func (f *FakeRefcountingIdentityAllocator) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	// Leave the ipToIdentity mapping alone since we don't have enough info
	// to clean it up. That's fine, it's not necessary for current testing.
	for _, id := range identities {
		f.identityCount.Delete(int(id))
	}
}

func (f *FakeRefcountingIdentityAllocator) IdentityReferenceCounter() counter.IntCounter {
	return f.identityCount
}

func (f *FakeRefcountingIdentityAllocator) Close() {
}
func (f *FakeRefcountingIdentityAllocator) InitIdentityAllocator(versioned.Interface, k8sCache.Store) <-chan struct{} {
	return nil
}
func (f *FakeRefcountingIdentityAllocator) WatchRemoteIdentities(kvstore.BackendOperations) (*allocator.RemoteCache, error) {
	return nil, nil
}

func (ds *DaemonFQDNSuite) SetUpTest(c *C) {
	d := &Daemon{}
	d.identityAllocator = NewFakeIdentityAllocator(nil)
	d.policy = policy.NewPolicyRepository(d.identityAllocator, nil, nil)
	d.dnsNameManager = fqdn.NewNameManager(fqdn.Config{
		MinTTL:          1,
		Cache:           fqdn.NewDNSCache(0),
		UpdateSelectors: d.updateSelectors,
	})
	d.endpointManager = WithCustomEndpointManager(&dummyEpSyncher{})
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(d.dnsNameManager)
	ds.d = d
}

// makeIPs generates count sequential IPv4 IPs
func makeIPs(count uint32) []net.IP {
	ips := make([]net.IP, 0, count)
	for i := uint32(0); i < count; i++ {
		ips = append(ips, net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i>>0)))
	}
	return ips
}

// BenchmarkFqdnCache tests how slow a full dump of DNSHistory from a number of
// endpoints is. Each endpoints has 1000 DNS lookups, each with 10 IPs. The
// dump iterates over all endpoints, lookups, and IPs.
func (ds *DaemonSuite) BenchmarkFqdnCache(c *C) {
	c.StopTimer()

	endpoints := make([]*endpoint.Endpoint, 0, c.N)
	for i := 0; i < c.N; i++ {
		lookupTime := time.Now()
		ep := &endpoint.Endpoint{} // only works because we only touch .DNSHistory
		ep.DNSHistory = fqdn.NewDNSCache(0)

		for i := 0; i < 1000; i++ {
			ep.DNSHistory.Update(lookupTime, fmt.Sprintf("domain-%d.com.", i), makeIPs(10), 1000)
		}

		endpoints = append(endpoints, ep)
	}
	c.StartTimer()

	extractDNSLookups(endpoints, "0.0.0.0/0", "*")
}

func (ds *DaemonFQDNSuite) TestFQDNIdentityReferenceCounting(c *C) {
	var (
		idAllocator             = ds.d.identityAllocator.(*FakeRefcountingIdentityAllocator)
		nameManager             = ds.d.dnsNameManager
		ciliumIOSel             = api.FQDNSelector{MatchName: "cilium.io"}
		ciliumIOSelMatchPattern = api.FQDNSelector{MatchPattern: "*cilium.io."}
		ebpfIOSel               = api.FQDNSelector{MatchName: "ebpf.io"}
		ciliumDNSRecord         = map[string]*fqdn.DNSIPRecords{
			dns.FQDN("cilium.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("192.0.2.3")}},
		}
		ebpfDNSRecord = map[string]*fqdn.DNSIPRecords{
			dns.FQDN("ebpf.io"): {TTL: 60, IPs: []net.IP{net.ParseIP("192.0.2.4")}},
		}
	)

	// add rules
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	nameManager.Lock()
	for _, sel := range selectorsToAdd {
		nameManager.RegisterForIdentityUpdatesLocked(sel)
	}
	nameManager.Unlock()

	// poll DNS once, check that we only generate 1 IP for cilium.io
	_, _, err := nameManager.UpdateGenerateDNS(context.Background(), time.Now(), ciliumDNSRecord)
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(idAllocator.IdentityReferenceCounter()), Equals, 1,
		Commentf("Unexpected number of identities allocated during DNS name event handler"))

	// Same thing, new reference for same identity but otherwise the same.
	_, _, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), ciliumDNSRecord)
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(idAllocator.IdentityReferenceCounter()), Equals, 1,
		Commentf("Unexpected number of identities allocated during DNS name event handler"))

	// poll DNS for ebpf.io, check that we now have two different identities referenced
	_, _, err = nameManager.UpdateGenerateDNS(context.Background(), time.Now(), ebpfDNSRecord)
	c.Assert(err, IsNil, Commentf("Error mapping selectors to IPs"))
	c.Assert(len(idAllocator.IdentityReferenceCounter()), Equals, 2,
		Commentf("Unexpected number of identities allocated during DNS name event handler"))

	// Two selectors are selecting the same identity. If we remove one of
	// them, then the identity should remain referenced by the other
	// existing selector.
	var wg sync.WaitGroup
	ds.d.policy.GetSelectorCache().UpdateFQDNSelector(ciliumIOSel, nil, &wg)
	wg.Wait()
	c.Assert(len(idAllocator.IdentityReferenceCounter()), Equals, 2,
		Commentf("Unexpected number of identities allocated during DNS name event handler"))

	// Similar to FQDN garbage collection, set the list of identities that
	// each selector would select to the empty set and then observe that
	// the outstanding identity references are released.
	for _, sel := range selectorsToAdd {
		ds.d.policy.GetSelectorCache().UpdateFQDNSelector(sel, nil, &wg)
	}
	wg.Wait()
	c.Assert(idAllocator.IdentityReferenceCounter(), checker.DeepEquals, counter.IntCounter{},
		Commentf("The Daemon code leaked references to one or more identities"))
}
