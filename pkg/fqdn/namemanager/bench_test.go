// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/policy/api"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/time"
)

// BenchmarkUpdateGenerateDNS tests updating a large number of selectors.
//
// Run it like
// go test -benchmem -run=^$ -bench ^BenchmarkUpdateGeneratedDNS$ github.com/cilium/cilium/pkg/fqdn -benchtime=4x -count=10
func BenchmarkUpdateGenerateDNS(b *testing.B) {

	// For every i in range 1 .. K, create selectors
	// - "$K.example.com"
	// - "*.$K.example.com"
	// as well as *.example.com.
	//
	// Then, update the generated DNS N * K times, setting i to N % K, and updating
	// - $i.example.com
	// - foo.$i.example.com
	// with a random new IP

	numSelectors := 1000

	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)

	nameManager := New(ManagerParams{
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          defaults.StateDir,
		},
		IPCache: testipcache.NewMockIPCache(),
	})

	for i := range numSelectors {
		nameManager.RegisterFQDNSelector(api.FQDNSelector{
			MatchName: fmt.Sprintf("%d.example.com", i),
		})
		nameManager.RegisterFQDNSelector(api.FQDNSelector{
			MatchPattern: fmt.Sprintf("*.%d.example.com", i),
		})
	}
	nameManager.RegisterFQDNSelector(api.FQDNSelector{
		MatchPattern: "*.example.com",
	})

	t := time.Now() // doesn't matter, just need a stable base
	ip := netip.MustParseAddr("10.0.0.0")

	b.ResetTimer() // Don't benchmark adding selectors, just evaluating them
	for i := range b.N * numSelectors {
		t = t.Add(1 * time.Second)
		ip = ip.Next()

		k := i % numSelectors
		nameManager.UpdateGenerateDNS(context.Background(), t, dns.FQDN(fmt.Sprintf("%d.example.com", k)), &fqdn.DNSIPRecords{
			TTL: 60,
			IPs: []netip.Addr{ip},
		})

		nameManager.UpdateGenerateDNS(context.Background(), t, dns.FQDN(fmt.Sprintf("example.%d.example.com", k)), &fqdn.DNSIPRecords{
			TTL: 60,
			IPs: []netip.Addr{ip},
		})
	}
}

// BenchmarkFqdnCache tests how slow a full dump of DNSHistory from a number of
// endpoints is. Each endpoints has 1000 DNS lookups, each with 10 IPs. The
// dump iterates over all endpoints, lookups, and IPs.
func BenchmarkFqdnCache(b *testing.B) {
	const endpoints = 8

	caches := make([]*fqdn.DNSCache, 0, endpoints)
	for i := 0; i < b.N; i++ {
		lookupTime := time.Now()
		dnsHistory := fqdn.NewDNSCache(0)

		for i := range 1000 {
			dnsHistory.Update(lookupTime, fmt.Sprintf("domain-%d.com.", i), makeIPs(10), 1000)
		}

		caches = append(caches, dnsHistory)
	}

	nameManager := New(ManagerParams{
		Config: NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          defaults.StateDir,
		},
		IPCache: testipcache.NewMockIPCache(),
		EPMgr:   &epMgrMock{caches},
	})
	prefixMatcher := func(_ netip.Addr) bool { return true }
	nameMatcher := func(_ string) bool { return true }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nameManager.dnsHistoryModel("", prefixMatcher, nameMatcher, "")
	}
}

type epMgrMock struct {
	caches []*fqdn.DNSCache
}

func (mgr *epMgrMock) Lookup(id string) (*endpoint.Endpoint, error) {
	return nil, fmt.Errorf("Lookup not implemented")
}

func (mgr *epMgrMock) GetEndpoints() []*endpoint.Endpoint {
	out := make([]*endpoint.Endpoint, 0, len(mgr.caches))
	for i, c := range mgr.caches {
		out = append(out, &endpoint.Endpoint{
			ID:         uint16(i),
			DNSHistory: c,
			DNSZombies: fqdn.NewDNSZombieMappings(1000, 1000),
		})
	}
	return out
}
