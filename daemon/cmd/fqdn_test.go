// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	. "github.com/cilium/checkmate"
	ciliumdns "github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type DaemonFQDNSuite struct {
	d *Daemon
}

var _ = Suite(&DaemonFQDNSuite{})

func (ds *DaemonFQDNSuite) SetUpSuite(c *C) {
	testutils.IntegrationTest(c)

	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
}

func (ds *DaemonFQDNSuite) SetUpTest(c *C) {
	d := &Daemon{}
	d.policy = policy.NewPolicyRepository(d.identityAllocator, nil, nil, nil)
	d.ipcache = ipcache.NewIPCache(&ipcache.Configuration{
		Context:           context.TODO(),
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		PolicyHandler:     d.policy.GetSelectorCache(),
		DatapathHandler:   d.endpointManager,
	})
	d.dnsNameManager = fqdn.NewNameManager(fqdn.Config{
		MinTTL:          1,
		Cache:           fqdn.NewDNSCache(0),
		UpdateSelectors: d.updateSelectors,
		IPCache:         d.ipcache,
	})
	d.endpointManager = endpointmanager.New(&dummyEpSyncher{}, nil)
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(d.dnsNameManager)

	ds.d = d

	logger.SetEndpointInfoRegistry(&dummyInfoRegistry{})
}

type dummyInfoRegistry struct{}

func (*dummyInfoRegistry) FillEndpointInfo(info *accesslog.EndpointInfo, addr netip.Addr, id identity.NumericIdentity) {
}

// makeIPs generates count sequential IPv4 IPs
func makeIPs(count uint32) []netip.Addr {
	ips := make([]netip.Addr, 0, count)
	for i := uint32(0); i < count; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i >> 0)}))
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

	extractDNSLookups(endpoints, "0.0.0.0/0", "*", "")
}

// Benchmark_notifyOnDNSMsg stresses the main callback function for the DNS
// proxy path, which is called on every DNS request and response.
func (ds *DaemonFQDNSuite) Benchmark_notifyOnDNSMsg(c *C) {
	var (
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

		wg sync.WaitGroup
	)

	// Register rules (simulates applied policies).
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	nameManager.Lock()
	for _, sel := range selectorsToAdd {
		nameManager.RegisterForIPUpdatesLocked(sel)
	}
	nameManager.Unlock()

	// Initialize the endpoints.
	endpoints := make([]*endpoint.Endpoint, c.N)
	for i := range endpoints {
		endpoints[i] = &endpoint.Endpoint{
			ID:   uint16(c.N % 65000),
			IPv4: netip.MustParseAddr(fmt.Sprintf("10.96.%d.%d", (c.N>>16)%8, c.N%256)),
			SecurityIdentity: &identity.Identity{
				ID: identity.NumericIdentity(c.N % int(identity.GetMaximumAllocationIdentity())),
			},
			DNSZombies: &fqdn.DNSZombieMappings{
				Mutex: lock.Mutex{},
			},
		}
		ep := endpoints[i]
		ep.UpdateLogger(nil)
		ep.DNSHistory = fqdn.NewDNSCache(0)
	}

	c.ResetTimer()
	// Simulate parallel DNS responses from the upstream DNS for cilium.io and
	// ebpf.io, done by every endpoint.
	for i := 0; i < c.N; i++ {
		wg.Add(1)
		go func(ep *endpoint.Endpoint) {
			defer wg.Done()
			// Using a hardcoded string representing endpoint IP:port as this
			// parameter is only used in logging. Not using the endpoint's IP
			// so we don't spend any time in the benchmark on converting from
			// net.IP to string.
			c.Assert(ds.d.notifyOnDNSMsg(time.Now(), ep, "10.96.64.8:12345", 0, "10.96.64.1:53", &ciliumdns.Msg{
				MsgHdr: ciliumdns.MsgHdr{
					Response: true,
				},
				Question: []ciliumdns.Question{{
					Name: dns.FQDN("cilium.io"),
				}},
				Answer: []ciliumdns.RR{&ciliumdns.A{
					Hdr: ciliumdns.RR_Header{Name: dns.FQDN("cilium.io")},
					A:   ciliumDNSRecord[dns.FQDN("cilium.io")].IPs[0],
				}}}, "udp", true, &dnsproxy.ProxyRequestContext{}), IsNil)

			c.Assert(ds.d.notifyOnDNSMsg(time.Now(), ep, "10.96.64.4:54321", 0, "10.96.64.1:53", &ciliumdns.Msg{
				MsgHdr: ciliumdns.MsgHdr{
					Response: true,
				},
				Compress: false,
				Question: []ciliumdns.Question{{
					Name: dns.FQDN("ebpf.io"),
				}},
				Answer: []ciliumdns.RR{&ciliumdns.A{
					Hdr: ciliumdns.RR_Header{Name: dns.FQDN("ebpf.io")},
					A:   ebpfDNSRecord[dns.FQDN("ebpf.io")].IPs[0],
				}}}, "udp", true, &dnsproxy.ProxyRequestContext{}), IsNil)
		}(endpoints[i%len(endpoints)])
	}

	wg.Wait()
}
