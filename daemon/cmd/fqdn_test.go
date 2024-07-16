// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ciliumdns "github.com/cilium/dns"
	"github.com/stretchr/testify/require"

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
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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

var notifyOnDNSMsgBenchSetup sync.Once

func setupDaemonFQDNSuite(tb testing.TB) *DaemonFQDNSuite {
	testutils.IntegrationTest(tb)

	// We rely on a sync.Once to complete the benchmark setup that initialize
	// read-only global status.
	// Also, node.SetTestLocalNodeStore() panics if it called more than once.
	notifyOnDNSMsgBenchSetup.Do(func() {
		// set FQDN related options to defaults in order to avoid a flood of warnings
		option.Config.DNSProxyLockCount = defaults.DNSProxyLockCount
		option.Config.DNSProxyLockTimeout = defaults.DNSProxyLockTimeout
		option.Config.FQDNProxyResponseMaxDelay = defaults.FQDNProxyResponseMaxDelay

		// Set local node store as it is accessed by NewLogRecord to get node IPv4
		node.SetTestLocalNodeStore()

		re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
		logger.SetEndpointInfoRegistry(&dummyInfoRegistry{})
	})

	ds := &DaemonFQDNSuite{}
	d := &Daemon{}
	d.ctx = context.Background()
	d.policy = policy.NewPolicyRepository(nil, nil, nil, nil)
	d.endpointManager = endpointmanager.New(&dummyEpSyncher{}, nil, nil)
	d.ipcache = ipcache.NewIPCache(&ipcache.Configuration{
		Context:           context.TODO(),
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		PolicyHandler:     d.policy.GetSelectorCache(),
		DatapathHandler:   d.endpointManager,
	})
	d.dnsNameManager = fqdn.NewNameManager(fqdn.Config{
		MinTTL:  1,
		Cache:   fqdn.NewDNSCache(0),
		IPCache: d.ipcache,
	})
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(d.dnsNameManager)

	ds.d = d

	return ds
}

type dummyInfoRegistry struct{}

func (*dummyInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
}

type dummySelectorCacheUser struct{}

func (d *dummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, added, deleted []identity.NumericIdentity) {
}

// BenchmarkNotifyOnDNSMsg stresses the main callback function for the DNS
// proxy path, which is called on every DNS request and response.
func BenchmarkNotifyOnDNSMsg(b *testing.B) {
	ds := setupDaemonFQDNSuite(b)

	var (
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
	dscu := &dummySelectorCacheUser{}
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	for _, sel := range selectorsToAdd {
		ds.d.policy.GetSelectorCache().AddFQDNSelector(dscu, nil, sel)
	}

	const nEndpoints int = 1024

	// Initialize the endpoints.
	endpoints := make([]*endpoint.Endpoint, nEndpoints)
	for i := range endpoints {
		endpoints[i] = &endpoint.Endpoint{
			ID:   uint16(i),
			IPv4: netip.MustParseAddr(fmt.Sprintf("10.96.%d.%d", i/256, i%256)),
			SecurityIdentity: &identity.Identity{
				ID: identity.NumericIdentity(i % int(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))),
			},
			DNSZombies: &fqdn.DNSZombieMappings{
				Mutex: lock.Mutex{},
			},
		}
		ep := endpoints[i]
		ep.UpdateLogger(nil)
		ep.DNSHistory = fqdn.NewDNSCache(0)
	}

	b.ResetTimer()
	// Simulate parallel DNS responses from the upstream DNS for cilium.io and
	// ebpf.io, done by every endpoint.
	for i := 0; i < b.N; i++ {
		for _, ep := range endpoints {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Using a hardcoded string representing endpoint IP:port as this
				// parameter is only used in logging. Not using the endpoint's IP
				// so we don't spend any time in the benchmark on converting from
				// net.IP to string.
				require.Nil(b, ds.d.notifyOnDNSMsg(time.Now(), ep, "10.96.64.8:12345", 0, "10.96.64.1:53", &ciliumdns.Msg{
					MsgHdr: ciliumdns.MsgHdr{
						Response: true,
					},
					Question: []ciliumdns.Question{{
						Name: dns.FQDN("cilium.io"),
					}},
					Answer: []ciliumdns.RR{&ciliumdns.A{
						Hdr: ciliumdns.RR_Header{Name: dns.FQDN("cilium.io")},
						A:   ciliumDNSRecord[dns.FQDN("cilium.io")].IPs[0],
					}}}, "udp", true, &dnsproxy.ProxyRequestContext{}))

				require.Nil(b, ds.d.notifyOnDNSMsg(time.Now(), ep, "10.96.64.4:54321", 0, "10.96.64.1:53", &ciliumdns.Msg{
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
					}}}, "udp", true, &dnsproxy.ProxyRequestContext{}))
			}()
		}
		wg.Wait()
	}
}
