// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ciliumdns "github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type DaemonFQDNSuite struct {
	d *fqdnProxyBootstrapper
}

var notifyOnDNSMsgBenchSetup sync.Once

func setupDaemonFQDNSuite(tb testing.TB) *DaemonFQDNSuite {
	testutils.IntegrationTest(tb)
	logger := hivetest.Logger(tb)

	// We rely on a sync.Once to complete the benchmark setup that initialize
	// read-only global status.
	// Also, node.SetTestLocalNodeStore() panics if it called more than once.
	notifyOnDNSMsgBenchSetup.Do(func() {
		// set FQDN related options to defaults in order to avoid a flood of warnings
		option.Config.DNSProxyLockTimeout = defaults.DNSProxyLockTimeout
		option.Config.FQDNProxyResponseMaxDelay = defaults.FQDNProxyResponseMaxDelay

		// Set local node store as it is accessed by NewLogRecord to get node IPv4
		node.SetTestLocalNodeStore()

		re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	})

	ds := &DaemonFQDNSuite{}
	d := &fqdnProxyBootstrapper{}
	d.policyRepo = policy.NewPolicyRepository(logger, nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	d.endpointManager = endpointmanager.New(logger, &dummyEpSyncher{}, nil, nil, nil)
	d.ipcache = ipcache.NewIPCache(&ipcache.Configuration{
		Context:           context.TODO(),
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		PolicyHandler:     d.policyRepo.GetSelectorCache(),
		DatapathHandler:   d.endpointManager,
	})
	ns := namemanager.New(namemanager.ManagerParams{
		Config: namemanager.NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          defaults.StateDir,
		},
		IPCache: d.ipcache,
	})
	d.nameManager = ns
	d.nameManager.CompleteBootstrap()
	d.policyRepo.GetSelectorCache().SetLocalIdentityNotifier(d.nameManager)
	d.dnsMessageHandler = messagehandler.NewDNSMessageHandler(
		messagehandler.DNSMessageHandlerParams{
			Logger:            logger,
			NameManager:       ns,
			ProxyInstance:     nil,
			ProxyAccessLogger: accesslog.NewProxyAccessLogger(logger, accesslog.ProxyAccessLoggerConfig{}, &noopNotifier{}, &dummyInfoRegistry{}),
		})

	ds.d = d

	return ds
}

type noopNotifier struct{}

func (*noopNotifier) NewProxyLogRecord(l *accesslog.LogRecord) error { return nil }

type dummyInfoRegistry struct{}

func (*dummyInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
}

// BenchmarkNotifyOnDNSMsg stresses the main callback function for the DNS
// proxy path, which is called on every DNS request and response.
func BenchmarkNotifyOnDNSMsg(b *testing.B) {
	var (
		ciliumMsg = &ciliumdns.Msg{
			MsgHdr: ciliumdns.MsgHdr{
				Response: true,
			},
			Question: []ciliumdns.Question{{
				Name: dns.FQDN("cilium.io"),
			}},
			Answer: []ciliumdns.RR{&ciliumdns.A{
				Hdr: ciliumdns.RR_Header{
					Name: dns.FQDN("cilium.io"),
					Ttl:  3600,
				},
				A: net.ParseIP("192.0.2.3"),
			}},
		}
		ebpfMsg = &ciliumdns.Msg{
			MsgHdr: ciliumdns.MsgHdr{
				Response: true,
			},
			Compress: false,
			Question: []ciliumdns.Question{{
				Name: dns.FQDN("ebpf.io"),
			}},
			Answer: []ciliumdns.RR{&ciliumdns.A{
				Hdr: ciliumdns.RR_Header{
					Name: dns.FQDN("ebpf.io"),
					Ttl:  3600,
				},
				A: net.ParseIP("192.0.2.4"),
			}},
		}
		srvAddr    = netip.MustParseAddrPort("10.96.64.1:53")
		emptyPRCtx = &dnsproxy.ProxyRequestContext{}
	)
	ds := setupDaemonFQDNSuite(b)

	var (
		ciliumIOSel             = api.FQDNSelector{MatchName: "cilium.io"}
		ciliumIOSelMatchPattern = api.FQDNSelector{MatchPattern: "*cilium.io."}
		ebpfIOSel               = api.FQDNSelector{MatchName: "ebpf.io"}

		wg sync.WaitGroup
	)

	// Register rules (simulates applied policies).
	dscu := &testpolicy.DummySelectorCacheUser{}
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	for _, sel := range selectorsToAdd {
		ds.d.policyRepo.GetSelectorCache().AddFQDNSelector(dscu, policy.EmptyStringLabels, sel)
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

	b.ReportAllocs()

	// Simulate parallel DNS responses from the upstream DNS for cilium.io and
	// ebpf.io, done by every endpoint.
	for b.Loop() {
		for _, ep := range endpoints {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Using a hardcoded string representing endpoint IP:port as this
				// parameter is only used in logging. Not using the endpoint's IP
				// so we don't spend any time in the benchmark on converting from
				// net.IP to string.
				require.NoError(b, ds.d.dnsMessageHandler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.8:12345", 0, srvAddr, ciliumMsg, "udp", true, emptyPRCtx))
				require.NoError(b, ds.d.dnsMessageHandler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.4:54321", 0, srvAddr, ebpfMsg, "udp", true, emptyPRCtx))
			}()
		}
		wg.Wait()
	}
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, hr cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}
