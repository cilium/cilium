// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	ciliumdns "github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	mockipc "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

func BenchmarkNotifyOnDNSMsg(b *testing.B) {
	var (
		logger    = hivetest.Logger(b)
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

	var (
		ciliumIOSel             = api.FQDNSelector{MatchName: "cilium.io"}
		ciliumIOSelMatchPattern = api.FQDNSelector{MatchPattern: "*cilium.io."}
		ebpfIOSel               = api.FQDNSelector{MatchName: "ebpf.io"}

		wg sync.WaitGroup
	)

	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	policyRepo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	ipc := &mockipc.MockIPCache{}
	nm := namemanager.New(namemanager.ManagerParams{
		Config: namemanager.NameManagerConfig{
			MinTTL:            1,
			DNSProxyLockCount: defaults.DNSProxyLockCount,
			StateDir:          defaults.StateDir,
		},
		IPCache:    ipc,
		PolicyRepo: policyRepo,
		Logger:     logger,
	})
	policyRepo.GetSelectorCache().SetLocalIdentityNotifier(nm)
	node.SetTestLocalNodeStore()
	option.Config.DNSProxyLockTimeout = defaults.DNSProxyLockTimeout
	option.Config.FQDNProxyResponseMaxDelay = defaults.FQDNProxyResponseMaxDelay

	handler := NewDNSMessageHandler(
		DNSMessageHandlerParams{
			Logger:            logger,
			NameManager:       nm,
			ProxyAccessLogger: accesslog.NewProxyAccessLogger(logger, accesslog.ProxyAccessLoggerConfig{}, &noopNotifier{}, &dummyInfoRegistry{}),
		})

	// Register rules (simulates applied policies).
	dscu := &testpolicy.DummySelectorCacheUser{}
	selectorsToAdd := api.FQDNSelectorSlice{ciliumIOSel, ciliumIOSelMatchPattern, ebpfIOSel}
	for _, sel := range selectorsToAdd {
		policyRepo.GetSelectorCache().AddFQDNSelector(dscu, policy.EmptyStringLabels, sel)
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
				require.NoError(b, handler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.8:12345", 0, srvAddr, ciliumMsg, "udp", true, emptyPRCtx))
				require.NoError(b, handler.NotifyOnDNSMsg(time.Now(), ep, "10.96.64.4:54321", 0, srvAddr, ebpfMsg, "udp", true, emptyPRCtx))
			}()
		}
		wg.Wait()
	}
}

type noopNotifier struct{}

func (*noopNotifier) NewProxyLogRecord(l *accesslog.LogRecord) error { return nil }

type dummyInfoRegistry struct{}

func (*dummyInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
}
