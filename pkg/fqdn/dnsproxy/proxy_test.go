// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	fqdndns "github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

type DNSProxyTestSuite struct {
	repo         policy.PolicyRepository
	dnsTCPClient *dns.Client
	dnsServer    *dns.Server
	proxy        *DNSProxy
	restoring    bool
}

func setupDNSProxyTestSuite(tb testing.TB) *DNSProxyTestSuite {
	testutils.PrivilegedTest(tb)
	logger := hivetest.Logger(tb)

	s := &DNSProxyTestSuite{}

	// Add these identities
	wg := &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(identity.IdentityMap{
		dstID1: labels.Labels{"Dst1": labels.NewLabel("Dst1", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID2: labels.Labels{"Dst2": labels.NewLabel("Dst2", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID3: labels.Labels{"Dst3": labels.NewLabel("Dst3", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID4: labels.Labels{"Dst4": labels.NewLabel("Dst4", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	s.repo = policy.NewPolicyRepository(logger, nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: time.Second, SingleInflight: true}
	s.dnsServer = setupServer(tb)
	require.NotNil(tb, s.dnsServer, "unable to setup DNS server")
	dnsProxyConfig := DNSProxyConfig{
		Logger:                 logger,
		Address:                "",
		IPv4:                   true,
		IPv6:                   true,
		EnableDNSCompression:   true,
		MaxRestoreDNSIPs:       1000,
		ConcurrencyLimit:       0,
		ConcurrencyGracePeriod: 0,
		RejectReply:            option.Config.FQDNRejectResponse,
	}
	proxy := NewDNSProxy(dnsProxyConfig,
		s,
		func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
			if s.restoring {
				return nil, false, fmt.Errorf("No EPs available when restoring")
			}
			model := newTestEndpointModel(int(epID1), endpoint.StateReady)
			ep, err := endpoint.NewEndpointFromChangeModel(tb.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
			ep.Start(uint16(model.ID))
			tb.Cleanup(ep.Stop)
			return ep, false, err
		},
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, dstAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error {
			return nil
		},
	)
	err := proxy.Listen(0)
	require.NoError(tb, err, "error listening for DNS requests")
	s.proxy = proxy

	// This is here because Listener or Listener.Addr() was nil. The
	// lookupTargetDNSServer function doesn't need to change the target.
	require.NotNil(tb, s.dnsServer.Listener, "DNS server missing a Listener")
	DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
	require.NotNil(tb, DNSServerListenerAddr, "DNS server missing a Listener address")
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (network u8proto.U8proto, server netip.AddrPort, err error) {
		return u8proto.UDP, DNSServerListenerAddr.AddrPort(), nil
	}
	dstPortProto = restore.MakeV2PortProto(uint16(DNSServerListenerAddr.Port), u8proto.UDP)

	tb.Cleanup(func() {
		for epID := range s.proxy.allowed {
			for pp := range s.proxy.allowed[epID] {
				s.proxy.UpdateAllowed(epID, pp, nil)
			}
		}
		for epID := range s.proxy.restored {
			s.proxy.RemoveRestoredRules(uint16(epID))
		}
		if len(s.proxy.cache) > 0 {
			tb.Error("cache not fully empty after removing all rules. Possible memory leak found.")
		}
		s.dnsServer.Listener.Close()
		for _, s := range s.proxy.DNSServers {
			s.Shutdown()
		}
	})

	return s
}

func (s *DNSProxyTestSuite) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
	switch {
	case ip.String() == DNSServerListenerAddr.IP.String():
		ident := ipcache.Identity{
			ID:     dstID1,
			Source: source.Unspec,
		}
		return ident, true
	default:
		ident := ipcache.Identity{
			ID:     dstID2,
			Source: source.Unspec,
		}
		return ident, true
	}
}

func (s *DNSProxyTestSuite) LookupByIdentity(nid identity.NumericIdentity) []string {
	DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
	switch nid {
	case dstID1:
		return []string{DNSServerListenerAddr.IP.String()}
	case dstID2:
		return []string{"127.0.0.1", "127.0.0.2"}
	default:
		return nil
	}
}

func setupServer(tb testing.TB) (dnsServer *dns.Server) {
	waitOnListen := make(chan struct{})
	dnsServer = &dns.Server{Addr: ":0", Net: "tcp", NotifyStartedFunc: func() { close(waitOnListen) }}
	go dnsServer.ListenAndServe()
	dns.HandleFunc(".", serveDNS)

	select {
	case <-waitOnListen:
		return dnsServer

	case <-time.After(10 * time.Second):
		tb.Error("DNS server did not start listening")
	}

	return nil
}

func serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	retARR, err := dns.NewRR(m.Question[0].Name + " 60 IN A 1.1.1.1")
	if err != nil {
		panic(err)
	}
	m.Answer = append(m.Answer, retARR)

	w.WriteMsg(m)
}

// Setup identities, ports and endpoint IDs we will need
var (
	cacheAllocator          = cache.NewCachingIdentityAllocator(logging.DefaultSlogLogger, &testidentity.IdentityAllocatorOwnerMock{}, cache.AllocatorConfig{})
	testSelectorCache       = policy.NewSelectorCache(logging.DefaultSlogLogger, cacheAllocator.GetIdentityCache())
	dummySelectorCacheUser  = &testpolicy.DummySelectorCacheUser{}
	DstID1Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst1=test"))
	cachedDstID1Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, DstID1Selector)
	DstID2Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst2=test"))
	cachedDstID2Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, DstID2Selector)
	DstID3Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst3=test"))
	cachedDstID3Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, DstID3Selector)
	DstID4Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst4=test"))
	cachedDstID4Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, DstID4Selector)

	cachedWildcardSelector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, api.WildcardEndpointSelector)

	epID1            = uint64(111)
	epID2            = uint64(222)
	epID3            = uint64(333)
	dstID1           = identity.NumericIdentity(1001)
	dstID2           = identity.NumericIdentity(2002)
	dstID3           = identity.NumericIdentity(3003)
	dstID4           = identity.NumericIdentity(4004)
	dstPortProto     = restore.MakeV2PortProto(53, u8proto.UDP) // Set below when we setup the server!
	udpProtoPort53   = dstPortProto
	udpProtoPort54   = restore.MakeV2PortProto(54, u8proto.UDP)
	udpProtoPort8053 = restore.MakeV2PortProto(8053, u8proto.UDP)
	tcpProtoPort53   = restore.MakeV2PortProto(53, u8proto.TCP)
)

func TestRejectFromDifferentEndpoint(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	// Reject a query from not endpoint 1
	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID2, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was not rejected when it should be blocked")
}

func TestAcceptFromMatchingEndpoint(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	// accept a query that matches from endpoint1
	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")
}

func TestAcceptNonRegex(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "simple.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	// accept a query that matches from endpoint1
	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")
}

func TestRejectNonRegex(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := "ciliumXio."

	// reject a query for a non-regex where a . is different (i.e. ensure simple FQDNs treat . as .)
	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was not rejected when it should be blocked")
}

func (s *DNSProxyTestSuite) requestRejectNonMatchingRefusedResponse(t *testing.T) *dns.Msg {
	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := "notcilium.io."

	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was not rejected when it should be blocked")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	return request
}

func TestRejectNonMatchingRefusedResponseWithNameError(t *testing.T) {
	// reject a query with NXDomain
	option.Config.FQDNRejectResponse = option.FQDNProxyDenyWithNameError
	t.Cleanup(func() {
		option.Config.FQDNRejectResponse = ""
	})
	s := setupDNSProxyTestSuite(t)

	request := s.requestRejectNonMatchingRefusedResponse(t)

	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, dns.RcodeNameError, response.Rcode, "DNS request from test client was not rejected when it should be blocked")
}

func TestRejectNonMatchingRefusedResponseWithRefused(t *testing.T) {
	// reject a query with Refused
	option.Config.FQDNRejectResponse = option.FQDNProxyDenyWithRefused
	t.Cleanup(func() {
		option.Config.FQDNRejectResponse = ""
	})
	s := setupDNSProxyTestSuite(t)

	request := s.requestRejectNonMatchingRefusedResponse(t)

	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, dns.RcodeRefused, response.Rcode, "DNS request from test client was not rejected when it should be blocked")
}

func TestErrorResponseServfail(t *testing.T) {
	s := setupDNSProxyTestSuite(t)
	// Trigger an error in the lookupTargetDNSServer function to force a SERVFAIL response
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (network u8proto.U8proto, server netip.AddrPort, err error) {
		return u8proto.UDP, netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), uint16(0)), fmt.Errorf("cannot find target DNS server")
	}

	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)

	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, dns.RcodeServerFailure, response.Rcode, "DNS request from test client did not trigger a SERVFAIL response")
}

func TestRespondViaCorrectProtocol(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	// Respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp) because we
	// connect with TCP, and the server only listens on TCP.

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v)", rtt)
	require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s", response)
	require.Equal(t, "cilium.io.\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
}

func TestRespondMixedCaseInRequestResponse(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	// Test that mixed case query is allowed out and then back in to support
	// high-order-bit query uniqueing schemes (and a data exfiltration
	// vector :( )
	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := "CILIUM.io."

	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s", response)
	require.Equal(t, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")

	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err = s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %+v", response.Answer)
	require.Equal(t, "ciliuM.io.\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
}

func TestCheckNoRules(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{},
		},
	}
	query := name

	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Error when inserting rules")

	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")

	require.True(t, allowed, "request was rejected when it should be allowed")

	l7map = policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{},
			},
		},
	}
	_, err = s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Error when inserting rules")

	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")
}

func TestCheckAllowedTwiceRemovedOnce(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	// Add the rule twice
	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	_, err = s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Delete once, it should reject
	_, err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.NoError(t, err, "Could not update with rules")
	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Delete once, it should reject and not crash
	_, err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.NoError(t, err, "Could not update with rules")
	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")
}

func makeMapOfRuleIPOrCIDR(addrs ...string) map[restore.RuleIPOrCIDR]struct{} {
	m := make(map[restore.RuleIPOrCIDR]struct{}, len(addrs))
	for _, addr := range addrs {
		if ripc, err := restore.ParseRuleIPOrCIDR(addr); err == nil {
			m[ripc] = struct{}{}
		}
	}
	return m
}

func TestFullPathDependence(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupDNSProxyTestSuite(t)

	// Test that we consider each of endpoint ID, destination SecID (via the
	// selector in L7DataMap), destination port (set in the redirect itself) and
	// the DNS name.
	// The rules approximate:
	// +------+--------+---------+----------+----------------+
	// | From |   To   | DstPort | Protocol |    DNSNames    |
	// +======+========+=========+===========================+
	// | EP1  | DstID1 |      53 |    UDP   | *.ubuntu.com   |
	// | EP1  | DstID1 |      53 |    TCP   | sub.ubuntu.com |
	// | EP1  | DstID1 |      53 |    UDP   | aws.amazon.com |
	// | EP1  | DstID2 |      53 |    UDP   | cilium.io      |
	// | EP1  | *      |      54 |    UDP   | example.com    |
	// | EP3  | DstID1 |      53 |    UDP   | example.com    |
	// | EP3  | DstID3 |      53 |    UDP   | *              |
	// | EP3  | DstID3 |      53 |    TCP   | example.com    |
	// | EP3  | DstID4 |      53 |    UDP   | nil            |
	// +------+--------+---------+---------------------------+
	//
	// Cases:
	// +------+-------+--------+------+---------------------------+----------+----------------------------------------------------------------+
	// | Case | From  |   To   | Port | Protocol |     Query      | Outcome  |                             Reason                             |
	// +------+-------+--------+------+----------+----------------+----------+----------------------------------------------------------------+
	// |    1 | EPID1 | DstID1 |   53 |    UDP   | www.ubuntu.com | Allowed  |                                                                |
	// |    2 | EPID1 | DstID1 |   53 |    TCP   | www.ubuntu.com | Rejected | Protocol TCP only allows "sub.ubuntu.com"                      |
	// |    3 | EPID1 | DstID1 |   53 |    TCP   | sub.ubuntu.com | Allowed  |                                                                |
	// |    4 | EPID1 | DstID1 |   53 |    UDP   | sub.ubuntu.com | Allowed  |                                                                |
	// |    5 | EPID1 | DstID1 |   54 |    UDP   | cilium.io      | Rejected | Port 54 only allows example.com                                |
	// |    6 | EPID1 | DstID2 |   53 |    UDP   | cilium.io      | Allowed  |                                                                |
	// |    7 | EPID1 | DstID2 |   53 |    UDP   | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2                          |
	// |    8 | EPID1 | DstID1 |   54 |    UDP   | example.com    | Allowed  |                                                                |
	// |    9 | EPID2 | DstID1 |   53 |    UDP   | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy                 |
	// |   10 | EPID3 | DstID1 |   53 |    UDP   | example.com    | Allowed  |                                                                |
	// |   11 | EPID3 | DstID1 |   53 |    UDP   | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |   12 | EPID3 | DstID1 |   54 |    UDP   | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |   13 | EPID3 | DstID2 |   53 |    UDP   | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |   14 | EPID3 | DstID3 |   53 |    UDP   | example.com    | Allowed  | Allowed due to wildcard match pattern                          |
	// |   15 | EPID3 | DstID3 |   53 |    TCP   | example.com    | Allowed  |                                                                |
	// |   16 | EPID3 | DstID3 |   53 |    TCP   | amazon.com     | Rejected | TCP protocol only allows "example.com"                         |
	// |   17 | EPID3 | DstID4 |   53 |    TCP   | example.com    | Rejected | "example.com" only allowed for DstID3                          |
	// |   18 | EPID3 | DstID4 |   53 |    UDP   | example.com    | Allowed  | Allowed due to a nil rule                                      |
	// +------+-------+--------+------+----------------+----------+----------+----------------------------------------------------------------+

	// Setup rules
	//	| EP1  | DstID1 |      53 |  UDP  | *.ubuntu.com   |
	//	| EP1  | DstID1 |      53 |  UDP  | aws.amazon.com |
	//	| EP1  | DstID2 |      53 |  UDP  | cilium.io      |
	_, err := s.proxy.UpdateAllowed(epID1, udpProtoPort53, policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "*.ubuntu.com."},
					{MatchPattern: "aws.amazon.com."},
				},
			},
		},
		cachedDstID2Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "cilium.io."},
				},
			},
		},
	})
	require.NoError(t, err, "Could not update with port 53 rules")

	//      | EP1  | DstID1 |      53 |  TCP  | sub.ubuntu.com |
	_, err = s.proxy.UpdateAllowed(epID1, tcpProtoPort53, policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "sub.ubuntu.com."},
				},
			},
		},
	})
	require.NoError(t, err, "Could not update with rules")

	//	| EP1  | DstID1 |      54 |  UDP  | example.com    |
	_, err = s.proxy.UpdateAllowed(epID1, udpProtoPort54, policy.L7DataMap{
		cachedWildcardSelector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com."},
				},
			},
		},
	})
	require.NoError(t, err, "Could not update with rules")

	// | EP3  | DstID1 |      53 |  UDP  | example.com    |
	// | EP3  | DstID3 |      53 |  UDP  | *              |
	// | EP3  | DstID4 |      53 |  UDP  | nil            |
	_, err = s.proxy.UpdateAllowed(epID3, udpProtoPort53, policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com."},
				},
			},
		},
		cachedDstID3Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "*"},
				},
			},
		},
		cachedDstID4Selector: nil,
	})
	require.NoError(t, err, "Could not update with rules")

	// | EP3  | DstID3 |      53 |  TCP  | example.com    |
	_, err = s.proxy.UpdateAllowed(epID3, tcpProtoPort53, policy.L7DataMap{
		cachedDstID3Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com"},
				},
			},
		},
	})
	require.NoError(t, err, "Could not update with rules")

	// Test cases
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Allowed
	allowed, err := s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, netip.Addr{}, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | DstID1 |   53 |    TCP   | www.ubuntu.com | Rejected | Protocol TCP only allows "sub.ubuntu.com"
	allowed, err = s.proxy.CheckAllowed(epID1, tcpProtoPort53, dstID1, netip.Addr{}, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID1 |   53 |    TCP   | sub.ubuntu.com | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, tcpProtoPort53, dstID1, netip.Addr{}, "sub.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | DstID1 |   53 |    UDP   | sub.ubuntu.com | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, netip.Addr{}, "sub.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, netip.Addr{}, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 6 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, netip.Addr{}, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 7 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, netip.Addr{}, "aws.amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 8 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 9 | EPID2 | DstID1 |   53 |  UDP  | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy
	allowed, err = s.proxy.CheckAllowed(epID2, udpProtoPort53, dstID1, netip.Addr{}, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 10 | EPID3 | DstID1 |   53 |  UDP  | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID1, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 11 | EPID3 | DstID1 |   53 |  UDP  | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID1, netip.Addr{}, "aws.amazon.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 12 | EPID3 | DstID1 |   54 |  UDP  | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort54, dstID1, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 13 | EPID3 | DstID2 |   53 |  UDP  | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID2, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 14 | EPID3 | DstID3 |   53 |  UDP  | example.com    | Allowed due to wildcard match pattern
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID3, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 15 | EPID3 | DstID3 |   53 |    TCP   | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID3, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 16 | EPID3 | DstID3 |   53 |    TCP   | amazon.com     | Rejected | TCP protocol only allows "example.com"
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID3, netip.Addr{}, "amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 17 | EPID3 | DstID4 |   53 |    TCP   | example.com    | Rejected | "example.com" only allowed for DstID3
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID4, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 18 | EPID3 | DstID4 |   53 |  UDP  | example.com    | Allowed due to a nil rule
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID4, netip.Addr{}, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Get rules for restoration
	expected1 := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID1Selector], makeMapOfRuleIPOrCIDR("::")),
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID2Selector], makeMapOfRuleIPOrCIDR("127.0.0.1", "127.0.0.2")),
		}.Sort(nil),
		udpProtoPort54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort54][cachedWildcardSelector], nil),
		},
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][tcpProtoPort53][cachedDstID1Selector], makeMapOfRuleIPOrCIDR("::")),
		},
	}
	restored1, _ := s.proxy.GetRules(versioned.Latest(), uint16(epID1))
	restored1.Sort(nil)
	require.Equal(t, expected1, restored1)

	expected2 := restore.DNSRules{}
	restored2, _ := s.proxy.GetRules(versioned.Latest(), uint16(epID2))
	restored2.Sort(nil)
	require.Equal(t, expected2, restored2)

	expected3 := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID1Selector], makeMapOfRuleIPOrCIDR("::")),
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID3Selector], makeMapOfRuleIPOrCIDR()),
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID4Selector], makeMapOfRuleIPOrCIDR()),
		}.Sort(nil),
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID3][tcpProtoPort53][cachedDstID3Selector], makeMapOfRuleIPOrCIDR()),
		},
	}
	restored3, _ := s.proxy.GetRules(versioned.Latest(), uint16(epID3))
	restored3.Sort(nil)
	require.Equal(t, expected3, restored3)

	// Test with limited set of allowed IPs
	oldUsed := s.proxy.usedServers
	s.proxy.usedServers = map[netip.Addr]struct{}{netip.MustParseAddr("127.0.0.2"): {}}

	expected1b := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID1Selector], makeMapOfRuleIPOrCIDR()),
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID2Selector], makeMapOfRuleIPOrCIDR("127.0.0.2")),
		}.Sort(nil),
		udpProtoPort54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort54][cachedWildcardSelector], nil),
		},
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][tcpProtoPort53][cachedDstID1Selector], makeMapOfRuleIPOrCIDR()),
		},
	}
	restored1b, _ := s.proxy.GetRules(versioned.Latest(), uint16(epID1))
	restored1b.Sort(nil)
	require.Equal(t, expected1b, restored1b)

	// unlimited again
	s.proxy.usedServers = oldUsed

	s.proxy.UpdateAllowed(epID1, udpProtoPort53, nil)
	s.proxy.UpdateAllowed(epID1, udpProtoPort54, nil)
	s.proxy.UpdateAllowed(epID1, tcpProtoPort53, nil)
	_, exists := s.proxy.allowed[epID1]
	require.False(t, exists)

	_, exists = s.proxy.allowed[epID2]
	require.False(t, exists)

	s.proxy.UpdateAllowed(epID3, udpProtoPort53, nil)
	s.proxy.UpdateAllowed(epID3, tcpProtoPort53, nil)
	_, exists = s.proxy.allowed[epID3]
	require.False(t, exists)

	dstIP1 := (s.dnsServer.Listener.Addr()).(*net.TCPAddr).AddrPort().Addr()
	dstIP2a := netip.MustParseAddr("127.0.0.1")
	dstIP2b := netip.MustParseAddr("127.0.0.2")
	dstIPrandom := netip.MustParseAddr("127.0.0.42")

	// Before restore: all rules removed above, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, dstIP1, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 2 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2a, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 4 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2b, "aws.amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Restore rules
	model := newTestEndpointModel(int(epID1), endpoint.StateReady)
	ep1, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep1.Start(uint16(model.ID))
	t.Cleanup(ep1.Stop)

	ep1.DNSRulesV2 = restored1
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.True(t, exists)

	// Same tests with 2 (WORLD) dstID to make sure it is not used, but with correct destination IP

	// Case 1 | EPID1 | dstIP1 |   53 |  UDP  | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP1, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | dstIP1 |   54 |  UDP  | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | dstIP2a |   53 |  UDP  | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2a, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | dstIP2b |   53 |  UDP  | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2b, "aws.amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | dstIP1 |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 |  UDP  | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIPrandom, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// make sure random destination IP is allowed in a wildcard selector
	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Restore rules for epID3
	modelEP3 := newTestEndpointModel(int(epID3), endpoint.StateReady)
	ep3, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, modelEP3)
	require.NoError(t, err)

	ep3.Start(uint16(modelEP3.ID))
	t.Cleanup(ep3.Stop)

	ep3.DNSRulesV2 = restored3
	s.proxy.RestoreRules(ep3)
	_, exists = s.proxy.restored[epID3]
	require.True(t, exists)

	// Set empty ruleset, check that restored rules were deleted in epID3
	_, err = s.proxy.UpdateAllowed(epID3, udpProtoPort53, nil)
	require.NoError(t, err, "Could not update with rules")

	_, exists = s.proxy.restored[epID3]
	require.False(t, exists)

	// epID1 still has restored rules
	_, exists = s.proxy.restored[epID1]
	require.True(t, exists)

	// Marshal restored rules to JSON
	jsn, err := json.Marshal(s.proxy.restored[epID1])
	require.NoError(t, err, "Could not marshal restored rules to json")

	expected := `
	{
		"` + restore.MakeV2PortProto(53, u8proto.TCP).String() + `":[{
			"Re":"^(?:sub[.]ubuntu[.]com[.])$",
			"IPs":{"::":{}}
		}],
		"` + restore.MakeV2PortProto(53, u8proto.UDP).String() + `":[{
			"Re":"^(?:[-a-zA-Z0-9_]*[.]ubuntu[.]com[.]|aws[.]amazon[.]com[.])$",
			"IPs":{"::":{}}
		},{
			"Re":"^(?:cilium[.]io[.])$",
			"IPs":{"127.0.0.1":{},"127.0.0.2":{}}
		}],
		"` + restore.MakeV2PortProto(54, u8proto.UDP).String() + `":[{
			"Re":"^(?:example[.]com[.])$",
			"IPs":null
		}]
	}`
	pretty := new(bytes.Buffer)
	err = json.Compact(pretty, []byte(expected))
	require.NoError(t, err, "Could not compact expected json")
	require.Equal(t, pretty.String(), string(jsn))

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.False(t, exists)

	// Before restore after marshal: previous restored rules are removed, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, dstIP1, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 2 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2a, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 4 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2b, "aws.amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Rejected
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Restore Unmarshaled rules
	var rules restore.DNSRules
	err = json.Unmarshal(jsn, &rules)
	rules = rules.Sort(nil)
	require.NoError(t, err, "Could not unmarshal restored rules from json")
	require.Equal(t, expected1, rules)

	// Marshal again & compare
	// Marshal restored rules to JSON
	jsn2, err := json.Marshal(rules)
	require.NoError(t, err, "Could not marshal restored rules to json")
	require.Equal(t, pretty.String(), string(jsn2))

	ep1.DNSRulesV2 = rules
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.True(t, exists)

	// After restoration of JSON marshaled/unmarshaled rules

	// Case 1 | EPID1 | dstIP1 |   53 |  UDP  | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP1, "www.ubuntu.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | dstIP1 |   54 |  UDP  | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | dstIP2a |   53 |  UDP  | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2a, "cilium.io")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | dstIP2b |   53 |  UDP  | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2b, "aws.amazon.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | dstIP1 |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 |  UDP  | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIPrandom, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.False(t, allowed, "request was allowed when it should be rejected")

	// make sure random IP is allowed on a wildcard
	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.NoError(t, err, "Error when checking allowed")
	require.True(t, allowed, "request was rejected when it should be allowed")

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.False(t, exists)
}

func TestRestoredEndpoint(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupDNSProxyTestSuite(t)

	// Respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp) because we
	// connect with TCP, and the server only listens on TCP.

	name := "cilium.io."
	pattern := "*.cilium.com."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}, {MatchPattern: pattern}},
			},
		},
	}
	queries := []string{name, strings.ReplaceAll(pattern, "*", "sub")}

	_, err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	for _, query := range queries {
		allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, netip.Addr{}, query)
		require.NoError(t, err, "Error when checking allowed query: %q", query)
		require.True(t, allowed, "request was rejected when it should be allowed for query: %q", query)
	}

	// 1st request
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	// Get restored rules
	restored, _ := s.proxy.GetRules(versioned.Latest(), uint16(epID1))
	restored.Sort(nil)

	// remove rules
	_, err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.NoError(t, err, "Could not remove rules")

	// 2nd request, refused due to no rules
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Empty(t, response.Answer, "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, dns.RcodeRefused, response.Rcode, "DNS request from test client was not rejected when it should be blocked (query: %q)", query)
	}

	// restore rules, set the mock to restoring state
	s.restoring = true
	model := newTestEndpointModel(int(epID1), endpoint.StateReady)
	ep1, err := endpoint.NewEndpointFromChangeModel(t.Context(), nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model)
	require.NoError(t, err)

	ep1.Start(uint16(model.ID))
	t.Cleanup(ep1.Stop)

	ep1.IPv4 = netip.MustParseAddr("127.0.0.1")
	ep1.IPv6 = netip.MustParseAddr("::1")
	ep1.DNSRulesV2 = restored
	s.proxy.RestoreRules(ep1)
	_, exists := s.proxy.restored[epID1]
	require.True(t, exists)

	// 3nd request, answered due to restored Endpoint and rules being found
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}
	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.False(t, exists)

	invalidRePattern := "invalid-re-pattern((*"
	validRePattern := "^this[.]domain[.]com[.]$"

	// extract the port the DNS-server is listening on by looking at the restored rules. The port is non-deterministic
	// since it's listening on :0
	require.Len(t, restored, 1, "GetRules is expected to return rules for one port but returned for %d", len(restored))
	portProto := slices.Collect(maps.Keys(restored))[0]

	// Insert one valid and one invalid pattern and ensure that the valid one works
	// and that the invalid one doesn't interfere with the other rules.
	restored[portProto] = append(restored[portProto],
		restore.IPRule{Re: restore.RuleRegex{Pattern: &invalidRePattern}},
		restore.IPRule{Re: restore.RuleRegex{Pattern: &validRePattern}},
	)
	ep1.DNSRulesV2 = restored
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.True(t, exists)

	// 4nd request, answered due to restored Endpoint and rules being found, including domain matched by new regex
	for _, query := range append(queries, "this.domain.com.") {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Len(t, response.Answer, 1, "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.False(t, exists)

	s.restoring = false
}

func TestProxyRequestContext_IsTimeout(t *testing.T) {
	p := new(ProxyRequestContext)
	p.Err = fmt.Errorf("sample err: %w", context.DeadlineExceeded)
	require.True(t, p.IsTimeout())

	// Assert that failing to wrap the error properly (by using '%w') causes
	// IsTimeout() to return the wrong value.
	//nolint:errorlint
	p.Err = fmt.Errorf("sample err: %s", context.DeadlineExceeded)
	require.False(t, p.IsTimeout())

	p.Err = ErrFailedAcquireSemaphore{}
	require.True(t, p.IsTimeout())
	p.Err = ErrTimedOutAcquireSemaphore{
		gracePeriod: 1 * time.Second,
	}
	require.True(t, p.IsTimeout())
}

func TestExtractMsgDetails(t *testing.T) {
	testCases := []struct {
		msg     *dns.Msg
		ttl     uint32
		cnames  []string
		wantErr bool
	}{
		// Invalid DNS message
		{
			msg:     &dns.Msg{},
			ttl:     0,
			cnames:  nil,
			wantErr: true,
		},
		// A response, no CNAMEs
		{
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response: true,
				},
				Question: []dns.Question{{
					Name: fqdndns.FQDN("cilium.io"),
				}},
				Answer: []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name: fqdndns.FQDN("cilium.io"),
						Ttl:  3600,
					},
					A: net.ParseIP("192.0.2.3"),
				}},
			},
			ttl:     3600,
			cnames:  nil,
			wantErr: false,
		},
		// AAAA response, no CNAMEs, min TTL
		{
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response: true,
				},
				Question: []dns.Question{{
					Name: fqdndns.FQDN("cilium.io"),
				}},
				Answer: []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("cilium.io"),
							Ttl:  3600,
						},
						AAAA: net.ParseIP("f00d::1"),
					},
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("cilium.io"),
							Ttl:  1800,
						},
						AAAA: net.ParseIP("f00d::2"),
					},
				},
			},
			ttl:     1800,
			cnames:  nil,
			wantErr: false,
		},
		// A & CNAME (1 level) response, min TTL
		{
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response: true,
				},
				Question: []dns.Question{{
					Name: fqdndns.FQDN("foo.cilium.io"),
				}},
				Answer: []dns.RR{
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("foo.cilium.io"),
							Ttl:  1800,
						},
						Target: fqdndns.FQDN("bar.cilium.io"),
					},
					&dns.A{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("bar.cilium.io"),
							Ttl:  3600,
						},
						A: net.ParseIP("192.168.0.2"),
					},
				},
			},
			ttl:     1800,
			cnames:  []string{"bar.cilium.io."},
			wantErr: false,
		},
		// AAAA & CNAME (3 levels) response, min TTL
		{
			msg: &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response: true,
				},
				Question: []dns.Question{{
					Name: fqdndns.FQDN("foo.cilium.io"),
				}},
				Answer: []dns.RR{
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("foo.cilium.io"),
							Ttl:  7200,
						},
						Target: fqdndns.FQDN("foo1.cilium.io"),
					},
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("foo1.cilium.io"),
							Ttl:  3600,
						},
						Target: fqdndns.FQDN("foo2.cilium.io"),
					},
					&dns.CNAME{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("foo2.cilium.io"),
							Ttl:  7200,
						},
						Target: fqdndns.FQDN("foo3.cilium.io"),
					},
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name: fqdndns.FQDN("foo3.cilium.io"),
							Ttl:  7200,
						},
						AAAA: net.ParseIP("f00d::1"),
					},
				},
			},
			ttl:     3600,
			cnames:  []string{"foo1.cilium.io.", "foo2.cilium.io.", "foo3.cilium.io."},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		_, _, ttl, cnames, _, _, _, err := ExtractMsgDetails(tc.msg)
		if tc.wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

		require.Equal(t, tc.ttl, ttl)
		require.Equal(t, tc.cnames, cnames)
	}
}

type selectorMock struct {
	key string
}

func (t selectorMock) GetSelections(*versioned.VersionHandle) identity.NumericIdentitySlice {
	panic("implement me")
}

func (t selectorMock) GetMetadataLabels() labels.LabelArray {
	panic("implement me")
}

func (t selectorMock) Selects(*versioned.VersionHandle, identity.NumericIdentity) bool {
	panic("implement me")
}

func (t selectorMock) IsWildcard() bool {
	panic("implement me")
}

func (t selectorMock) IsNone() bool {
	panic("implement me")
}

func (t selectorMock) String() string {
	return t.key
}

func Benchmark_perEPAllow_setPortRulesForID(b *testing.B) {
	const (
		nEPs              = 10000
		nEPsAtOnce        = 60
		nMatchPatterns    = 30
		nMatchNames       = 600
		everyNIsEqual     = 10
		everyNHasWildcard = 20
	)
	runtime.GC()
	initialHeap := getMemStats().HeapInuse
	rulesPerEP := make([]policy.L7DataMap, 0, nEPs)

	var defaultRules []api.PortRuleDNS
	for i := range nMatchPatterns {
		defaultRules = append(defaultRules, api.PortRuleDNS{MatchPattern: "*.bar" + strconv.Itoa(i) + "another.very.long.domain.here"})
	}
	for i := range nMatchNames {
		defaultRules = append(defaultRules, api.PortRuleDNS{MatchName: strconv.Itoa(i) + "very.long.domain.containing.a.lot.of.chars"})
	}

	for i := range nEPs {
		commonRules := slices.Clone(defaultRules)
		if i%everyNIsEqual != 0 {
			commonRules = append(
				commonRules,
				api.PortRuleDNS{MatchName: "custom-for-this-one" + strconv.Itoa(i) + ".domain.tld"},
				api.PortRuleDNS{MatchPattern: "custom2-for-this-one*" + strconv.Itoa(i) + ".domain.tld"},
			)
		}
		if (i+1)%everyNHasWildcard == 0 {
			commonRules = append(commonRules, api.PortRuleDNS{MatchPattern: "*"})
		}
		psp := &policy.PerSelectorPolicy{L7Rules: api.L7Rules{DNS: commonRules}}
		rulesPerEP = append(rulesPerEP, policy.L7DataMap{new(selectorMock): psp, new(selectorMock): psp})
	}

	pea := perEPAllow{}
	c := regexCache{}
	b.ReportAllocs()

	for b.Loop() {
		for epID := uint64(0); epID < nEPs; epID++ {
			pea.setPortRulesForID(c, epID, udpProtoPort8053, nil)
		}
		b.StartTimer()
		for epID, rules := range rulesPerEP {
			if epID >= nEPsAtOnce {
				pea.setPortRulesForID(c, uint64(epID)-nEPsAtOnce, udpProtoPort8053, nil)
			}
			pea.setPortRulesForID(c, uint64(epID), udpProtoPort8053, rules)
		}
		b.StopTimer()
	}
	runtime.GC()
	// This is a ~proxy metric for the growth of heap per b.N. We call it here instead of the loop to
	// ensure we also count things like the strings "borrowed" from rulesPerEP
	b.ReportMetric(float64(getMemStats().HeapInuse-initialHeap), "B(HeapInUse)/op")

	for epID := uint64(0); epID < nEPs; epID++ {
		pea.setPortRulesForID(c, epID, udpProtoPort8053, nil)
	}
	if len(pea) > 0 {
		b.Fail()
	}
	b.StopTimer()
	// Remove all the inserted rules to ensure the cache goes down to zero entries
	for epID := uint64(0); epID < 20; epID++ {
		pea.setPortRulesForID(c, epID, udpProtoPort8053, nil)
	}
	if len(pea) > 0 || len(c) > 0 {
		b.Fail()
	}
}

func Benchmark_perEPAllow_setPortRulesForID_large(b *testing.B) {
	b.Skip()
	numEPs := uint64(20)
	cnpFile := "testdata/cnps-large.yaml"

	runtime.GC()
	m := getMemStats()
	fmt.Printf("Before Setup (N=%v,EPs=%d)\n", b.N, numEPs)

	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tHeapInuse = %v MiB", bToMb(m.HeapInuse))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)

	bb, err := os.ReadFile(cnpFile)
	if err != nil {
		b.Fatal(err)
	}
	var cnpList v2.CiliumNetworkPolicyList
	if err := yaml.Unmarshal(bb, &cnpList); err != nil {
		b.Fatal(err)
	}

	rules := policy.L7DataMap{}

	addEgress := func(e []api.EgressRule) {
		var portRuleDNS []api.PortRuleDNS
		for _, egress := range e {
			if egress.ToPorts != nil {
				for _, ports := range egress.ToPorts {
					if ports.Rules != nil {
						for _, dns := range ports.Rules.DNS {
							if len(dns.MatchPattern) > 0 {
								portRuleDNS = append(portRuleDNS, api.PortRuleDNS{
									MatchPattern: dns.MatchPattern,
								})
							}
							if len(dns.MatchName) > 0 {
								portRuleDNS = append(portRuleDNS, api.PortRuleDNS{
									MatchName: dns.MatchName,
								})
							}
						}
					}
				}
			}
		}
		rules[new(selectorMock)] = &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: portRuleDNS,
			},
		}
	}

	for _, cnp := range cnpList.Items {
		if cnp.Specs != nil {
			for _, spec := range cnp.Specs {
				if spec.Egress != nil {
					addEgress(spec.Egress)
				}
			}
		}
		if cnp.Spec != nil {
			if cnp.Spec.Egress != nil {
				addEgress(cnp.Spec.Egress)
			}
		}
	}

	runtime.GC()
	m = getMemStats()
	fmt.Printf("Before Test (N=%v,EPs=%d)\n", b.N, numEPs)

	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tHeapInuse = %v MiB", bToMb(m.HeapInuse))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)

	pea := perEPAllow{}
	c := regexCache{}
	b.ReportAllocs()

	for b.Loop() {
		for epID := uint64(0); epID < numEPs; epID++ {
			pea.setPortRulesForID(c, epID, udpProtoPort8053, rules)
		}
	}
	b.StopTimer()

	// Uncomment to see the HeapInUse from only the regexp cache
	// for epID := uint64(0); epID < numEPs; epID++ {
	//	 pea.setPortRulesForID(epID, udpProtoPort8053, nil)
	// }

	// Explicitly run gc to ensure we measure what we want
	runtime.GC()
	m = getMemStats()
	// Explicitly keep a reference to "pea" to keep it on the heap
	// so that we can measure it before it is garbage collected.
	fmt.Printf("After Test (N=%v,EPs=%d)\n", b.N, len(pea))
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tHeapInuse = %v MiB", bToMb(m.HeapInuse))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
	// Remove all the inserted rules to ensure both indexes go to zero entries
	for epID := uint64(0); epID < numEPs; epID++ {
		pea.setPortRulesForID(c, epID, udpProtoPort8053, nil)
	}
	if len(pea) > 0 || len(c) > 0 {
		b.Fail()
	}
}

func getMemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func newTestEndpointModel(id int, state endpoint.State) *models.EndpointChangeRequest {
	return &models.EndpointChangeRequest{
		ID:    int64(id),
		State: ptr.To(models.EndpointState(state)),
		Properties: map[string]interface{}{
			endpoint.PropertyFakeEndpoint: true,
		},
	}
}
