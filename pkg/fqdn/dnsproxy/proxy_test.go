// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"sigs.k8s.io/yaml"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/u8proto"
)

type DNSProxyTestSuite struct {
	repo         *policy.Repository
	dnsTCPClient *dns.Client
	dnsServer    *dns.Server
	proxy        *DNSProxy
	restoring    bool
}

func setupDNSProxyTestSuite(tb testing.TB) *DNSProxyTestSuite {
	testutils.PrivilegedTest(tb)

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

	s.repo = policy.NewPolicyRepository(nil, nil, nil, nil)
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: time.Second, SingleInflight: true}
	s.dnsServer = setupServer(tb)
	require.NotNil(tb, s.dnsServer, "unable to setup DNS server")
	dnsProxyConfig := DNSProxyConfig{
		Address:                "",
		Port:                   0,
		IPv4:                   true,
		IPv6:                   true,
		EnableDNSCompression:   true,
		MaxRestoreDNSIPs:       1000,
		ConcurrencyLimit:       0,
		ConcurrencyGracePeriod: 0,
	}
	proxy, err := StartDNSProxy(dnsProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
		// LookupEPByIP
		func(ip netip.Addr) (*endpoint.Endpoint, error) {
			if s.restoring {
				return nil, fmt.Errorf("No EPs available when restoring")
			}
			return endpoint.NewTestEndpointWithState(tb, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady), nil
		},
		// LookupSecIDByIP
		func(ip netip.Addr) (ipcache.Identity, bool) {
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
		},
		// LookupIPsBySecID
		func(nid identity.NumericIdentity) []string {
			DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
			switch nid {
			case dstID1:
				return []string{DNSServerListenerAddr.IP.String()}
			case dstID2:
				return []string{"127.0.0.1", "127.0.0.2"}
			default:
				return nil
			}
		},
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, dstAddr string, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error {
			return nil
		},
	)
	require.Nil(tb, err, "error starting DNS Proxy")
	s.proxy = proxy

	// This is here because Listener or Listeer.Addr() was nil. The
	// lookupTargetDNSServer function doesn't need to change the target.
	require.NotNil(tb, s.dnsServer.Listener, "DNS server missing a Listener")
	DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
	require.NotNil(tb, DNSServerListenerAddr, "DNS server missing a Listener address")
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (serverIP net.IP, serverPortProto restore.PortProto, addrStr string, err error) {
		return DNSServerListenerAddr.IP, restore.MakeV2PortProto(uint16(DNSServerListenerAddr.Port), uint8(u8proto.UDP)), DNSServerListenerAddr.String(), nil
	}
	dstPortProto = restore.MakeV2PortProto(uint16(DNSServerListenerAddr.Port), udpProto)

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
		s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
		s.dnsServer.Listener.Close()
		for _, s := range s.proxy.DNSServers {
			s.Shutdown()
		}
	})

	return s
}

func (s *DNSProxyTestSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *DNSProxyTestSuite) GetProxyPort(string) (uint16, error) {
	return 0, nil
}

func (s *DNSProxyTestSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *DNSProxyTestSuite) GetCompilationLock() datapath.CompilationLock {
	return nil
}

func (s *DNSProxyTestSuite) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

func (s *DNSProxyTestSuite) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s *DNSProxyTestSuite) Datapath() datapath.Datapath {
	return nil
}

func (s *DNSProxyTestSuite) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *DNSProxyTestSuite) RemoveRestoredDNSRules(epID uint16) {}

func (s *DNSProxyTestSuite) AddIdentity(id *identity.Identity)                   {}
func (s *DNSProxyTestSuite) RemoveIdentity(id *identity.Identity)                {}
func (s *DNSProxyTestSuite) RemoveOldAddNewIdentity(old, new *identity.Identity) {}

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

type DummySelectorCacheUser struct{}

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, added, deleted []identity.NumericIdentity) {
}

// Setup identities, ports and endpoint IDs we will need
var (
	cacheAllocator          = cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	testSelectorCache       = policy.NewSelectorCache(cacheAllocator.GetIdentityCache())
	dummySelectorCacheUser  = &DummySelectorCacheUser{}
	DstID1Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst1=test"))
	cachedDstID1Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, DstID1Selector)
	DstID2Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst2=test"))
	cachedDstID2Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, DstID2Selector)
	DstID3Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst3=test"))
	cachedDstID3Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, DstID3Selector)
	DstID4Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst4=test"))
	cachedDstID4Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, DstID4Selector)

	cachedWildcardSelector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, api.WildcardEndpointSelector)

	epID1            = uint64(111)
	epID2            = uint64(222)
	epID3            = uint64(333)
	dstID1           = identity.NumericIdentity(1001)
	dstID2           = identity.NumericIdentity(2002)
	dstID3           = identity.NumericIdentity(3003)
	dstID4           = identity.NumericIdentity(4004)
	dstPortProto     = restore.MakeV2PortProto(53, udpProto) // Set below when we setup the server!
	udpProtoPort53   = dstPortProto
	udpProtoPort54   = restore.MakeV2PortProto(54, udpProto)
	udpProtoPort8053 = restore.MakeV2PortProto(8053, udpProto)
	tcpProtoPort53   = restore.MakeV2PortProto(53, tcpProto)
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
	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID2, dstPortProto, dstID1, nil, query)
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
	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.NoError(t, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
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
	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")
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
	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was not rejected when it should be blocked")
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

	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was not rejected when it should be blocked")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	return request
}

func TestRejectNonMatchingRefusedResponseWithNameError(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	request := s.requestRejectNonMatchingRefusedResponse(t)

	// reject a query with NXDomain
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithNameError)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, dns.RcodeNameError, response.Rcode, "DNS request from test client was not rejected when it should be blocked")
}

func TestRejectNonMatchingRefusedResponseWithRefused(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	request := s.requestRejectNonMatchingRefusedResponse(t)

	// reject a query with Refused
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, dns.RcodeRefused, response.Rcode, "DNS request from test client was not rejected when it should be blocked")
}

func TestRespondViaCorrectProtocol(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	// Respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp) because we
	// connet with TCP, and the server only listens on TCP.

	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := name

	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v)", rtt)
	require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s", response)
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

	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s", response)
	require.Equal(t, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")

	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err = s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	require.NoError(t, err, "DNS request from test client failed when it should succeed")
	require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %+v", response.Answer)
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

	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Error when inserting rules")

	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")

	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	l7map = policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{},
			},
		},
	}
	err = s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Error when inserting rules")

	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")
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
	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	err = s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Delete once, it should reject
	err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Delete once, it should reject and not crash
	err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.Equal(t, nil, err, "Could not update with rules")
	allowed, err = s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")
}

func TestFullPathDependence(t *testing.T) {
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
	err := s.proxy.UpdateAllowed(epID1, udpProtoPort53, policy.L7DataMap{
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
	require.Equal(t, nil, err, "Could not update with port 53 rules")

	//      | EP1  | DstID1 |      53 |  TCP  | sub.ubuntu.com |
	err = s.proxy.UpdateAllowed(epID1, tcpProtoPort53, policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "sub.ubuntu.com."},
				},
			},
		},
	})
	require.Equal(t, nil, err, "Could not update with rules")

	//	| EP1  | DstID1 |      54 |  UDP  | example.com    |
	err = s.proxy.UpdateAllowed(epID1, udpProtoPort54, policy.L7DataMap{
		cachedWildcardSelector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com."},
				},
			},
		},
	})
	require.Equal(t, nil, err, "Could not update with rules")

	// | EP3  | DstID1 |      53 |  UDP  | example.com    |
	// | EP3  | DstID3 |      53 |  UDP  | *              |
	// | EP3  | DstID4 |      53 |  UDP  | nil            |
	err = s.proxy.UpdateAllowed(epID3, udpProtoPort53, policy.L7DataMap{
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
	require.Equal(t, nil, err, "Could not update with rules")

	// | EP3  | DstID3 |      53 |  TCP  | example.com    |
	err = s.proxy.UpdateAllowed(epID3, tcpProtoPort53, policy.L7DataMap{
		cachedDstID3Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com"},
				},
			},
		},
	})
	require.Equal(t, nil, err, "Could not update with rules")

	// Test cases
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Allowed
	allowed, err := s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, nil, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | DstID1 |   53 |    TCP   | www.ubuntu.com | Rejected | Protocol TCP only allows "sub.ubuntu.com"
	allowed, err = s.proxy.CheckAllowed(epID1, tcpProtoPort53, dstID1, nil, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID1 |   53 |    TCP   | sub.ubuntu.com | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, tcpProtoPort53, dstID1, nil, "sub.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | DstID1 |   53 |    UDP   | sub.ubuntu.com | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, nil, "sub.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, nil, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 6 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, nil, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 7 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, nil, "aws.amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 8 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 9 | EPID2 | DstID1 |   53 |  UDP  | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy
	allowed, err = s.proxy.CheckAllowed(epID2, udpProtoPort53, dstID1, nil, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 10 | EPID3 | DstID1 |   53 |  UDP  | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID1, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 11 | EPID3 | DstID1 |   53 |  UDP  | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID1, nil, "aws.amazon.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 12 | EPID3 | DstID1 |   54 |  UDP  | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort54, dstID1, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 13 | EPID3 | DstID2 |   53 |  UDP  | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID2, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 14 | EPID3 | DstID3 |   53 |  UDP  | example.com    | Allowed due to wildcard match pattern
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID3, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 15 | EPID3 | DstID3 |   53 |    TCP   | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID3, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 16 | EPID3 | DstID3 |   53 |    TCP   | amazon.com     | Rejected | TCP protocol only allows "example.com"
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID3, nil, "amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 17 | EPID3 | DstID4 |   53 |    TCP   | example.com    | Rejected | "example.com" only allowed for DstID3
	allowed, err = s.proxy.CheckAllowed(epID3, tcpProtoPort53, dstID4, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 18 | EPID3 | DstID4 |   53 |  UDP  | example.com    | Allowed due to a nil rule
	allowed, err = s.proxy.CheckAllowed(epID3, udpProtoPort53, dstID4, nil, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Get rules for restoration
	expected1 := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID1Selector], map[string]struct{}{"::": {}}),
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID2Selector], map[string]struct{}{"127.0.0.1": {}, "127.0.0.2": {}}),
		}.Sort(nil),
		udpProtoPort54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort54][cachedWildcardSelector], nil),
		},
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][tcpProtoPort53][cachedDstID1Selector], map[string]struct{}{"::": {}}),
		},
	}
	restored1, _ := s.proxy.GetRules(uint16(epID1))
	restored1.Sort(nil)
	require.EqualValues(t, expected1, restored1)

	expected2 := restore.DNSRules{}
	restored2, _ := s.proxy.GetRules(uint16(epID2))
	restored2.Sort(nil)
	require.EqualValues(t, expected2, restored2)

	expected3 := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID1Selector], map[string]struct{}{"::": {}}),
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID3Selector], map[string]struct{}{}),
			asIPRule(s.proxy.allowed[epID3][udpProtoPort53][cachedDstID4Selector], map[string]struct{}{}),
		}.Sort(nil),
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID3][tcpProtoPort53][cachedDstID3Selector], map[string]struct{}{}),
		},
	}
	restored3, _ := s.proxy.GetRules(uint16(epID3))
	restored3.Sort(nil)
	require.EqualValues(t, expected3, restored3)

	// Test with limited set of allowed IPs
	oldUsed := s.proxy.usedServers
	s.proxy.usedServers = map[string]struct{}{"127.0.0.2": {}}

	expected1b := restore.DNSRules{
		udpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID1Selector], map[string]struct{}{}),
			asIPRule(s.proxy.allowed[epID1][udpProtoPort53][cachedDstID2Selector], map[string]struct{}{"127.0.0.2": {}}),
		}.Sort(nil),
		udpProtoPort54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][udpProtoPort54][cachedWildcardSelector], nil),
		},
		tcpProtoPort53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][tcpProtoPort53][cachedDstID1Selector], map[string]struct{}{}),
		},
	}
	restored1b, _ := s.proxy.GetRules(uint16(epID1))
	restored1b.Sort(nil)
	require.EqualValues(t, expected1b, restored1b)

	// unlimited again
	s.proxy.usedServers = oldUsed

	s.proxy.UpdateAllowed(epID1, udpProtoPort53, nil)
	s.proxy.UpdateAllowed(epID1, udpProtoPort54, nil)
	s.proxy.UpdateAllowed(epID1, tcpProtoPort53, nil)
	_, exists := s.proxy.allowed[epID1]
	require.Equal(t, false, exists)

	_, exists = s.proxy.allowed[epID2]
	require.Equal(t, false, exists)

	s.proxy.UpdateAllowed(epID3, udpProtoPort53, nil)
	s.proxy.UpdateAllowed(epID3, tcpProtoPort53, nil)
	_, exists = s.proxy.allowed[epID3]
	require.Equal(t, false, exists)

	dstIP1 := (s.dnsServer.Listener.Addr()).(*net.TCPAddr).IP
	dstIP2a := net.ParseIP("127.0.0.1")
	dstIP2b := net.ParseIP("127.0.0.2")
	dstIPrandom := net.ParseIP("127.0.0.42")

	// Before restore: all rules removed above, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, dstIP1, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 2 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2a, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 4 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2b, "aws.amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Restore rules
	ep1 := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady)
	ep1.DNSRulesV2 = restored1
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, true, exists)

	// Same tests with 2 (WORLD) dstID to make sure it is not used, but with correct destination IP

	// Case 1 | EPID1 | dstIP1 |   53 |  UDP  | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP1, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | dstIP1 |   54 |  UDP  | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | dstIP2a |   53 |  UDP  | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2a, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | dstIP2b |   53 |  UDP  | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2b, "aws.amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | dstIP1 |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 |  UDP  | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIPrandom, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// make sure random destination IP is allowed in a wildcard selector
	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Restore rules for epID3
	ep3 := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID3), endpoint.StateReady)
	ep3.DNSRulesV2 = restored3
	s.proxy.RestoreRules(ep3)
	_, exists = s.proxy.restored[epID3]
	require.Equal(t, true, exists)

	// Set empty ruleset, check that restored rules were deleted in epID3
	err = s.proxy.UpdateAllowed(epID3, udpProtoPort53, nil)
	require.Equal(t, nil, err, "Could not update with rules")

	_, exists = s.proxy.restored[epID3]
	require.Equal(t, false, exists)

	// epID1 still has restored rules
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, true, exists)

	// Marshal restored rules to JSON
	jsn, err := json.Marshal(s.proxy.restored[epID1])
	require.Equal(t, nil, err, "Could not marshal restored rules to json")

	expected := `
	{
		"` + restore.MakeV2PortProto(53, tcpProto).String() + `":[{
			"Re":"^(?:sub[.]ubuntu[.]com[.])$",
			"IPs":{"::":{}}
		}],
		"` + restore.MakeV2PortProto(53, udpProto).String() + `":[{
			"Re":"^(?:[-a-zA-Z0-9_]*[.]ubuntu[.]com[.]|aws[.]amazon[.]com[.])$",
			"IPs":{"::":{}}
		},{
			"Re":"^(?:cilium[.]io[.])$",
			"IPs":{"127.0.0.1":{},"127.0.0.2":{}}
		}],
		"` + restore.MakeV2PortProto(54, udpProto).String() + `":[{
			"Re":"^(?:example[.]com[.])$",
			"IPs":null
		}]
	}`
	pretty := new(bytes.Buffer)
	err = json.Compact(pretty, []byte(expected))
	require.Equal(t, nil, err, "Could not compact expected json")
	require.Equal(t, pretty.String(), string(jsn))

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, false, exists)

	// Before restore after marshal: previous restored rules are removed, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 |  UDP  | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID1, dstIP1, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 2 | EPID1 | DstID1 |   54 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | DstID2 |   53 |  UDP  | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2a, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 4 | EPID1 | DstID2 |   53 |  UDP  | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, dstID2, dstIP2b, "aws.amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | DstID1 |   54 |  UDP  | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, dstID1, dstIP1, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Rejected
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Restore Unmarshaled rules
	var rules restore.DNSRules
	err = json.Unmarshal(jsn, &rules)
	rules = rules.Sort(nil)
	require.Equal(t, nil, err, "Could not unmarshal restored rules from json")
	require.EqualValues(t, expected1, rules)

	// Marshal again & compare
	// Marshal restored rules to JSON
	jsn2, err := json.Marshal(rules)
	require.Equal(t, nil, err, "Could not marshal restored rules to json")
	require.Equal(t, pretty.String(), string(jsn2))

	ep1.DNSRulesV2 = rules
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, true, exists)

	// After restoration of JSON marshaled/unmarshaled rules

	// Case 1 | EPID1 | dstIP1 |   53 |  UDP  | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP1, "www.ubuntu.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 2 | EPID1 | dstIP1 |   54 |  UDP  | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 3 | EPID1 | dstIP2a |   53 |  UDP  | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2a, "cilium.io")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// Case 4 | EPID1 | dstIP2b |   53 |  UDP  | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIP2b, "aws.amazon.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// Case 5 | EPID1 | dstIP1 |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIP1, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 |  UDP  | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort53, 2, dstIPrandom, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, false, allowed, "request was allowed when it should be rejected")

	// make sure random IP is allowed on a wildcard
	// Case 5 | EPID1 | random IP |   54 |  UDP  | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, udpProtoPort54, 2, dstIPrandom, "example.com")
	require.Equal(t, nil, err, "Error when checking allowed")
	require.Equal(t, true, allowed, "request was rejected when it should be allowed")

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, false, exists)
}

func TestRestoredEndpoint(t *testing.T) {
	s := setupDNSProxyTestSuite(t)

	// Respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp) because we
	// connet with TCP, and the server only listens on TCP.

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

	err := s.proxy.UpdateAllowed(epID1, dstPortProto, l7map)
	require.Equal(t, nil, err, "Could not update with rules")
	for _, query := range queries {
		allowed, err := s.proxy.CheckAllowed(epID1, dstPortProto, dstID1, nil, query)
		require.Equal(t, nil, err, "Error when checking allowed query: %q", query)
		require.Equal(t, true, allowed, "request was rejected when it should be allowed for query: %q", query)
	}

	// 1st request
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	// Get restored rules
	restored, _ := s.proxy.GetRules(uint16(epID1))
	restored.Sort(nil)

	// remove rules
	err = s.proxy.UpdateAllowed(epID1, dstPortProto, nil)
	require.Equal(t, nil, err, "Could not remove rules")

	// 2nd request, refused due to no rules
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Equal(t, 0, len(response.Answer), "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, dns.RcodeRefused, response.Rcode, "DNS request from test client was not rejected when it should be blocked (query: %q)", query)
	}

	// restore rules, set the mock to restoring state
	s.restoring = true
	ep1 := endpoint.NewTestEndpointWithState(t, s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady)
	ep1.IPv4 = netip.MustParseAddr("127.0.0.1")
	ep1.IPv6 = netip.MustParseAddr("::1")
	ep1.DNSRulesV2 = restored
	s.proxy.RestoreRules(ep1)
	_, exists := s.proxy.restored[epID1]
	require.Equal(t, true, exists)

	// 3nd request, answered due to restored Endpoint and rules being found
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}
	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, false, exists)

	invalidRePattern := "invalid-re-pattern((*"
	validRePattern := "^this[.]domain[.]com[.]$"

	// extract the port the DNS-server is listening on by looking at the restored rules. The port is non-deterministic
	// since it's listening on :0
	require.Equal(t, 1, len(restored), "GetRules is expected to return rules for one port but returned for %d", len(restored))
	portProto := maps.Keys(restored)[0]

	// Insert one valid and one invalid pattern and ensure that the valid one works
	// and that the invalid one doesn't interfere with the other rules.
	restored[portProto] = append(restored[portProto],
		restore.IPRule{Re: restore.RuleRegex{Pattern: &invalidRePattern}},
		restore.IPRule{Re: restore.RuleRegex{Pattern: &validRePattern}},
	)
	ep1.DNSRulesV2 = restored
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, true, exists)

	// 4nd request, answered due to restored Endpoint and rules being found, including domain matched by new regex
	for _, query := range append(queries, "this.domain.com.") {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		require.NoErrorf(t, err, "DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query)
		require.Equal(t, 1, len(response.Answer), "Proxy returned incorrect number of answer RRs %s (query: %q)", response, query)
		require.Equal(t, query+"\t60\tIN\tA\t1.1.1.1", response.Answer[0].String(), "Proxy returned incorrect RRs")
	}

	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	require.Equal(t, false, exists)

	s.restoring = false
}

func TestProxyRequestContext_IsTimeout(t *testing.T) {
	p := new(ProxyRequestContext)
	p.Err = fmt.Errorf("sample err: %w", context.DeadlineExceeded)
	require.Equal(t, true, p.IsTimeout())

	// Assert that failing to wrap the error properly (by using '%w') causes
	// IsTimeout() to return the wrong value.
	//nolint:errorlint
	p.Err = fmt.Errorf("sample err: %s", context.DeadlineExceeded)
	require.Equal(t, false, p.IsTimeout())

	p.Err = ErrFailedAcquireSemaphore{}
	require.Equal(t, true, p.IsTimeout())
	p.Err = ErrTimedOutAcquireSemaphore{
		gracePeriod: 1 * time.Second,
	}
	require.Equal(t, true, p.IsTimeout())
}

type selectorMock struct {
	key string
}

func (t selectorMock) GetSelections() identity.NumericIdentitySlice {
	panic("implement me")
}

func (t selectorMock) GetMetadataLabels() labels.LabelArray {
	panic("implement me")
}

func (t selectorMock) Selects(nid identity.NumericIdentity) bool {
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
	for i := 0; i < nMatchPatterns; i++ {
		defaultRules = append(defaultRules, api.PortRuleDNS{MatchPattern: "*.bar" + strconv.Itoa(i) + "another.very.long.domain.here"})
	}
	for i := 0; i < nMatchNames; i++ {
		defaultRules = append(defaultRules, api.PortRuleDNS{MatchName: strconv.Itoa(i) + "very.long.domain.containing.a.lot.of.chars"})
	}

	for i := 0; i < nEPs; i++ {
		commonRules := append([]api.PortRuleDNS{}, defaultRules...)
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
	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
