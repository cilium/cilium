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

	. "github.com/cilium/checkmate"
	"github.com/miekg/dns"
	"golang.org/x/exp/maps"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type DNSProxyTestSuite struct {
	repo         *policy.Repository
	dnsTCPClient *dns.Client
	dnsServer    *dns.Server
	proxy        *DNSProxy
	restoring    bool
}

func (s *DNSProxyTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *DNSProxyTestSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *DNSProxyTestSuite) GetProxyPort(string) (uint16, error) {
	return 0, nil
}

func (s *DNSProxyTestSuite) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s *DNSProxyTestSuite) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s *DNSProxyTestSuite) UpdateNetworkPolicy(e regeneration.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	return nil, nil
}

func (s *DNSProxyTestSuite) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {}

func (s *DNSProxyTestSuite) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *DNSProxyTestSuite) GetCompilationLock() *lock.RWMutex {
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

func (s *DNSProxyTestSuite) RemoveRestoredDNSRules(epID uint16) {
}

var _ = Suite(&DNSProxyTestSuite{})

func setupServer(c *C) (dnsServer *dns.Server) {
	waitOnListen := make(chan struct{})
	dnsServer = &dns.Server{Addr: ":0", Net: "tcp", NotifyStartedFunc: func() { close(waitOnListen) }}
	go dnsServer.ListenAndServe()
	dns.HandleFunc(".", serveDNS)

	select {
	case <-waitOnListen:
		return dnsServer

	case <-time.After(10 * time.Second):
		c.Error("DNS server did not start listening")
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
	fakeAllocator           = testidentity.NewMockIdentityAllocator(cacheAllocator.GetIdentityCache())
	testSelectorCache       = policy.NewSelectorCache(fakeAllocator, cacheAllocator.GetIdentityCache())
	dummySelectorCacheUser  = &DummySelectorCacheUser{}
	DstID1Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst1=test"))
	cachedDstID1Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID1Selector)
	DstID2Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst2=test"))
	cachedDstID2Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID2Selector)
	DstID3Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst3=test"))
	cachedDstID3Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID3Selector)
	DstID4Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst4=test"))
	cachedDstID4Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID4Selector)

	cachedWildcardSelector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, api.WildcardEndpointSelector)

	epID1   = uint64(111)
	epID2   = uint64(222)
	epID3   = uint64(333)
	dstID1  = identity.NumericIdentity(1001)
	dstID2  = identity.NumericIdentity(2002)
	dstID3  = identity.NumericIdentity(3003)
	dstID4  = identity.NumericIdentity(4004)
	dstPort = uint16(53) // Set below when we setup the server!
)

func (s *DNSProxyTestSuite) SetUpTest(c *C) {
	// Add these identities
	wg := &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(cache.IdentityCache{
		dstID1: labels.Labels{"Dst1": labels.NewLabel("Dst1", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID2: labels.Labels{"Dst2": labels.NewLabel("Dst2", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID3: labels.Labels{"Dst3": labels.NewLabel("Dst3", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID4: labels.Labels{"Dst4": labels.NewLabel("Dst4", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil, wg)
	wg.Wait()

	s.repo = policy.NewPolicyRepository(nil, nil, nil, nil)
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: time.Second, SingleInflight: true}
	s.dnsServer = setupServer(c)
	c.Assert(s.dnsServer, Not(IsNil), Commentf("unable to setup DNS server"))

	option.Config.FQDNRegexCompileLRUSize = 1024
	err := re.InitRegexCompileLRU(option.Config.FQDNRegexCompileLRUSize)
	c.Assert(err, IsNil)
	proxy, err := StartDNSProxy("", 0, true, 1000, // any address, any port, enable compression, max 1000 restore IPs
		// LookupEPByIP
		func(ip net.IP) (*endpoint.Endpoint, error) {
			if s.restoring {
				return nil, fmt.Errorf("No EPs available when restoring")
			}
			return endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady), nil
		},
		// LookupSecIDByIP
		func(ip netip.Addr) (ipcache.Identity, bool) {
			DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
			switch {
			case ip.String() == DNSServerListenerAddr.IP.String():
				ident := ipcache.Identity{
					ID:     dstID1,
					Source: source.Unspec}
				return ident, true
			default:
				ident := ipcache.Identity{
					ID:     dstID2,
					Source: source.Unspec}
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
		0, 0,
	)
	c.Assert(err, IsNil, Commentf("error starting DNS Proxy"))
	s.proxy = proxy

	// This is here because Listener or Listeer.Addr() was nil. The
	// lookupTargetDNSServer function doesn't need to change the target.
	c.Assert(s.dnsServer.Listener, Not(IsNil), Commentf("DNS server missing a Listener"))
	DNSServerListenerAddr := (s.dnsServer.Listener.Addr()).(*net.TCPAddr)
	c.Assert(DNSServerListenerAddr, Not(IsNil), Commentf("DNS server missing a Listener address"))
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, addrStr string, err error) {
		return DNSServerListenerAddr.IP, uint16(DNSServerListenerAddr.Port), DNSServerListenerAddr.String(), nil
	}
	dstPort = uint16(DNSServerListenerAddr.Port)
}

func (s *DNSProxyTestSuite) TearDownTest(c *C) {
	for epID := range s.proxy.allowed {
		for port := range s.proxy.allowed[epID] {
			s.proxy.UpdateAllowed(epID, port, nil)
		}
	}
	for epID := range s.proxy.restored {
		s.proxy.RemoveRestoredRules(uint16(epID))
	}
	if len(s.proxy.cache) > 0 {
		c.Error("cache not fully empty after removing all rules. Possible memory leak found.")
	}
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
	s.dnsServer.Listener.Close()
	for _, s := range s.proxy.DNSServers {
		s.Shutdown()
	}
}

func (s *DNSProxyTestSuite) TestRejectFromDifferentEndpoint(c *C) {
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
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID2, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestAcceptFromMatchingEndpoint(c *C) {
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
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))
}

func (s *DNSProxyTestSuite) TestAcceptNonRegex(c *C) {
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
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))
}

func (s *DNSProxyTestSuite) TestRejectNonRegex(c *C) {
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
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) requestRejectNonMatchingRefusedResponse(c *C) *dns.Msg {
	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{MatchName: name}},
			},
		},
	}
	query := "notcilium.io."

	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was not rejected when it should be blocked"))

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	return request
}

func (s *DNSProxyTestSuite) TestRejectNonMatchingRefusedResponseWithNameError(c *C) {
	request := s.requestRejectNonMatchingRefusedResponse(c)

	// reject a query with NXDomain
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithNameError)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(response.Rcode, Equals, dns.RcodeNameError, Commentf("DNS request from test client was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestRejectNonMatchingRefusedResponseWithRefused(c *C) {
	request := s.requestRejectNonMatchingRefusedResponse(c)

	// reject a query with Refused
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(response.Rcode, Equals, dns.RcodeRefused, Commentf("DNS request from test client was not rejected when it should be blocked"))

}

func (s *DNSProxyTestSuite) TestRespondViaCorrectProtocol(c *C) {
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

	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v)", rtt))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s", response))
	c.Assert(response.Answer[0].String(), Equals, "cilium.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))

}

func (s *DNSProxyTestSuite) TestRespondMixedCaseInRequestResponse(c *C) {
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

	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s", response))
	c.Assert(response.Answer[0].String(), Equals, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))

	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err = s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %+v", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "ciliuM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}
func (s *DNSProxyTestSuite) TestCheckNoRules(c *C) {
	name := "cilium.io."
	l7map := policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{},
		},
	}
	query := name

	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Error when inserting rules"))

	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))

	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	l7map = policy.L7DataMap{
		cachedDstID1Selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{},
			},
		},
	}
	err = s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Error when inserting rules"))

	allowed, err = s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedTwiceRemovedOnce(c *C) {
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
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	err = s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Delete once, it should reject
	err = s.proxy.UpdateAllowed(epID1, dstPort, nil)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err = s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Delete once, it should reject and not crash
	err = s.proxy.UpdateAllowed(epID1, dstPort, nil)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err = s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))
}

func (s *DNSProxyTestSuite) TestFullPathDependence(c *C) {
	// Test that we consider each of endpoint ID, destination SecID (via the
	// selector in L7DataMap), destination port (set in the redirect itself) and
	// the DNS name.
	// The rules approximate:
	// +------+--------+---------+----------------+
	// | From |   To   | DstPort |    DNSNames    |
	// +======+========+=========+================+
	// | EP1  | DstID1 |      53 | *.ubuntu.com   |
	// | EP1  | DstID1 |      53 | aws.amazon.com |
	// | EP1  | DstID2 |      53 | cilium.io      |
	// | EP1  | *      |      54 | example.com    |
	// | EP3  | DstID1 |      53 | example.com    |
	// | EP3  | DstID3 |      53 | *              |
	// | EP3  | DstID4 |      53 | nil            |
	// +------+--------+---------+----------------+
	//
	// Cases:
	// +------+-------+--------+------+----------------+----------+----------------------------------------------------------------+
	// | Case | From  |   To   | Port |     Query      | Outcome  |                             Reason                             |
	// +------+-------+--------+------+----------------+----------+----------------------------------------------------------------+
	// |    1 | EPID1 | DstID1 |   53 | www.ubuntu.com | Allowed  |                                                                |
	// |    2 | EPID1 | DstID1 |   54 | cilium.io      | Rejected | Port 54 only allows example.com                                |
	// |    3 | EPID1 | DstID2 |   53 | cilium.io      | Allowed  |                                                                |
	// |    4 | EPID1 | DstID2 |   53 | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2                          |
	// |    5 | EPID1 | DstID1 |   54 | example.com    | Allowed  |                                                                |
	// |    6 | EPID2 | DstID1 |   53 | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy                 |
	// |    7 | EPID3 | DstID1 |   53 | example.com    | Allowed  |                                                                |
	// |    8 | EPID3 | DstID1 |   53 | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |    8 | EPID3 | DstID1 |   54 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |    9 | EPID3 | DstID2 |   53 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com |
	// |   10 | EPID3 | DstID3 |   53 | example.com    | Allowed  | Allowed due to wildcard match pattern                          |
	// |   11 | EPID3 | DstID4 |   53 | example.com    | Allowed  | Allowed due to a nil rule                                      |
	// +------+-------+--------+------+----------------+----------+----------------------------------------------------------------+

	// Setup rules
	//	| EP1  | DstID1 |      53 | *.ubuntu.com   |
	//	| EP1  | DstID1 |      53 | aws.amazon.com |
	//	| EP1  | DstID2 |      53 | cilium.io      |
	err := s.proxy.UpdateAllowed(epID1, 53, policy.L7DataMap{
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
	c.Assert(err, Equals, nil, Commentf("Could not update with port 53 rules"))

	//	| EP1  | DstID1 |      54 | example.com    |
	err = s.proxy.UpdateAllowed(epID1, 54, policy.L7DataMap{
		cachedWildcardSelector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{MatchPattern: "example.com."},
				},
			},
		},
	})
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))

	// | EP3  | DstID1 |      53 | example.com    |
	// | EP3  | DstID3 |      53 | *              |
	// | EP3  | DstID4 |      53 | nil            |
	err = s.proxy.UpdateAllowed(epID3, 53, policy.L7DataMap{
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
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))

	// Test cases
	// Case 1 | EPID1 | DstID1 |   53 | www.ubuntu.com | Allowed
	allowed, err := s.proxy.CheckAllowed(epID1, 53, dstID1, nil, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 2 | EPID1 | DstID1 |   54 | cilium.io      | Rejected | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, nil, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | DstID2 |   53 | cilium.io      | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, nil, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 4 | EPID1 | DstID2 |   53 | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, nil, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | DstID1 |   54 | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 6 | EPID2 | DstID1 |   53 | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy
	allowed, err = s.proxy.CheckAllowed(epID2, 53, dstID1, nil, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 7 | EPID3 | DstID1 |   53 | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID1, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 8 | EPID3 | DstID1 |   53 | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID1, nil, "aws.amazon.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 8 | EPID3 | DstID1 |   54 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 54, dstID1, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 9 | EPID3 | DstID2 |   53 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID2, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 10 | EPID3 | DstID3 |   53 | example.com    | Allowed due to wildcard match pattern
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID3, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 11 | EPID3 | DstID4 |   53 | example.com    | Allowed due to a nil rule
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID4, nil, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Get rules for restoration
	expected1 := restore.DNSRules{
		53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][53][cachedDstID1Selector], map[string]struct{}{"::": {}}),
			asIPRule(s.proxy.allowed[epID1][53][cachedDstID2Selector], map[string]struct{}{"127.0.0.1": {}, "127.0.0.2": {}}),
		}.Sort(),
		54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][54][cachedWildcardSelector], nil),
		},
	}
	restored1, _ := s.proxy.GetRules(uint16(epID1))
	restored1.Sort()
	c.Assert(restored1, checker.DeepEquals, expected1)

	expected2 := restore.DNSRules{}
	restored2, _ := s.proxy.GetRules(uint16(epID2))
	restored2.Sort()
	c.Assert(restored2, checker.DeepEquals, expected2)

	expected3 := restore.DNSRules{
		53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID3][53][cachedDstID1Selector], map[string]struct{}{"::": {}}),
			asIPRule(s.proxy.allowed[epID3][53][cachedDstID3Selector], map[string]struct{}{}),
			asIPRule(s.proxy.allowed[epID3][53][cachedDstID4Selector], map[string]struct{}{}),
		}.Sort(),
	}
	restored3, _ := s.proxy.GetRules(uint16(epID3))
	restored3.Sort()
	c.Assert(restored3, checker.DeepEquals, expected3)

	// Test with limited set of allowed IPs
	oldUsed := s.proxy.usedServers
	s.proxy.usedServers = map[string]struct{}{"127.0.0.2": {}}

	expected1b := restore.DNSRules{
		53: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][53][cachedDstID1Selector], map[string]struct{}{}),
			asIPRule(s.proxy.allowed[epID1][53][cachedDstID2Selector], map[string]struct{}{"127.0.0.2": {}}),
		}.Sort(),
		54: restore.IPRules{
			asIPRule(s.proxy.allowed[epID1][54][cachedWildcardSelector], nil),
		},
	}
	restored1b, _ := s.proxy.GetRules(uint16(epID1))
	restored1b.Sort()
	c.Assert(restored1b, checker.DeepEquals, expected1b)

	// unlimited again
	s.proxy.usedServers = oldUsed

	s.proxy.UpdateAllowed(epID1, 53, nil)
	s.proxy.UpdateAllowed(epID1, 54, nil)
	_, exists := s.proxy.allowed[epID1]
	c.Assert(exists, Equals, false)

	_, exists = s.proxy.allowed[epID2]
	c.Assert(exists, Equals, false)

	s.proxy.UpdateAllowed(epID3, 53, nil)
	_, exists = s.proxy.allowed[epID3]
	c.Assert(exists, Equals, false)

	dstIP1 := (s.dnsServer.Listener.Addr()).(*net.TCPAddr).IP
	dstIP2a := net.ParseIP("127.0.0.1")
	dstIP2b := net.ParseIP("127.0.0.2")
	dstIPrandom := net.ParseIP("127.0.0.42")

	// Before restore: all rules removed above, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID1, dstIP1, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 2 | EPID1 | DstID1 |   54 | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, dstIP1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | DstID2 |   53 | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, dstIP2a, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 4 | EPID1 | DstID2 |   53 | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, dstIP2b, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | DstID1 |   54 | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, dstIP1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Restore rules
	ep1 := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady)
	ep1.DNSRules = restored1
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, true)

	// Same tests with 2 (WORLD) dstID to make sure it is not used, but with correct destination IP

	// Case 1 | EPID1 | dstIP1 |   53 | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP1, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 2 | EPID1 | dstIP1 |   54 | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIP1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | dstIP2a |   53 | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP2a, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 4 | EPID1 | dstIP2b |   53 | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP2b, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | dstIP1 |   54 | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIP1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIPrandom, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// make sure random destination IP is allowed in a wildcard selector
	// Case 5 | EPID1 | random IP |   54 | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIPrandom, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Restore rules for epID3
	ep3 := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID3), endpoint.StateReady)
	ep3.DNSRules = restored3
	s.proxy.RestoreRules(ep3)
	_, exists = s.proxy.restored[epID3]
	c.Assert(exists, Equals, true)

	// Set empty ruleset, check that restored rules were deleted in epID3
	err = s.proxy.UpdateAllowed(epID3, 53, nil)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))

	_, exists = s.proxy.restored[epID3]
	c.Assert(exists, Equals, false)

	// epID1 still has restored rules
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, true)

	// Marshal restored rules to JSON
	jsn, err := json.Marshal(s.proxy.restored[epID1])
	c.Assert(err, Equals, nil, Commentf("Could not marshal restored rules to json"))

	expected := `
	{
		"53": [{
			"Re":  "^(?:[-a-zA-Z0-9_]*[.]ubuntu[.]com[.]|aws[.]amazon[.]com[.])$",
			"IPs": {"::": {}}
		}, {
			"Re":  "^(?:cilium[.]io[.])$",
			"IPs": {"127.0.0.1": {}, "127.0.0.2": {}}
		}],
		"54": [{
			"Re":  "^(?:example[.]com[.])$",
			"IPs": null
		}]
	}`
	pretty := new(bytes.Buffer)
	err = json.Compact(pretty, []byte(expected))
	c.Assert(err, Equals, nil, Commentf("Could not compact expected json"))
	c.Assert(string(jsn), Equals, pretty.String())

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, false)

	// Before restore after marshal: previous restored rules are removed, everything is dropped
	// Case 1 | EPID1 | DstID1 |   53 | www.ubuntu.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID1, dstIP1, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 2 | EPID1 | DstID1 |   54 | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, dstIP1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | DstID2 |   53 | cilium.io      | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, dstIP2a, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 4 | EPID1 | DstID2 |   53 | aws.amazon.com | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, dstIP2b, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | DstID1 |   54 | example.com    | Rejected | No rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, dstIP1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | random IP |   54 | example.com    | Rejected
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIPrandom, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Restore Unmarshaled rules
	var rules restore.DNSRules
	err = json.Unmarshal(jsn, &rules)
	rules = rules.Sort()
	c.Assert(err, Equals, nil, Commentf("Could not unmarshal restored rules from json"))
	c.Assert(rules, checker.DeepEquals, expected1)

	// Marshal again & compare
	// Marshal restored rules to JSON
	jsn2, err := json.Marshal(rules)
	c.Assert(err, Equals, nil, Commentf("Could not marshal restored rules to json"))
	c.Assert(string(jsn2), Equals, pretty.String())

	ep1.DNSRules = rules
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, true)

	// After restoration of JSON marshaled/unmarshaled rules

	// Case 1 | EPID1 | dstIP1 |   53 | www.ubuntu.com | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP1, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 2 | EPID1 | dstIP1 |   54 | cilium.io      | Rejected due to restored rules | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIP1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | dstIP2a |   53 | cilium.io      | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP2a, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 4 | EPID1 | dstIP2b |   53 | aws.amazon.com | Rejected due to restored rules | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIP2b, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | dstIP1 |   54 | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIP1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// make sure random IP is not allowed
	// Case 5 | EPID1 | random IP |   53 | example.com    | Rejected due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 53, 2, dstIPrandom, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// make sure random IP is allowed on a wildcard
	// Case 5 | EPID1 | random IP |   54 | example.com    | Allowed due to restored rules
	allowed, err = s.proxy.CheckAllowed(epID1, 54, 2, dstIPrandom, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, false)
}

func (s *DNSProxyTestSuite) TestRestoredEndpoint(c *C) {
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

	c.TestName()
	err := s.proxy.UpdateAllowed(epID1, dstPort, l7map)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	for _, query := range queries {
		allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, nil, query)
		c.Assert(err, Equals, nil, Commentf("Error when checking allowed query: %q", query))
		c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed for query: %q", query))
	}

	// 1st request
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query))
		c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s (query: %q)", response, query))
		c.Assert(response.Answer[0].String(), Equals, query+"\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
	}

	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query))
		c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s (query: %q)", response, query))
		c.Assert(response.Answer[0].String(), Equals, query+"\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
	}

	// Get restored rules
	restored, _ := s.proxy.GetRules(uint16(epID1))
	restored.Sort()

	// remove rules
	err = s.proxy.UpdateAllowed(epID1, dstPort, nil)
	c.Assert(err, Equals, nil, Commentf("Could not remove rules"))

	// 2nd request, refused due to no rules
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query))
		c.Assert(len(response.Answer), Equals, 0, Commentf("Proxy returned incorrect number of answer RRs %s (query: %q)", response, query))
		c.Assert(response.Rcode, Equals, dns.RcodeRefused, Commentf("DNS request from test client was not rejected when it should be blocked (query: %q)", query))
	}

	// restore rules, set the mock to restoring state
	s.restoring = true
	ep1 := endpoint.NewEndpointWithState(s, s, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), uint16(epID1), endpoint.StateReady)
	ep1.IPv4 = netip.MustParseAddr("127.0.0.1")
	ep1.IPv6 = netip.MustParseAddr("::1")
	ep1.DNSRules = restored
	s.proxy.RestoreRules(ep1)
	_, exists := s.proxy.restored[epID1]
	c.Assert(exists, Equals, true)

	// 3nd request, answered due to restored Endpoint and rules being found
	for _, query := range queries {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query))
		c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s (query: %q)", response, query))
		c.Assert(response.Answer[0].String(), Equals, query+"\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
	}
	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, false)

	invalidRePattern := "invalid-re-pattern((*"
	validRePattern := "^this[.]domain[.]com[.]$"

	// extract the port the DNS-server is listening on by looking at the restored rules. The port is non-deterministic
	// since it's listening on :0
	c.Assert(len(restored), Equals, 1, Commentf("GetRules is expected to return rules for one port but returned for %d", len(restored)))
	port := maps.Keys(restored)[0]

	// Insert one valid and one invalid pattern and ensure that the valid one works
	// and that the invalid one doesn't interfere with the other rules.
	restored[port] = append(restored[port],
		restore.IPRule{Re: restore.RuleRegex{Pattern: &invalidRePattern}},
		restore.IPRule{Re: restore.RuleRegex{Pattern: &validRePattern}},
	)
	ep1.DNSRules = restored
	s.proxy.RestoreRules(ep1)
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, true)

	// 4nd request, answered due to restored Endpoint and rules being found, including domain matched by new regex
	for _, query := range append(queries, "this.domain.com.") {
		request := new(dns.Msg)
		request.SetQuestion(query, dns.TypeA)
		response, rtt, err := s.dnsTCPClient.Exchange(request, s.proxy.DNSServers[0].Listener.Addr().String())
		c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed (RTT: %v) (query: %q)", rtt, query))
		c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s (query: %q)", response, query))
		c.Assert(response.Answer[0].String(), Equals, query+"\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
	}

	// cleanup
	s.proxy.RemoveRestoredRules(uint16(epID1))
	_, exists = s.proxy.restored[epID1]
	c.Assert(exists, Equals, false)

	s.restoring = false
}

func (s *DNSProxyTestSuite) TestProxyRequestContext_IsTimeout(c *C) {
	p := new(ProxyRequestContext)
	p.Err = fmt.Errorf("sample err: %w", context.DeadlineExceeded)
	c.Assert(p.IsTimeout(), Equals, true)

	// Assert that failing to wrap the error properly (by using '%w') causes
	// IsTimeout() to return the wrong value.
	p.Err = fmt.Errorf("sample err: %s", context.DeadlineExceeded)
	c.Assert(p.IsTimeout(), Equals, false)

	p.Err = ErrFailedAcquireSemaphore{}
	c.Assert(p.IsTimeout(), Equals, true)
	p.Err = ErrTimedOutAcquireSemaphore{
		gracePeriod: 1 * time.Second,
	}
	c.Assert(p.IsTimeout(), Equals, true)
}

type selectorMock struct {
	key string
}

func (t selectorMock) GetSelections() []identity.NumericIdentity {
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
		cacheSize         = 128
	)
	re.InitRegexCompileLRU(cacheSize)
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
		re.InitRegexCompileLRU(cacheSize)
		for epID := uint64(0); epID < nEPs; epID++ {
			pea.setPortRulesForID(c, epID, 8053, nil)
		}
		b.StartTimer()
		for epID, rules := range rulesPerEP {
			if epID >= nEPsAtOnce {
				pea.setPortRulesForID(c, uint64(epID)-nEPsAtOnce, 8053, nil)
			}
			pea.setPortRulesForID(c, uint64(epID), 8053, rules)
		}
		b.StopTimer()
	}
	runtime.GC()
	// This is a ~proxy metric for the growth of heap per b.N. We call it here instead of the loop to
	// ensure we also count things like the strings "borrowed" from rulesPerEP
	b.ReportMetric(float64(getMemStats().HeapInuse-initialHeap), "B(HeapInUse)/op")

	for epID := uint64(0); epID < nEPs; epID++ {
		pea.setPortRulesForID(c, epID, 8053, nil)
	}
	if len(pea) > 0 {
		b.Fail()
	}
	b.StopTimer()
	// Remove all the inserted rules to ensure the cache goes down to zero entries
	for epID := uint64(0); epID < 20; epID++ {
		pea.setPortRulesForID(c, epID, 8053, nil)
	}
	if len(pea) > 0 || len(c) > 0 {
		b.Fail()
	}
}

func Benchmark_perEPAllow_setPortRulesForID_large(b *testing.B) {
	b.Skip()
	cacheSize := 128
	numEPs := uint64(20)
	cnpFile := "testdata/cnps-large.yaml"

	// init empty cache so old cache entries are correctly
	// garbage collected.
	re.InitRegexCompileLRU(cacheSize)
	runtime.GC()
	m := getMemStats()
	fmt.Printf("Before Setup (N=%v,EPs=%d,cache=%d)\n", b.N, numEPs, cacheSize)

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
		var (
			portRuleDNS []api.PortRuleDNS
		)
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
	fmt.Printf("Before Test (N=%v,EPs=%d,cache=%d)\n", b.N, numEPs, cacheSize)

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
			pea.setPortRulesForID(c, epID, 8053, rules)
		}
	}
	b.StopTimer()

	// Uncomment to see the HeapInUse from only the regexp cache
	// for epID := uint64(0); epID < numEPs; epID++ {
	//	 pea.setPortRulesForID(epID, 8053, nil)
	// }

	// Explicitly run gc to ensure we measure what we want
	runtime.GC()
	m = getMemStats()
	// Explicitly keep a reference to "pea" to keep it on the heap
	// so that we can measure it before it is garbage collected.
	fmt.Printf("After Test (N=%v,EPs=%d,cache=%d)\n", b.N, len(pea), cacheSize)
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tHeapInuse = %v MiB", bToMb(m.HeapInuse))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
	// Remove all the inserted rules to ensure both indexes go to zero entries
	for epID := uint64(0); epID < numEPs; epID++ {
		pea.setPortRulesForID(c, epID, 8053, nil)
	}
	if len(pea) > 0 || len(c) > 0 {
		b.Fail()
	}
}

//nolint:unused // Used in benchmark above, false-positive in golangci-lint v1.48.0.
func getMemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

//nolint:unused // Used in benchmark above, false-positive in golangci-lint v1.48.0.
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
