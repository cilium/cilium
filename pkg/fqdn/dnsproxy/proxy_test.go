// Copyright 2018-2020 Authors of Cilium
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

// +build privileged_tests

package dnsproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils/allocator"

	"github.com/miekg/dns"
	. "gopkg.in/check.v1"
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
}

func (s *DNSProxyTestSuite) GetPolicyRepository() *policy.Repository {
	return s.repo
}

func (s *DNSProxyTestSuite) GetProxyPort(l7Type policy.L7ParserType, ingress bool) (uint16, string, error) {
	return 0, "", nil
}

func (s *DNSProxyTestSuite) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, wg *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	return 0, nil, nil, nil
}

func (s *DNSProxyTestSuite) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

func (s *DNSProxyTestSuite) UpdateNetworkPolicy(e regeneration.EndpointUpdater, policy *policy.L4Policy,
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

func (s *DNSProxyTestSuite) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	return nil
}

func (s *DNSProxyTestSuite) Datapath() datapath.Datapath {
	return nil
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

func teardown(dnsServer *dns.Server) {
	dnsServer.Listener.Close()
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

func (d *DummySelectorCacheUser) IdentitySelectionUpdated(selector policy.CachedSelector, selections, added, deleted []identity.NumericIdentity) {
}

// Setup identities, ports and endpoint IDs we will need
var (
	cacheAllocator          = cache.NewCachingIdentityAllocator(&allocator.IdentityAllocatorOwnerMock{})
	testSelectorCache       = policy.NewSelectorCache(cacheAllocator.GetIdentityCache())
	dummySelectorCacheUser  = &DummySelectorCacheUser{}
	DstID1Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst1=test"))
	cachedDstID1Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID1Selector)
	DstID2Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst2=test"))
	cachedDstID2Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID2Selector)
	DstID3Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst3=test"))
	cachedDstID3Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID3Selector)
	DstID4Selector          = api.NewESFromLabels(labels.ParseSelectLabel("k8s:Dst4=test"))
	cachedDstID4Selector, _ = testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, DstID4Selector)

	epID1   = uint64(111)
	epID2   = uint64(222)
	epID3   = uint64(333)
	dstID1  = identity.NumericIdentity(1001)
	dstID2  = identity.NumericIdentity(2002)
	dstID3  = identity.NumericIdentity(3003)
	dstID4  = identity.NumericIdentity(4004)
	dstPort = uint16(53) // Set below when we setup the server!
)

func (s *DNSProxyTestSuite) SetUpSuite(c *C) {
	// Add these identities
	testSelectorCache.UpdateIdentities(cache.IdentityCache{
		dstID1: labels.Labels{"Dst1": labels.NewLabel("Dst1", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID2: labels.Labels{"Dst2": labels.NewLabel("Dst2", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID3: labels.Labels{"Dst3": labels.NewLabel("Dst3", "test", labels.LabelSourceK8s)}.LabelArray(),
		dstID4: labels.Labels{"Dst4": labels.NewLabel("Dst4", "test", labels.LabelSourceK8s)}.LabelArray(),
	}, nil)

	s.repo = policy.NewPolicyRepository(nil, nil)
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: 100 * time.Millisecond, SingleInflight: true}
	s.dnsServer = setupServer(c)
	c.Assert(s.dnsServer, Not(IsNil), Commentf("unable to setup DNS server"))

	proxy, err := StartDNSProxy("", 0, true, // any address, any port, enable compression
		// LookupEPByIP
		func(ip net.IP) (*endpoint.Endpoint, error) {
			return endpoint.NewEndpointWithState(s, &endpoint.FakeEndpointProxy{}, &allocator.FakeIdentityAllocator{}, uint16(epID1), endpoint.StateReady), nil
		},
		// LookupSecIDByIP
		func(ip net.IP) (ipcache.Identity, bool) {
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
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, dstAddr string, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error {
			return nil
		})
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
	s.proxy.allowed = make(perEPAllow)
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
}

func (s *DNSProxyTestSuite) TearDownSuite(c *C) {
	s.dnsServer.Listener.Close()
	s.proxy.UDPServer.Shutdown()
	s.proxy.TCPServer.Shutdown()
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
	allowed, err := s.proxy.CheckAllowed(epID2, dstPort, dstID1, query)
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
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
	response, _, _ := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(response.Rcode, Equals, dns.RcodeNameError, Commentf("DNS request from test client was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestRejectNonMatchingRefusedResponseWithRefused(c *C) {
	request := s.requestRejectNonMatchingRefusedResponse(c)

	// reject a query with Refused
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
	response, _, _ := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	request := new(dns.Msg)
	request.SetQuestion(query, dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %s", response))
	c.Assert(response.Answer[0].String(), Equals, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))

	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err = s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs %+v", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "ciliuM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
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
	allowed, err := s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Delete once, it should reject
	err = s.proxy.UpdateAllowed(epID1, dstPort, nil)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err = s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Delete once, it should reject and not crash
	err = s.proxy.UpdateAllowed(epID1, dstPort, nil)
	c.Assert(err, Equals, nil, Commentf("Could not update with rules"))
	allowed, err = s.proxy.CheckAllowed(epID1, dstPort, dstID1, query)
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
	// | EP1  | DstID1 |      54 | example.com    |
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
		cachedDstID1Selector: &policy.PerSelectorPolicy{
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
	allowed, err := s.proxy.CheckAllowed(epID1, 53, dstID1, "www.ubuntu.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 2 | EPID1 | DstID1 |   54 | cilium.io      | Rejected | Port 54 only allows example.com
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 3 | EPID1 | DstID2 |   53 | cilium.io      | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 4 | EPID1 | DstID2 |   53 | aws.amazon.com | Rejected | Only cilium.io is allowed with DstID2
	allowed, err = s.proxy.CheckAllowed(epID1, 53, dstID2, "aws.amazon.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 5 | EPID1 | DstID1 |   54 | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID1, 54, dstID1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 6 | EPID2 | DstID1 |   53 | cilium.io      | Rejected | EPID2 is not allowed as a source by any policy
	allowed, err = s.proxy.CheckAllowed(epID2, 53, dstID1, "cilium.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 7 | EPID3 | DstID1 |   53 | example.com    | Allowed
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 8 | EPID3 | DstID1 |   53 | aws.amazon.com | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID1, "aws.amazon.io")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 8 | EPID3 | DstID1 |   54 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 54, dstID1, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 9 | EPID3 | DstID2 |   53 | example.com    | Rejected | EPID3 is only allowed to ask DstID1 on Port 53 for example.com
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID2, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, false, Commentf("request was allowed when it should be rejected"))

	// Case 10 | EPID3 | DstID3 |   53 | example.com    | Allowed due to wildcard match pattern
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID3, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))

	// Case 11 | EPID3 | DstID4 |   53 | example.com    | Allowed due to a nil rule
	allowed, err = s.proxy.CheckAllowed(epID3, 53, dstID4, "example.com")
	c.Assert(err, Equals, nil, Commentf("Error when checking allowed"))
	c.Assert(allowed, Equals, true, Commentf("request was rejected when it should be allowed"))
}
