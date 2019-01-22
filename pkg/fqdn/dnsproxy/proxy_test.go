// Copyright 2018 Authors of Cilium
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

package dnsproxy

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/dns"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type DNSProxyTestSuite struct {
	dnsTCPClient *dns.Client
	dnsServer    *dns.Server
	proxy        *DNSProxy
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

func (s *DNSProxyTestSuite) SetUpSuite(c *C) {
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: 100 * time.Millisecond, SingleInflight: true}
	s.dnsServer = setupServer(c)
	c.Assert(s.dnsServer, Not(IsNil), Commentf("unable to setup DNS server"))

	proxy, err := StartDNSProxy("", 0,
		func(ip net.IP) (endpointID string, err error) {
			return "endpoint1", nil
		},
		func(lookupTime time.Time, srcAddr, dstAddr string, msg *dns.Msg, protocol string, allowed bool, stat ProxyRequestContext) error {
			return nil
		})
	c.Assert(err, IsNil, Commentf("error starting DNS Proxy"))
	s.proxy = proxy

	// This is here because Listener or Listeer.Addr() was nil. The
	// lookupTargetDNSServer function doesn't need to change the target.
	c.Assert(s.dnsServer.Listener, Not(IsNil), Commentf("DNS server missing a Listener"))
	DNSServerListenerAddr := s.dnsServer.Listener.Addr()
	c.Assert(DNSServerListenerAddr, Not(IsNil), Commentf("DNS server missing a Listener address"))
	DNSServerListenerAddrString := DNSServerListenerAddr.String()
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (server string, err error) {
		return DNSServerListenerAddrString, nil
	}
}

func (s *DNSProxyTestSuite) TearDownTest(c *C) {
	s.proxy.allowed = regexpmap.NewRegexpMap()
}

func (s *DNSProxyTestSuite) TearDownSuite(c *C) {
	s.dnsServer.Listener.Close()
	s.proxy.UDPServer.Shutdown()
	s.proxy.TCPServer.Shutdown()
}

func (s *DNSProxyTestSuite) TestRejectMatchingForDifferentEndpoint(c *C) {
	// Reject a query from not endpoint1
	s.proxy.AddAllowed("c[il]{3,3}um[.]io[.]", "notendpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, Equals, nil, Commentf("DNS request should not yield error when being rejected"))
	c.Assert(response.Rcode, Equals, dns.RcodeRefused, Commentf("DNS request from test client was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestAcceptMatchingFromEndpoint(c *C) {
	// accept a query that matches from endpoint1
	s.proxy.AddAllowed("c[il]{3,3}um[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
}

func (s *DNSProxyTestSuite) TestAcceptNonRegex(c *C) {
	s.proxy.AddAllowed("simple[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("simple.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
}

func (s *DNSProxyTestSuite) TestRejectNonRegex(c *C) {
	// reject a query for a non-regex where a . is different (i.e. ensure simple FQDNs treat . as .)
	s.proxy.AddAllowed("simple[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("simpleXio.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client returned error when it should be rejected"))
	c.Assert(response.Rcode, Equals, dns.RcodeRefused, Commentf("DNS request from test client was not rejected when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestRejectNonMatchingRefusedResponse(c *C) {
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithRefused)
	request := new(dns.Msg)
	request.SetQuestion("notcilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client returned error when it should be rejected"))
	c.Assert(response.Rcode, Equals, dns.RcodeRefused, Commentf("DNS request from test client was not rejected with the rigth response code"))
}

func (s *DNSProxyTestSuite) TestRejectNonMatchingNoDomainResponse(c *C) {
	s.proxy.SetRejectReply(option.FQDNProxyDenyWithNameError)
	request := new(dns.Msg)
	request.SetQuestion("notcilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client returned error when it should be rejected"))
	c.Assert(response.Rcode, Equals, dns.RcodeNameError, Commentf("DNS request from test client was not rejected with the rigth response code"))
}

func (s *DNSProxyTestSuite) TestRespondViaCorrectProtocol(c *C) {
	// respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp)
	s.proxy.AddAllowed("c[il]{3,3}um[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "cilium.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestRespondMixedCaseInRequest(c *C) {
	s.proxy.AddAllowed("c[il]{3,3}um[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("CILIUM.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestRespondMixedCaseInResponse(c *C) {
	s.proxy.AddAllowed("c[IL]{3,3}um[.]io[.]", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "ciliuM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedMixedCaseChecked(c *C) {
	s.proxy.AddAllowed("c[il]{3,3}um[.]io[.]", "endpoint1")

	result := s.proxy.CheckAllowed("CILIUM.io.", "endpoint1")

	c.Assert(result, Equals, true, Commentf("Mixed case dns request should be allowed"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedMixedCaseRule(c *C) {
	s.proxy.AddAllowed("CILIUM[.]io[.]", "endpoint1")

	result := s.proxy.CheckAllowed("ciliuM.io.", "endpoint1")

	c.Assert(result, Equals, true, Commentf("Mixed case dns request should be allowed based on mixed case rule"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedTwiceRemovedOnce(c *C) {
	s.proxy.AddAllowed("cilium.io.", "endpoint1")
	s.proxy.AddAllowed("cilium.io.", "endpoint1")

	result := s.proxy.CheckAllowed("cilium.io.", "endpoint1")
	c.Assert(result, Equals, true, Commentf("Should allow requests matching duplicate rules"))

	s.proxy.RemoveAllowed("cilium.io.", "endpoint1")
	result = s.proxy.CheckAllowed("cilium.io.", "endpoint1")

	c.Assert(result, Equals, true, Commentf("Should allow requests matching duplicate rules from which one was deleted"))

	s.proxy.RemoveAllowed("cilium.io.", "endpoint1")
	result = s.proxy.CheckAllowed("cilium.io.", "endpoint1")
	c.Assert(result, Equals, false, Commentf("Should not allow requests matching duplicate rules from which both were deleted"))
}

func (s *DNSProxyTestSuite) TestSetRejectReplyNoValidData(c *C) {
	s.proxy.SetRejectReply("banana")
	request := new(dns.Msg)
	request.SetQuestion("notcilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client returned error when it should be rejected"))
	c.Assert(response.Rcode, Not(Equals), 100, Commentf("DNS request from test client has an invalid response code"))
}
