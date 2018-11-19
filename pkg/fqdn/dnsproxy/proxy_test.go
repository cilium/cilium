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

	"github.com/miekg/dns"
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

func setupServer() (dnsServer *dns.Server) {
	dnsServer = &dns.Server{Addr: ":0", Net: "tcp"}
	go dnsServer.ListenAndServe()
	dns.HandleFunc(".", serveDNS)
	return dnsServer
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
	s.dnsTCPClient = &dns.Client{Net: "tcp", Timeout: time.Second, SingleInflight: true}
	s.dnsServer = setupServer()

	proxy, err := StartDNSProxy("", 0,
		func(ip net.IP) (endpointID string, err error) {
			return "endpoint1", nil
		},
		func(lookupTime time.Time, name string, ips []net.IP, ttl int) error {
			return nil
		})
	c.Assert(err, IsNil, Commentf("error starting DNS Proxy"))
	s.proxy = proxy
	s.proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (server string, err error) {
		return s.dnsServer.Listener.Addr().String(), nil
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
	s.proxy.AddAllowed("c[il]{3,3}um.io.", "notendpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeded when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestAcceptMatchingFromEndpoint(c *C) {
	// accept a query that matches from endpoint1
	s.proxy.AddAllowed("c[il]{3,3}um.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
}

func (s *DNSProxyTestSuite) TestAcceptNonRegex(c *C) {
	s.proxy.AddAllowed("simple.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("simple.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
}

func (s *DNSProxyTestSuite) TestRejectNonRegex(c *C) {
	// reject a query for a non-regex where a . is different (i.e. ensure simple FQDNs treat . as .)
	s.proxy.AddAllowed("simple.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("simpleXio.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeeded when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestRejectNonMatching(c *C) {
	request := new(dns.Msg)
	request.SetQuestion("notcilium.io.", dns.TypeA)
	_, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeeded when it should be blocked"))
}

func (s *DNSProxyTestSuite) TestRespondViaCorrectProtocol(c *C) {
	// respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp)
	s.proxy.AddAllowed("c[il]{3,3}um.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("cilium.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "cilium.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestRespondMixedCaseInRequest(c *C) {
	s.proxy.AddAllowed("c[il]{3,3}um.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("CILIUM.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "CILIUM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestRespondMixedCaseInResponse(c *C) {
	s.proxy.AddAllowed("c[IL]{3,3}um.io.", "endpoint1")
	request := new(dns.Msg)
	request.SetQuestion("ciliuM.io.", dns.TypeA)
	response, _, err := s.dnsTCPClient.Exchange(request, s.proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "ciliuM.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedMixedCaseChecked(c *C) {
	s.proxy.AddAllowed("c[il]{3,3}um.io.", "endpoint1")

	result := s.proxy.CheckAllowed("CILIUM.io.", "endpoint1")

	c.Assert(result, Equals, true, Commentf("Mixed case dns request should be allowed"))
}

func (s *DNSProxyTestSuite) TestCheckAllowedMixedCaseRule(c *C) {
	s.proxy.AddAllowed("CILIUM.io.", "endpoint1")

	result := s.proxy.CheckAllowed("ciliuM.io.", "endpoint1")

	c.Assert(result, Equals, true, Commentf("Mixed case dns request should be allowed based on mixed case rule"))
}
