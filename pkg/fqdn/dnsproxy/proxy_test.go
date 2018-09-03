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

	"github.com/miekg/dns"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type DNSProxyTestSuite struct{}

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

// TestDNSProxy tests:
// - allow a matching name for a specific endpoint
// - reject matching name for different endpoint
// - reject non-matching name
// - forward to correct DNS server IP (returned by lookupTargetDNSServer)
// - return response to original query to the original client
// - that we use the same proto as the original request (tcp/udp)
func (ts *DNSProxyTestSuite) TestDNSProxy(c *C) {
	var (
		request      = new(dns.Msg)
		dnsTCPClient = &dns.Client{Net: "tcp", Timeout: time.Second, SingleInflight: true}
		dnsServer    = setupServer()
	)
	defer teardown(dnsServer)

	proxy, err := StartDNSProxy("", 0,
		func(ip net.IP) (endpointID string, err error) {
			return "endpoint1", nil
		},
		func(lookupTime time.Time, name string, ips []net.IP, ttl int) error {
			return nil
		})
	c.Assert(err, IsNil, Commentf("error starting DNS Proxy"))
	proxy.lookupTargetDNSServer = func(w dns.ResponseWriter) (server string, err error) {
		return dnsServer.Listener.Addr().String(), nil
	}
	defer proxy.UDPServer.Shutdown()
	defer proxy.TCPServer.Shutdown()

	// Reject a query from not endpoint1
	proxy.AddAllowed("c[il]{3,3}um.io.", "notendpoint1")
	request.SetQuestion("cilium.io.", dns.TypeA)
	_, _, err = dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeded when it should be blocked"))

	// accept a query that matches from endpoint1
	proxy.AddAllowed("c[il]{3,3}um.io.", "endpoint1")
	request.SetQuestion("cilium.io.", dns.TypeA)
	_, _, err = dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))

	// accept a query for a non-regex
	proxy.AddAllowed("simple.io.", "endpoint1")
	request.SetQuestion("simple.io.", dns.TypeA)
	_, _, err = dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))

	// reject a query for a non-regex where a . is different (i.e. ensure simple FQDNs treat . as .)
	proxy.AddAllowed("simple.io.", "endpoint1")
	request.SetQuestion("simpleXio.", dns.TypeA)
	_, _, err = dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeeded when it should be blocked"))

	// reject a query for a non-matching domain
	request.SetQuestion("notcilium.io.", dns.TypeA)
	_, _, err = dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, NotNil, Commentf("DNS request from test client succeeded when it should be blocked"))

	// respond with an actual answer for the query. This also tests that the
	// connection was forwarded via the correct protocol (tcp/udp)
	request.SetQuestion("cilium.io.", dns.TypeA)
	response, _, err := dnsTCPClient.Exchange(request, proxy.TCPServer.Listener.Addr().String())
	c.Assert(err, IsNil, Commentf("DNS request from test client failed when it should succeed"))
	c.Assert(len(response.Answer), Equals, 1, Commentf("Proxy returned incorrect number of answer RRs", response.Answer))
	c.Assert(response.Answer[0].String(), Equals, "cilium.io.\t60\tIN\tA\t1.1.1.1", Commentf("Proxy returned incorrect RRs"))
}
