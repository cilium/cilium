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

package fqdn

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/dns"

	. "gopkg.in/check.v1"
)

func init() {
	// setup dummy dnsConfig for tests
	dnsConfig = &dns.ClientConfig{
		Servers:  []string{"1.2.3.4", "5.6.7.8"},
		Search:   make([]string, 0),
		Port:     "53",
		Ndots:    1,
		Timeout:  5,
		Attempts: 2,
	}
}

func makeResponse(qname string, dnsType uint16, rcode int, answers []dns.RR) *dns.Msg {
	ret := &dns.Msg{}
	ret.SetQuestion(dns.Fqdn(qname), dnsType)
	ret.Opcode = dns.OpcodeQuery
	ret.Rcode = rcode
	ret.RecursionDesired = true
	ret.RecursionAvailable = true
	ret.Response = true
	ret.Answer = answers
	return ret
}

// TestDNSResolverQueryAllNames tests that DNSLookupDefaultResolver should:
// - query all names in dnsNames
// - query for A and AAAA for each name
// - use the TTL in CNAMEs to set the TTL, and choose the lowest
func (ds *FQDNTestSuite) TestDNSResolverQueryAllNames(c *C) {
	dnsNames := []string{"a.com", "b.com", "c.com"}

	lookups := make(map[string]int)
	lookupFunc := func(server string, name string, dnsType uint16) (response *dns.Msg, err error) {
		lookups[name]++
		switch dnsType {
		case dns.TypeA:
			return makeResponse(name, dnsType, dns.RcodeSuccess, []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 20}, Target: "something.else."},
				&dns.A{Hdr: dns.RR_Header{Name: "something.else.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1")},
				&dns.A{Hdr: dns.RR_Header{Name: "something.else.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("2.2.2.2")},
			}), nil
		case dns.TypeAAAA:
			return makeResponse(name, dnsType, dns.RcodeSuccess, []dns.RR{
				&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 10}, Target: "something.else."},
				&dns.AAAA{Hdr: dns.RR_Header{Name: "something.else.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("cafe::face")},
				&dns.AAAA{Hdr: dns.RR_Header{Name: "something.else.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("face::cafe")},
			}), nil

		default:
			return makeResponse(name, dnsType, dns.RcodeRefused, nil), nil
		}
	}

	responses, errors := doResolverLogic(lookupFunc, dnsNames)
	c.Assert(len(errors), Equals, 0, Commentf("Returned unexpected errors for some names: %v", errors))
	c.Assert(len(responses), Equals, len(dnsNames), Commentf("Did not return results for all query names"))
	c.Assert(len(lookups), Equals, len(dnsNames), Commentf("Did not do a lookup for all names"))
	for name, ans := range responses {
		c.Assert(lookups[name], Equals, 2, Commentf("More than 2 expected lookups (A & AAAA) for %s: %v", name, lookups))

		c.Assert(len(ans.IPs), Equals, 4, Commentf("Incorrect number of IPs returned from lookups"))
		for i, correctIP := range []string{"1.1.1.1", "2.2.2.2", "cafe::face", "face::cafe"} {
			c.Assert(ans.IPs[i].String(), Equals, correctIP, Commentf("Incorrect IP returned"))
		}

		c.Assert(ans.TTL, Equals, 10, Commentf("TTL is not the smallest of all A, AAAA, and CNAME records"))
	}
}

// TestDNSResolverNextServerOnError tests that DNSLookupDefaultResolver should:
// test that we skip to next server on error
func (ds *FQDNTestSuite) TestDNSResolverNextServerOnError(c *C) {
	dnsNames := []string{"a.com"}

	lookups := make(map[string]int)
	lookupFunc := func(server string, name string, dnsType uint16) (response *dns.Msg, err error) {
		lookups[server]++

		// Return an error on the first lookup, then work correctly
		if len(lookups) == 1 {
			return nil, errors.New("test error")

		}

		switch dnsType {
		case dns.TypeA:
			return makeResponse(name, dnsType, dns.RcodeSuccess, []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("1.1.1.1")},
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("2.2.2.2")},
			}), nil
		case dns.TypeAAAA:
			return makeResponse(name, dnsType, dns.RcodeSuccess, []dns.RR{
				&dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("cafe::face")},
				&dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("face::cafe")},
			}), nil
		}

		return nil, fmt.Errorf("Unhandled DNS query type: %v", dnsType)
	}

	responses, errors := doResolverLogic(lookupFunc, dnsNames)
	c.Assert(len(errors), Equals, 0, Commentf("Returned incorrect number of errors(cleared on success): %v", errors))
	c.Assert(len(lookups), Equals, len(dnsConfig.Servers), Commentf("Did not query 2/2 DNS servers (expected due to test-induced error): %v", lookups))
	c.Assert(lookups[dnsConfig.Servers[0]+":"+dnsConfig.Port], Equals, 2, Commentf("First server in list not queried enough times (1 error, 1 success): %v", lookups))
	c.Assert(lookups[dnsConfig.Servers[1]+":"+dnsConfig.Port], Equals, 1, Commentf("Second server in list not queried enough times (1 success from failover): %v", lookups))
	for _, ans := range responses {
		c.Assert(len(ans.IPs), Equals, 4, Commentf("Incorrect number of IPs returned from lookups"))
		for i, correctIP := range []string{"1.1.1.1", "2.2.2.2", "cafe::face", "face::cafe"} {
			c.Assert(ans.IPs[i].String(), Equals, correctIP, Commentf("Incorrect IP returned"))
		}

		c.Assert(ans.TTL, Equals, 30, Commentf("TTL is not the smallest of all A, AAAA, and CNAME records"))
	}

}
