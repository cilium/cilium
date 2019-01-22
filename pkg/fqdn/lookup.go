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

package fqdn

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"

	"github.com/cilium/dns"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// DNSIPRecords mimics the RR data from an A or AAAA response.
// My kingdom for a DNS IP RR type that isn't hidden in the stdlib or has a
// million layers of type indirection.
type DNSIPRecords struct {
	// TTL is the time, in seconds, that these IPs are valid for
	TTL int

	// IPs are the IPs associated with a DNS Name
	IPs []net.IP
}

var (
	// dnsConfig is the general config. It must be set via SetDNSConfig otherwise
	// no lookups will actually happen.
	dnsConfig = &dns.ClientConfig{
		Servers: nil,
	}

	// clientUDP and clientTCP can be reused, and will coalesce multiple queries
	// for the same (Qname, Qtype, Qclass)
	clientUDP, clientTCP *dns.Client
)

// ConfigFromResolvConf parses the configuration in /etc/resolv.conf and sets
// the configuration for pkg/fqdn.
// nameservers and opt timeout are supported.
// search and ndots are NOT supported.
// This call is not thread safe.
func ConfigFromResolvConf() error {
	dnsConf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	SetDNSConfig(dnsConf)

	return nil
}

// SetDNSConfig store conf in pkg/fqdn as the global config. It also creates
// the global UDP and TCP clients used for DNS lookups in
// DNSLookupDefaultResolver.
// Only .Servers and .Timeout are utilized from conf.
// This call is not thread safe.
func SetDNSConfig(conf *dns.ClientConfig) {
	dnsConfig = conf

	clientUDP = &dns.Client{
		Net:            "udp",
		Timeout:        time.Duration(dnsConfig.Timeout) * time.Second,
		SingleInflight: true,
	}

	clientTCP = &dns.Client{
		Net:            "tcp",
		Timeout:        time.Duration(dnsConfig.Timeout) * time.Second,
		SingleInflight: true,
	}
}

// DNSLookupDefaultResolver sequentially and synchronously runs a DNS lookup
// for every name in dnsNames. It does not use net.DefaultResolver, but
// dnsConfig from this package (populated from resolv.conf). The configured
// servers are always queried in the same order, only moving to the next on
// errors (such as timeouts). The names are queried in random order (as the map
// iteration is random) but, for each name, A records and then AAAA records are
// requested in that order.
// It will return:
// DNSIPs: a map of DNS names to their IPs and associated smallest TTL (only
// contains successful lookups). CNAME records in the response are collapsed
// into the IPs later in the response data. The CNAME TTL is considered when
// finding the smallest TTL.
// DNSErrors: a map of DNS names to lookup errors.
//
// DNSLookupDefaultResolver is used by DNSPoller when no alternative LookupDNSNames is provided.
func DNSLookupDefaultResolver(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, DNSErrors map[string]error) {
	return doResolverLogic(lookup, dnsNames)
}

// doResolverLogic exists to allow testing the more complex logic around
// collecting A and AAAA records, handling CNAMEs and trying different servers.
func doResolverLogic(lookupFunc func(string, string, uint16) (*dns.Msg, error), dnsNames []string) (DNSIPs map[string]*DNSIPRecords, DNSErrors map[string]error) {
	DNSIPs = make(map[string]*DNSIPRecords)
	DNSErrors = make(map[string]error)

	// This is the top-level list of names to query
	for _, dnsName := range dnsNames {
		responseData := &DNSIPRecords{TTL: math.MaxInt32}

		// Query for A & AAAA for each dnsName
	perTypeToQuery:
		for _, dnsType := range []dns.Type{dns.Type(dns.TypeA), dns.Type(dns.TypeAAAA)} { // the dns library doesn't use dns.Type

			// Try the servers in the order they were configured in resolv.conf
		perServerToAttempt:
			for _, server := range dnsConfig.Servers {
				response, err := lookupFunc(server+":"+dnsConfig.Port, dnsName, uint16(dnsType))
				// Move onto the next server when the response is bad
				switch {
				case err != nil:
					DNSErrors[dnsName] = fmt.Errorf("error when querying %s: %s", server, err)
					continue perServerToAttempt
				case response.Response != true:
					continue perServerToAttempt
				case response.Rcode != dns.RcodeSuccess: // e.g. NXDomain or Refused
					// Not an error, but also no data we can use. Move on to the next
					// type. We assume that the servers are not lying to us (i.e. they
					// can all answer the query)
					DNSErrors[dnsName] = fmt.Errorf("no data when querying %s", server)
					continue perTypeToQuery
				}

				// To arrive here means:
				//  - The server responded without a communication error
				//  - response.Rcode == dns.RcodeSuccess
				delete(DNSErrors, dnsName) // clear any errors we set for other servers

				for _, answer := range response.Answer {
					switch answer := answer.(type) {
					case *dns.A:
						DNSIPs[dnsName] = responseData // return only when we have an answer
						responseData.IPs = append(responseData.IPs, answer.A)
						responseData.TTL = ttlMin(responseData.TTL, int(answer.Hdr.Ttl))

					case *dns.AAAA:
						DNSIPs[dnsName] = responseData // return only when we have an answer
						responseData.IPs = append(responseData.IPs, answer.AAAA)
						responseData.TTL = ttlMin(responseData.TTL, int(answer.Hdr.Ttl))

					case *dns.CNAME:
						// Do we need to enforce any policy on this?
						// Responses with CNAMEs from recursive resolvers will have IPs
						// included, and we will return those as the IPs for dnsName.
						// We still track the TTL because the lowest TTL in the chain
						// determines the valid caching time for the whole response.
						responseData.TTL = ttlMin(responseData.TTL, int(answer.Hdr.Ttl))

					// Treat an inappropriate response like no response, and try another
					// server
					default:
						DNSErrors[dnsName] = fmt.Errorf("unexpected DNS Resource Records(%T) in response from %s: %s", answer, server, err)
						continue perServerToAttempt
					}
				}

				// We have a valid response, stop trying queryNames or other servers.
				continue perTypeToQuery
			}
		}
	}

	return DNSIPs, DNSErrors
}

// lookup sends a single DNS lookup to server for name/dnsType.
// It uses the global clients and their configured timeouts and retries.
func lookup(server string, name string, dnsType uint16) (response *dns.Msg, err error) {
	name = dns.Fqdn(name)
	m := &dns.Msg{}
	m.SetQuestion(name, dnsType)
	m.Rcode = dns.OpcodeQuery
	m.RecursionDesired = true

	response, _, err = clientUDP.Exchange(m, server)
	if err == nil && m.Response == true && m.Truncated == false {
		return response, nil
	}

	// Try TCP on error, a truncated response, or some bogus non-response
	response, _, err = clientTCP.Exchange(m, server)
	return response, err
}

// ttlMin returns the lower of i and j, or the one that is not 0.
func ttlMin(i, j int) int {
	if i < j {
		return i
	}
	return j
}
