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
	"net"

	"github.com/miekg/dns"
)

var (
	ipLookups = map[string]*DNSIPRecords{
		dns.Fqdn("cilium.io"): {
			TTL: 60,
			IPs: []net.IP{
				net.ParseIP("172.217.18.174"),
				net.ParseIP("2a00:1450:4001:811::200e")}},
		dns.Fqdn("github.com"): {
			TTL: 60,
			IPs: []net.IP{
				net.ParseIP("98.138.219.231"),
				net.ParseIP("72.30.35.10"),
				net.ParseIP("001:4998:c:1023::4"),
				net.ParseIP("001:4998:58:1836::10")}},
	}
)

// LookupDNSNames is a wrappable dummy used by the tests. It counts the number
// of times a name is looked up in lookups, and uses ipData as a source for the
// "response"
func lookupDNSNames(ipData map[string]*DNSIPRecords, lookups map[string]int, dnsNames []string) (DNSIPs map[string]*DNSIPRecords) {
	DNSIPs = make(map[string]*DNSIPRecords)
	for _, dnsName := range dnsNames {
		lookups[dnsName] += 1
		DNSIPs[dnsName] = ipData[dnsName]
	}
	return DNSIPs
}
