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
	"net"
	"strings"

	"github.com/miekg/dns"
)

// sortedIPsAreEqual compares two lists of sorted IPs. If any differ it returns
// false.
func sortedIPsAreEqual(a, b []net.IP) bool {
	// the IP set is definitely different if the lengths are different
	if len(a) != len(b) {
		return false
	}

	// lengths are equal, so each member in one set must be in the other
	// Note: we sorted fullNewIPs above, and sorted oldIPs when they were
	// inserted in this function, previously.
	// If any IPs at the same index differ, updated = true.
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return strings.ToLower(dns.Fqdn(matchName))
}

// KeepUniqueNames it gets a array of strings and return a new array of strings
// with the unique names.
func KeepUniqueNames(names []string) []string {
	result := []string{}
	entries := map[string]bool{}

	for _, item := range names {
		if _, ok := entries[item]; ok {
			continue
		}
		entries[item] = true
		result = append(result, item)
	}
	return result
}
