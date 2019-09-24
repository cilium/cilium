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
	"context"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/miekg/dns"
)

// Config is a simple configuration structure to set how pkg/fqdn subcomponents
// behave.
// DNSPoller relies on LookupDNSNames to control how DNS lookups are done, and
// UpdateSelectors to control how generated policy rules are emitted.
type Config struct {
	// MinTTL is the time used by the poller to cache information.
	// When set to 0, 2*DNSPollerInterval is used.
	MinTTL int

	// OverLimit is the number of max entries that a host can have in the DNS cache.
	OverLimit int

	// Cache is where the poller stores DNS data used to generate rules.
	// When set to nil, it uses fqdn.DefaultDNSCache, a global cache instance.
	Cache *DNSCache

	// DNSConfig includes the Resolver IPs, port, timeout and retry count. It is
	// expected to be  generated from /etc/resolv.conf.
	DNSConfig *dns.ClientConfig

	// LookupDNSNames is a callback to run the provided DNS lookups.
	// When set to nil, fqdn.DNSLookupDefaultResolver is used.
	LookupDNSNames func(dnsNames []string) (DNSIPs map[string]*DNSIPRecords, errorDNSNames map[string]error)

	// UpdateSelectors is a callback to update the mapping of FQDNSelector to
	// sets of IPs.
	UpdateSelectors func(ctx context.Context, selectorsWithIPs map[api.FQDNSelector][]net.IP, selectorsWithoutIPs []api.FQDNSelector) (*sync.WaitGroup, error)

	// PollerResponseNotify is used when the poller receives DNS data in response
	// to a successful poll.
	// Note: This function doesn't do much, as the poller is still wired to
	// NameManager directly right now.
	PollerResponseNotify func(lookupTime time.Time, qname string, response *DNSIPRecords)
}
