// Copyright 2019 Authors of Hubble
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

package fqdncache

import (
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/go-openapi/strfmt"
)

type dnsLookup struct {
	*models.DNSLookup

	// name of the lookup, i.e. the fqdn without any trailing dot
	name string
}

// lookupsByIP maps IP addresses to the dns lookups assiciated with them
type lookupsByIP map[string][]*dnsLookup

// dnsHistory is the fqdn cache for a single endpoint
type dnsHistory struct {
	// ipToLookup maps IP addresses to all lookups accociated with it. Note that
	// a lookup may have multiple IPs and therefore will be contained multiple
	// times in this map.
	ipToNames lookupsByIP
}

// insertDNSLookup inserts a DNSLookup into the given dnsHistory.
func (d *dnsHistory) insertDNSLookup(m *models.DNSLookup) {
	if m == nil {
		return
	}

	newLookup := fromModel(m)
NextIP:
	for _, ip := range m.Ips {
		lookups := d.ipToNames[ip]
		for _, lookup := range lookups {
			// skip entry if it already exists
			if reflect.DeepEqual(lookup, newLookup) {
				continue NextIP
			}
		}

		// no matching existing entry, insert new
		d.ipToNames[ip] = append(lookups, newLookup)
	}
}

// endpoints contains the dns history for each endpoint
type endpoints map[uint64]*dnsHistory

// createOrGetEndpoint returns the endpoint dnsHistory for the given epID,
// or creates a new one if one does not exist yet.
func (e endpoints) createOrGetEndpoint(epID uint64) *dnsHistory {
	ep, ok := e[epID]
	if !ok {
		ep = &dnsHistory{
			ipToNames: make(map[string][]*dnsLookup),
		}
		e[epID] = ep
	}

	return ep
}

// FQDNCache maps IP addresses to fqdn names per endpoint
type FQDNCache struct {
	mutex     sync.RWMutex
	endpoints endpoints
}

// New empty FQDNCache
func New() *FQDNCache {
	return &FQDNCache{
		endpoints: endpoints{},
	}
}

// InitializeFrom replaces the content of the FQDN cache with the lookups from
// entries.
func (f *FQDNCache) InitializeFrom(entries []*models.DNSLookup) {
	// create a new empty endpoint map
	endpoints := endpoints{}

	for _, entry := range entries {
		ep := endpoints.createOrGetEndpoint(uint64(entry.EndpointID))
		ep.insertDNSLookup(entry)
	}

	// replace existing map
	f.mutex.Lock()
	f.endpoints = endpoints
	f.mutex.Unlock()
}

// AddDNSLookup adds a DNS lookup into the FQDNCache.
func (f *FQDNCache) AddDNSLookup(epID uint64, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	entry := newModel(epID, lookupTime, domainName, ips, ttl)
	ep := f.endpoints.createOrGetEndpoint(uint64(entry.EndpointID))
	ep.insertDNSLookup(entry)
}

// GetNamesOf returns all domain names associated with ip from the perspective
// of a given endpoint.
func (f *FQDNCache) GetNamesOf(epID uint64, ip net.IP) []string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	// resolve endpoint
	ep, ok := f.endpoints[epID]
	if !ok {
		return nil
	}

	// resolve ip to lookups containing it
	lookups := ep.ipToNames[ip.String()]
	if len(lookups) == 0 {
		return nil
	}

	// return deduplicated list of names for that ip
	names := make([]string, 0, len(lookups))
	for _, lookup := range lookups {
		names = append(names, lookup.name)
	}
	names = dedupeInPlace(names)

	return names
}

// newModel creates a new models.DNSLookup object
func newModel(epID uint64, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32) *models.DNSLookup {
	ipStr := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStr = append(ipStr, ip.String())
	}

	return &models.DNSLookup{
		EndpointID:     int64(epID),
		ExpirationTime: strfmt.DateTime(lookupTime.Add(time.Duration(ttl) * time.Second)),
		Fqdn:           domainName,
		Ips:            ipStr,
		LookupTime:     strfmt.DateTime(lookupTime),
		TTL:            int64(ttl),
	}
}

func fromModel(m *models.DNSLookup) *dnsLookup {
	return &dnsLookup{
		DNSLookup: m,
		name:      strings.TrimSuffix(m.Fqdn, "."),
	}
}

// dedupNames deduplicates strings in-place (i.e. n will be shuffled)
func dedupeInPlace(n []string) []string {
	if len(n) < 2 {
		return n
	}

	sort.Strings(n)
	j := 0
	for i := 1; i < len(n); i++ {
		if n[j] == n[i] {
			continue
		}
		j++
		n[i], n[j] = n[j], n[i]
	}
	return n[:j+1]
}
