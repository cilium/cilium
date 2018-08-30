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
	"bytes"
	"net"
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

var DefaultDNSCache = NewDNSCache()

// cacheEntry objects are immutable once created.
// They hold an the DNS data passed in with DNSCache.Update, nominally equating
// to a DNS lookup. cacheEntry objects are managed by DNSCache and are not
// expected to be returned.
type cacheEntry struct {
	Name           string
	LookupTime     time.Time
	ExpirationTime time.Time
	TTL            int
	IPs            []net.IP
}

func (entry *cacheEntry) isExpired(now time.Time) bool {
	return now.After(entry.ExpirationTime)
}

// ipEntries maps a unique IP to the cacheEntry that provides it in .IPs.
// Multiple IPs may point to the same cacheEntry, or they may all be different.
// Crucially, an IP may be present in a cacheEntry but the IP in ipEntries
// points to another cacheEntry. This is because the second cacheEntry has a
// later expiration for this specific IP, and may not include the other IPs
// provided by the first entry.
// The DNS name in the entries is not checked, but is assumed to be the same
// for all entries.
// Note: They are guarded by the DNSCache mutex.
type ipEntries map[string]*cacheEntry

// getIPs returns a sorted list of non-expired unique IPs.
// This needs a read-lock
func (s ipEntries) getIPs(now time.Time) []net.IP {
	ips := make([]net.IP, 0, len(s)) // worst case size
	for ip, entry := range s {
		if entry != nil && !entry.isExpired(now) {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	return keepUniqueIPs(ips) // sorts IPs
}

// DNSCache manages DNS data that will expire after a certain TTL. Information
// is tracked per-IP address, retaining the latest-expiring DNS data for each
// address.
// For most real-world DNS data, the entry per name remains small because newer
// lookups replace older ones. Large TTLs may cause entries to grow if many
// unique IPs are returned in separate lookups.
// Redundant or expired entries are removed on insert.
// Lookups check for expired entries.
type DNSCache struct {
	lock.RWMutex

	// forward DNS lookups name -> IPEntries
	// IPEntries maps IP -> entry that provides it. An entry may provide multiple IPs.
	forward map[string]ipEntries
}

// NewDNSCache returns an initialized DNSCache
func NewDNSCache() *DNSCache {
	c := &DNSCache{
		forward: make(map[string]ipEntries),
	}

	return c
}

// Update inserts a new entry into the cache.
// After insertion cache entries for name are expired and redundant entries
// evicted. This is O(number of new IPs) for eviction, and O(number of IPs for
// name) for expiration.
func (c *DNSCache) Update(now time.Time, name string, ips []net.IP, ttl int) {
	entry := &cacheEntry{
		Name:           name,
		LookupTime:     now,
		ExpirationTime: now.Add(time.Duration(ttl) * time.Second),
		TTL:            ttl,
		IPs:            ips,
	}

	c.Lock()
	defer c.Unlock()

	entries, exists := c.forward[name]
	if !exists {
		entries = make(map[string]*cacheEntry)
		c.forward[name] = entries
	}
	c.updateWithEntryIPs(entries, entry)
	c.removeExpired(entries, now)
}

// Lookup returns a set of unique IPs that are currently unexpired for name, if
// any exist. An empty list indicates no valid records exist. The IPs are
// returned sorted.
func (c *DNSCache) Lookup(name string) (ips []net.IP) {
	return c.lookupByTime(time.Now(), name)
}

// lookupByTime takes a timestamp for expiration comparisions, and is only
// intended for testing.
func (c *DNSCache) lookupByTime(now time.Time, name string) (ips []net.IP) {
	c.RLock()
	defer c.RUnlock()

	entries, found := c.forward[name]
	if !found {
		return nil
	}

	return entries.getIPs(now)
}

// updateWithEntry adds a mapping for every IP in entry. It will replace
// existing IP->old entry mappings if the older entry expires sooner (or has
// already expired).
// This needs a write lock
func (c *DNSCache) updateWithEntryIPs(entries ipEntries, entry *cacheEntry) {
	for _, ip := range entry.IPs {
		ipStr := ip.String()
		old, exists := entries[ipStr]
		switch {
		case old == nil || !exists:
			entries[ipStr] = entry

		case entry.ExpirationTime.After(old.ExpirationTime):
			entries[ipStr] = entry
		}
	}
}

// removeExpired removes expired (or nil) cacheEntry pointers from entries, an
// ipEntries for a specific name.
// This needs a write lock
func (c *DNSCache) removeExpired(entries ipEntries, now time.Time) {
	for ip, entry := range entries {
		if entry == nil || entry.isExpired(now) {
			delete(entries, ip)
		}
	}
}

// keepUniqueIPs returns part of ips that includes only 1 entry per unique IP,
// lexicographically sorted via a byte-wise comparison of the IP slices.
// The slice is manipulated in-place destructively.
//
// 1- Sort the slice by comparing the IPs as bytes
// 2- For every unseen unique IP in the sorted slice, move it to the start of
// the return slice.
// Note that the slice is always large enough and, because it is sorted, we
// will not overwrite a valid element with another. To overwrite an element i
// with j, i must have come before j AND we decided it was a duplicate of the
// element at i-1.
func keepUniqueIPs(ips []net.IP) []net.IP {
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) == -1
	})

	returnIPs := ips[:0] // len==0 but cap==cap(ips)
	for readIdx, ip := range ips {
		if len(returnIPs) == 0 ||
			bytes.Compare(returnIPs[len(returnIPs)-1], ips[readIdx]) != 0 {
			returnIPs = append(returnIPs, ip)
		}
	}

	return returnIPs
}
