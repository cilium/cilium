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
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
)

// cacheEntry objects hold data passed in via DNSCache.Update, nominally
// equating to a DNS lookup. They are internal to DNSCache and should not be
// returned.
// cacheEntry objects are immutable once created; the address of an instance is
// a unique identifier.
// Note: the JSON names are intended to correlate to field names from
// api/v1/models.DNSLookup to allow dumping the json from
// `cilium fqdn cache list` to a file that can be unmarshalled via
// `--tofqdns-per-cache`
type cacheEntry struct {
	// Name is a DNS name, it my be not fully qualified (e.g. myservice.namespace)
	Name string `json:"fqdn,omitempty"`

	// LookupTime is when the data begins being valid
	LookupTime time.Time `json:"lookup-time,omitempty"`

	// ExpirationTime is a calcutated time when the DNS data stops being valid.
	// It is simply LookupTime + TTL
	ExpirationTime time.Time `json:"expiration-time,omitempty"`

	// TTL represents the number of seconds past LookupTime that this data is
	// valid.
	TTL int `json:"ttl,omitempty"`

	// IPs are the IPs associated with Name for this cacheEntry.
	IPs []net.IP `json:"ips,omitempty"`
}

// isExpiredBy returns true if entry is no longer valid at pointInTime
func (entry *cacheEntry) isExpiredBy(pointInTime time.Time) bool {
	return pointInTime.After(entry.ExpirationTime)
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

// nameEntries maps a DNS name to the cache entry that inserted it into the
// cache. It used in reverse DNS lookups. It is similar to ipEntries, above,
// but the key is a DNS name.
type nameEntries map[string]*cacheEntry

// getIPs returns a sorted list of non-expired unique IPs.
// This needs a read-lock
func (s ipEntries) getIPs(now time.Time) []net.IP {
	ips := make([]net.IP, 0, len(s)) // worst case size
	for ip, entry := range s {
		if entry != nil && !entry.isExpiredBy(now) {
			ips = append(ips, net.ParseIP(ip))
		}
	}

	return ip.KeepUniqueIPs(ips) // sorts IPs
}

// DNSCache manages DNS data that will expire after a certain TTL. Information
// is tracked per-IP address, retaining the latest-expiring DNS data for each
// address.
// For most real-world DNS data, the entry per name remains small because newer
// lookups replace older ones. Large TTLs may cause entries to grow if many
// unique IPs are returned in separate lookups.
// It is critical to run .GC periodically. This cleans up expired entries and
// steps forward the time used to determine that entries are expired. This
// means that the Lookup functions may return expired entries until GC is
// called.
// Redundant entries are removed on insert.
type DNSCache struct {
	lock.RWMutex

	// forward DNS lookups name -> IPEntries
	// IPEntries maps IP -> entry that provides it. An entry may provide multiple IPs.
	forward map[string]ipEntries

	// IP->dnsNames lookup
	// This map is subordinate to forward, above. An IP inserted into forward, or
	// expired in forward, should also be added/removed in reverse.
	reverse map[string]nameEntries

	// LastCleanup is the latest time for which entries have been expired. It is
	// used as "now" when doing lookups and advanced by calls to .GC
	// When an entry is added with an expiration time before lastCleanup, it is
	// set to that value.
	lastCleanup time.Time

	// cleanup maps the TTL expiration times (in seconds since the epoch) to
	// DNS names that expire in that second. On every new insertion where the
	// new data is actually inserted into the cache (i.e. it expires later than
	// an existing entry) cleanup will be updated. CleanupExpiredEntries cleans
	// up these entries on demand.
	// Note: Lookup functions will not return expired entries, and this is used
	// to proactively enforce expirations.
	// Note: It is important to periodically call CleanupExpiredEntries
	// otherwise this map will grow forever.
	cleanup map[int64][]string

	// overLimit is a set of DNS names that were over the per-host configured
	// limit when they received an update. The excess IPs will be removed when
	// cleanupOverLimitEntries is called, but will continue to be returned by
	// Lookup until then.
	// Note: It is important to periodically call GC otherwise this map will
	// grow forever (it is very bounded, however).
	overLimit map[string]bool

	// perHostLimit is the number of maximum number of IP per host.
	perHostLimit int

	// minTTL is the minimun TTL value that a cache entry can have, if the TTL
	// sent in the Update is lower, the TTL will be owerwritten to this value.
	// Due is only read-only is not protected by the mutex.
	minTTL int
}

// NewDNSCache returns an initialized DNSCache
func NewDNSCache(minTTL int) *DNSCache {
	c := &DNSCache{
		forward: make(map[string]ipEntries),
		reverse: make(map[string]nameEntries),
		// lastCleanup is populated on the first insert
		cleanup:      map[int64][]string{},
		overLimit:    map[string]bool{},
		perHostLimit: 0,
		minTTL:       minTTL,
	}
	return c
}

// NewDNSCache returns an initialized DNSCache and set the max host limit to
// the given argument
func NewDNSCacheWithLimit(minTTL int, limit int) *DNSCache {
	c := NewDNSCache(minTTL)
	c.perHostLimit = limit
	return c
}

// Update inserts a new entry into the cache.
// After insertion cache entries for name are expired and redundant entries
// evicted. This is O(number of new IPs) for eviction, and O(number of IPs for
// name) for expiration.
// lookupTime is the time the DNS information began being valid. It should be
// in the past.
// name is used as is and may be an unqualified name (e.g. myservice.namespace).
// ips may be an IPv4 or IPv6 IP. Duplicates will be removed.
// ttl is the DNS TTL for ips and is a seconds value.
func (c *DNSCache) Update(lookupTime time.Time, name string, ips []net.IP, ttl int) bool {
	if c.minTTL > ttl {
		ttl = c.minTTL
	}

	entry := &cacheEntry{
		Name:           name,
		LookupTime:     lookupTime,
		ExpirationTime: lookupTime.Add(time.Duration(ttl) * time.Second),
		TTL:            ttl,
		IPs:            ips,
	}

	c.Lock()
	defer c.Unlock()
	return c.updateWithEntry(entry)
}

// updateWithEntry implements the insertion of a cacheEntry. It is used by
// DNSCache.Update and DNSCache.UpdateWithEntry.
// This needs a write lock
func (c *DNSCache) updateWithEntry(entry *cacheEntry) bool {
	changed := false
	entries, exists := c.forward[entry.Name]
	if !exists {
		changed = true
		entries = make(map[string]*cacheEntry)
		c.forward[entry.Name] = entries
	}

	if c.updateWithEntryIPs(entries, entry) {
		changed = true
	}

	if c.perHostLimit > 0 && len(entries) > c.perHostLimit {
		c.overLimit[entry.Name] = true
	}
	return changed
}

// AddNameToCleanup adds the IP with the given TTL to the the cleanup map to
// delete the entry from the policy when it expires.
// Need to be called with a write lock
func (c *DNSCache) addNameToCleanup(entry *cacheEntry) {
	if c.lastCleanup.Equal(time.Time{}) || entry.ExpirationTime.Before(c.lastCleanup) {
		c.lastCleanup = entry.ExpirationTime
	}
	expiration := entry.ExpirationTime.Unix()
	expiredEntries, exists := c.cleanup[expiration]
	if !exists {
		expiredEntries = []string{}
	}
	c.cleanup[expiration] = append(expiredEntries, entry.Name)
}

// cleanupExpiredEntries cleans all the expired entries since lastCleanup up to
// expires, but not including it. lastCleanup is set to expires and later
// cleanups begin from that time.
// It returns the list of names that have expired data.
func (c *DNSCache) cleanupExpiredEntries(expires time.Time) (affectedNames []string, removed map[string][]*cacheEntry) {
	if c.lastCleanup.Equal(time.Time{}) {
		return nil, nil
	}

	var toCleanNames []string
	for c.lastCleanup.Before(expires) {
		key := c.lastCleanup.Unix()
		if entries, exists := c.cleanup[key]; exists {
			toCleanNames = append(toCleanNames, entries...)
			delete(c.cleanup, key)
		}
		c.lastCleanup = c.lastCleanup.Add(time.Second).Truncate(time.Second)
	}

	removed = make(map[string][]*cacheEntry)
	for _, name := range KeepUniqueNames(toCleanNames) {
		if entries, exists := c.forward[name]; exists {
			affectedNames = append(affectedNames, name)
			for ip, entry := range c.removeExpired(entries, c.lastCleanup, time.Time{}) {
				affectedNames = append(affectedNames, name)
				removed[ip] = append(removed[ip], entry)
			}
		}
	}

	return KeepUniqueNames(affectedNames), removed
}

// cleanupOverLimitEntries returns the names that has reached the max number of
// IP per host. Internally the function sort the entries by the expiration
// time.
func (c *DNSCache) cleanupOverLimitEntries() (affectedNames []string, removed map[string][]*cacheEntry) {
	type IPEntry struct {
		ip    string
		entry *cacheEntry
	}
	removed = make(map[string][]*cacheEntry)

	// For global cache the limit maybe is not used at all.
	if c.perHostLimit == 0 {
		return affectedNames, nil
	}

	for dnsName := range c.overLimit {
		entries, ok := c.forward[dnsName]
		if !ok {
			continue
		}
		overlimit := len(entries) - c.perHostLimit
		if overlimit <= 0 {
			continue
		}
		sortedEntries := []IPEntry{}
		for ip, entry := range entries {
			sortedEntries = append(sortedEntries, IPEntry{ip, entry})
		}

		sort.Slice(sortedEntries, func(i, j int) bool {
			return sortedEntries[i].entry.ExpirationTime.Before(sortedEntries[j].entry.ExpirationTime)
		})

		for i := 0; i < overlimit; i++ {
			key := sortedEntries[i]
			delete(entries, key.ip)
			c.removeReverse(key.ip, key.entry)
			removed[key.ip] = append(removed[key.ip], key.entry)
		}
		affectedNames = append(affectedNames, dnsName)
	}
	c.overLimit = map[string]bool{}
	return affectedNames, removed
}

// GC cleans TTL expired entries up to now, and overlimit entries, returning
// both sets.
// If deferredDeletes is passed in, expired IPs are inserted into it. GC and
// other management of deferredDeletes is left to the caller.
func (c *DNSCache) GC(now time.Time, deferredDeletes *DNSPendingDeletes) (affectedNames []string) {
	c.Lock()
	expiredNames, expiredEntries := c.cleanupExpiredEntries(now)
	overLimitNames, overLimitEntries := c.cleanupOverLimitEntries()
	c.Unlock()

	if deferredDeletes != nil {
		// Iterate over 2 maps
		for _, m := range []map[string][]*cacheEntry{
			expiredEntries,
			overLimitEntries,
		} {
			for ipStr, entries := range m {
				for _, entry := range entries {
					deferredDeletes.WantToDelete(ipStr, entry.Name)
				}
			}
		}
	}

	return KeepUniqueNames(append(expiredNames, overLimitNames...))
}

// UpdateFromCache is a utility function that allows updating a DNSCache
// instance with all the internal entries of another. Latest-Expiration still
// applies, thus the merged outcome is consistent with adding the entries
// individually.
// When namesToUpdate has non-zero length only those names are updated from
// update, otherwise all DNS names in update are used.
func (c *DNSCache) UpdateFromCache(update *DNSCache, namesToUpdate []string) {
	if update == nil {
		return
	}

	c.Lock()
	defer c.Unlock()
	c.updateFromCache(update, namesToUpdate)
}

func (c *DNSCache) updateFromCache(update *DNSCache, namesToUpdate []string) {
	update.RLock()
	defer update.RUnlock()

	if len(namesToUpdate) == 0 {
		for name := range update.forward {
			namesToUpdate = append(namesToUpdate, name)
		}
	}
	for _, name := range namesToUpdate {
		newEntries, exists := update.forward[name]
		if !exists {
			continue
		}
		for _, newEntry := range newEntries {
			c.updateWithEntry(newEntry)
		}
	}
}

// ReplaceFromCacheByNames operates as an atomic combination of ForceExpire and
// multiple UpdateFromCache invocations. The result is to collect all entries
// for DNS names in namesToUpdate from each DNSCache in updates, replacing the
// current entries for each of those names.
func (c *DNSCache) ReplaceFromCacheByNames(namesToUpdate []string, updates ...*DNSCache) {
	c.Lock()
	defer c.Unlock()

	// Remove any DNS name in namesToUpdate with a lookup before "now". This
	// effectively deletes all lookups because we're holding the lock.
	c.forceExpireByNames(time.Now(), namesToUpdate)

	for _, update := range updates {
		c.updateFromCache(update, namesToUpdate)
	}
}

// Lookup returns a set of unique IPs that are currently unexpired for name, if
// any exist. An empty list indicates no valid records exist. The IPs are
// returned sorted.
func (c *DNSCache) Lookup(name string) (ips []net.IP) {
	c.RLock()
	defer c.RUnlock()

	return c.lookupByTime(c.lastCleanup, name)
}

// lookupByTime takes a timestamp for expiration comparisons, and is only
// intended for testing.
func (c *DNSCache) lookupByTime(now time.Time, name string) (ips []net.IP) {
	entries, found := c.forward[name]
	if !found {
		return nil
	}

	return entries.getIPs(now)
}

// LookupByRegexp returns all non-expired cache entries that match re as a map
// of name -> IPs
func (c *DNSCache) LookupByRegexp(re *regexp.Regexp) (matches map[string][]net.IP) {
	return c.lookupByRegexpByTime(c.lastCleanup, re)
}

// lookupByRegexpByTime takes a timestamp for expiration comparisons, and is
// only intended for testing.
func (c *DNSCache) lookupByRegexpByTime(now time.Time, re *regexp.Regexp) (matches map[string][]net.IP) {
	matches = make(map[string][]net.IP)

	c.RLock()
	defer c.RUnlock()

	for name, entry := range c.forward {
		if re.MatchString(name) {
			matches[name] = append(matches[name], entry.getIPs(now)...)
		}
	}

	return matches
}

// LookupIP returns all DNS names in entries that include that IP. The cache
// maintains the latest-expiring entry per-name per-IP. This means that multiple
// names referrring to the same IP will expire from the cache at different times,
// and only 1 entry for each name-IP pair is internally retained.
func (c *DNSCache) LookupIP(ip net.IP) (names []string) {
	c.RLock()
	defer c.RUnlock()

	return c.lookupIPByTime(c.lastCleanup, ip)
}

// lookupIPByTime takes a timestamp for expiration comparisons, and is
// only intended for testing.
func (c *DNSCache) lookupIPByTime(now time.Time, ip net.IP) (names []string) {
	ipKey := ip.String()
	cacheEntries, found := c.reverse[ipKey]
	if !found {
		return nil
	}

	for name, entry := range cacheEntries {
		if entry != nil && !entry.isExpiredBy(now) {
			names = append(names, name)
		}
	}

	sort.Strings(names)
	return names
}

// updateWithEntryIPs adds a mapping for every IP found in `entry` to `ipEntries`
// (which maps IP -> cacheEntry). It will replace existing IP->old mappings in
// `entries` if the current entry expires sooner (or has already expired).
// This needs a write lock
func (c *DNSCache) updateWithEntryIPs(entries ipEntries, entry *cacheEntry) bool {
	added := false
	for _, ip := range entry.IPs {
		ipStr := ip.String()
		old, exists := entries[ipStr]
		if old == nil || !exists || old.isExpiredBy(entry.ExpirationTime) {
			entries[ipStr] = entry
			c.upsertReverse(ipStr, entry)
			c.addNameToCleanup(entry)
			added = true
		}
	}
	return added

}

// removeExpired removes expired (or nil) cacheEntry pointers from entries, an
// ipEntries instance for a specific name. It returns a boolean if any entry is
// removed.
// now is the "current time" and entries with ExpirationTime before then are
// removed.
// expireLookupsBefore is an optional parameter. It causes any entry with a
// LookupTime before it to be expired. It is intended for use with cache
// clearing functions like ForceExpire, and does not maintain the cache's
// guarantees.
// This needs a write lock
func (c *DNSCache) removeExpired(entries ipEntries, now time.Time, expireLookupsBefore time.Time) (removed ipEntries) {
	removed = make(ipEntries)
	for ip, entry := range entries {
		if entry == nil || entry.isExpiredBy(now) || entry.LookupTime.Before(expireLookupsBefore) {
			delete(entries, ip)
			c.removeReverse(ip, entry)
			removed[ip] = entry
		}
	}

	return removed
}

// upsertReverse updates the reverse DNS cache for ip with entry, if it expires
// later than the already-stored entry.
// It is assumed that entry includes ip.
// This needs a write lock
func (c *DNSCache) upsertReverse(ip string, entry *cacheEntry) {
	entries, exists := c.reverse[ip]
	if entries == nil || !exists {
		entries = make(map[string]*cacheEntry)
		c.reverse[ip] = entries
	}
	entries[entry.Name] = entry
}

// removeReverse removes the reference between ip and the name stored in entry.
// When no more references from ip to any name exist, the map entry is deleted
// outright.
// It is assumed that entry includes ip.
// This needs a write lock
func (c *DNSCache) removeReverse(ip string, entry *cacheEntry) {
	entries, exists := c.reverse[ip]
	if entries == nil || !exists {
		return
	}
	delete(entries, entry.Name)
	if len(entries) == 0 {
		delete(c.reverse, ip)
	}
}

// ForceExpire is used to clear entries from the cache before their TTL is
// over. This operation does not keep previous guarantees that, for each IP,
// the most recent lookup to provide that IP is used.
// Note that all parameters must match, if provided. `time.Time{}` is
// considered not-provided for time parameters.
// expireLookupsBefore requires a lookup to have a LookupTime before it in
// order to remove it.
// nameMatch will remove any DNS names that match.
func (c *DNSCache) ForceExpire(expireLookupsBefore time.Time, nameMatch *regexp.Regexp) (namesAffected []string) {
	c.Lock()
	defer c.Unlock()

	for name, entries := range c.forward {
		// If nameMatch was passed in, we must match it. Otherwise, "match all".
		if nameMatch != nil && !nameMatch.MatchString(name) {
			continue
		}
		// We pass expireLookupsBefore as the `now` parameter but it is redundant
		// because LookupTime must be before ExpirationTime.
		// The second expireLookupsBefore actually matches lookup times, and will
		// delete the entries completely.
		for _, entry := range c.removeExpired(entries, expireLookupsBefore, expireLookupsBefore) {
			namesAffected = append(namesAffected, entry.Name)
		}
	}

	return KeepUniqueNames(namesAffected)
}

// ForceExpireByNames is the same function as ForceExpire but uses the exact
// names to delete the entries.
func (c *DNSCache) ForceExpireByNames(expireLookupsBefore time.Time, names []string) (namesAffected []string) {
	c.Lock()
	defer c.Unlock()

	return c.forceExpireByNames(expireLookupsBefore, names)
}

func (c *DNSCache) forceExpireByNames(expireLookupsBefore time.Time, names []string) (namesAffected []string) {
	for _, name := range names {
		entries, exists := c.forward[name]
		if !exists {
			continue
		}

		// We pass expireLookupsBefore as the `now` parameter but it is redundant
		// because LookupTime must be before ExpirationTime.
		// The second expireLookupsBefore actually matches lookup times, and will
		// delete the entries completely.
		for _, entry := range c.removeExpired(entries, expireLookupsBefore, expireLookupsBefore) {
			namesAffected = append(namesAffected, entry.Name)
		}
	}

	return namesAffected
}

// Dump returns unexpired cache entries in the cache. They are deduplicated,
// but not usefully sorted. These objects should not be modified.
func (c *DNSCache) Dump() (lookups []*cacheEntry) {
	c.RLock()
	defer c.RUnlock()

	// Collect all the still-valid entries
	lookups = make([]*cacheEntry, 0, len(c.forward))
	for _, entries := range c.forward {
		for _, entry := range entries {
			lookups = append(lookups, entry)
		}
	}

	// Dedup the entries. They are created once and are immutable so the address
	// is a unique identifier.
	// We iterate through the list, keeping unique pointers. This is correct
	// because the list is sorted and, if two consecutive entries are the same,
	// it is safe to overwrite the second duplicate.
	sort.Slice(lookups, func(i, j int) bool {
		return uintptr(unsafe.Pointer(lookups[i])) < uintptr(unsafe.Pointer(lookups[j]))
	})

	deduped := lookups[:0] // len==0 but cap==cap(lookups)
	for readIdx, lookup := range lookups {
		if readIdx == 0 || deduped[len(deduped)-1] != lookups[readIdx] {
			deduped = append(deduped, lookup)
		}
	}

	return deduped
}

// MarshalJSON serialises the set of DNS lookup cacheEntries needed to
// reconstruct this cache instance.
// Note: Expiration times are honored and the reconstructed cache instance is
// expected to return the same values as the original at that point in time.
func (c *DNSCache) MarshalJSON() ([]byte, error) {
	lookups := c.Dump()

	// serialise into a JSON object array
	return json.Marshal(lookups)
}

// UnmarshalJSON rebuilds a DNSCache from serialized JSON.
// Note: This is destructive to any currect data. Use UpdateFromCache for bulk
// updates.
func (c *DNSCache) UnmarshalJSON(raw []byte) error {
	lookups := make([]*cacheEntry, 0)
	if err := json.Unmarshal(raw, &lookups); err != nil {
		return err
	}

	c.Lock()
	defer c.Unlock()

	c.forward = make(map[string]ipEntries)
	c.reverse = make(map[string]nameEntries)

	for _, newLookup := range lookups {
		c.updateWithEntry(newLookup)
	}

	return nil
}

// DNSPendingDelete is an IP that has expired or been evicted from a DNS cache.
// It records the DNS name and IP, along with other bookkeeping timestamps that
// help determine when it can be finally deleted. Entries are deletable when
// they are not marked active by CT GC.
type DNSPendingDelete struct {
	Names           []string  `json:"names,omitempty"`
	IP              net.IP    `json:"ip,omitempty"`
	ActiveAt        time.Time `json:"active-at,omitempty"`
	DeletePendingAt time.Time `json:"delete-pending-at,omitempty"`
}

// DNSPendingDeletes collects DNS Name->IP mappings that may be deletable. They
// are marked active, periodically, by the CT GC goroutine. When .GC is called,
// active and deletable entries are returned, allowing us to skip deleting an IP
// from the global DNS cache to avoid breaking connections that outlast the DNS
// TTL.
type DNSPendingDeletes struct {
	lock.Mutex
	deletes        map[string]*DNSPendingDelete // map[ip]toDelete
	lastCTGCUpdate time.Time
}

// NewDNSPendingDeletes constructs a DNSPendingDeletes that is read to use
func NewDNSPendingDeletes() *DNSPendingDeletes {
	return &DNSPendingDeletes{
		deletes: make(map[string]*DNSPendingDelete),
	}
}

// WantToDelete enqueues the ip -> qname as a possible deletion
// updatedExisting is true when an earlier enqueue existed and was updated
func (d *DNSPendingDeletes) WantToDelete(ipStr string, qname ...string) (updatedExisting bool) {
	d.Lock()
	defer d.Unlock()

	entry, updatedExisting := d.deletes[ipStr]
	if !updatedExisting {
		entry = &DNSPendingDelete{}
		d.deletes[ipStr] = entry
	}

	entry.Names = append(entry.Names, qname...)
	entry.IP = net.ParseIP(ipStr)
	entry.DeletePendingAt = time.Now()

	return updatedExisting
}

// Delete after it is seen by CT GC, DeletePendingAt < lastCTGCUpdate, and the ActiveTime is 0 or no longer current, ActiveAt < lastCTGCUpdate
func (d *DNSPendingDeletes) canDelete(del *DNSPendingDelete) bool {
	return d.lastCTGCUpdate.After(del.DeletePendingAt) && d.lastCTGCUpdate.After(del.ActiveAt)
}

// GC returns active and deletable DNSPendingDelete entries. This removes
// deletable entries interally, and repeated calls will return different data.
// Entries are active if they have been marked active (with MarkActive). When
// SetCTGCTime is called and an entry not marked active, it become deletable.
// Calling WantToDelete on a deletable entry will make it active again.
func (d *DNSPendingDeletes) GC() (active, deletable []*DNSPendingDelete) {
	d.Lock()
	defer d.Unlock()

	// Collect entries we can delete
perIP:
	for _, del := range d.deletes {
		cpy := &DNSPendingDelete{
			IP:              del.IP,
			DeletePendingAt: del.DeletePendingAt,
			ActiveAt:        del.ActiveAt,
		}
		cpy.Names = append(cpy.Names, del.Names...)

		if !d.canDelete(cpy) {
			active = append(active, cpy)
			continue perIP
		}
		deletable = append(deletable, cpy)
	}

	// Delete the entries we collected above
	for _, del := range deletable {
		delete(d.deletes, del.IP.String())
	}

	return active, deletable
}

// MarkActive makes an entry active and not deletable. When now is after the
// time set with SetCTGCTime the entry remains active.
func (d *DNSPendingDeletes) MarkActive(ip net.IP, now time.Time) {
	d.Lock()
	defer d.Unlock()

	entry, exists := d.deletes[ip.String()]
	if !exists {
		return
	}
	entry.ActiveAt = now
}

// SetCTGCTime marks the start of the most recent CT GC. This must be set after
// all MarkActive calls complete to avoid races. When now is later than an
// active timestamp set with MarkActive the entry is no longer active. Thus,
// this call acts as a gating function for what data is returned by GC.
func (d *DNSPendingDeletes) SetCTGCTime(now time.Time) {
	d.lastCTGCUpdate = now
}

// ForceExpire is used to clear entries irrespective of their active status (or
// them being updated at all). Only entries with DeletePendingAt times before
// expireLookupBefore are considered. Each name in an entry is matched against
// nameMatcher (nil is match all) and when an entry no longer has any valid
// names will it be removed outright.
// Note that all parameters must match, if provided. `time.Time{}` is
// considered not-provided for time parameters.
// expireLookupsBefore requires an entry to have been enqueued before the
// specified time in order to remove it.
// nameMatch will remove any DNS names that match.
func (d *DNSPendingDeletes) ForceExpire(expireLookupsBefore time.Time, nameMatch *regexp.Regexp) (namesAffected []string) {
	d.Lock()
	defer d.Unlock()

	var toDelete []*DNSPendingDelete

	for _, entry := range d.deletes {
		// Do not expire entries that were enqueued after expireLookupsBefore, but
		// only if the value is non-zero
		if !expireLookupsBefore.Equal(time.Time{}) && entry.DeletePendingAt.After(expireLookupsBefore) {
			continue
		}

		// An entry has multiple names, collect the ones that should remain (i.e.
		// do not match nameMatch)
		var newNames []string
		for _, name := range entry.Names {
			if nameMatch != nil && !nameMatch.MatchString(name) {
				newNames = append(newNames, name)
			} else {
				namesAffected = append(namesAffected, name)
			}
		}
		entry.Names = newNames

		// Delete the entry outright if no names remain
		if len(entry.Names) == 0 {
			toDelete = append(toDelete, entry)
		}
	}

	// Delete the entries that are now empty
	for _, entry := range toDelete {
		delete(d.deletes, entry.IP.String())
	}

	return namesAffected
}

// DumpActive returns copies of still-active delete entries
func (d *DNSPendingDeletes) DumpActive() (active []*DNSPendingDelete) {
	d.Lock()
	defer d.Unlock()

	for _, del := range d.deletes {
		if d.canDelete(del) {
			continue
		}

		cpy := &DNSPendingDelete{
			IP:              del.IP,
			DeletePendingAt: del.DeletePendingAt,
			ActiveAt:        del.ActiveAt,
		}
		cpy.Names = append(cpy.Names, del.Names...)

		active = append(active, cpy)
	}

	return active
}

// MarshalJSON encodes DNSPendingDeletes into JSON. Only the DNSPendingDelete
// entries are encoded.
func (d *DNSPendingDeletes) MarshalJSON() ([]byte, error) {
	aux := struct {
		Deletes map[string]*DNSPendingDelete `json:"deletes,omitempty"`
	}{
		Deletes: d.deletes,
	}

	return json.Marshal(aux)
}

// UnmarshalJSON rebuilds a DNSPendingDeletes from serialized JSON. It resets
// the ActiveAt timestamps, requiring a CT GC cycle to occur before any entries
// are deleted (by not being marked active).
// Note: This is destructive to any currect data
func (d *DNSPendingDeletes) UnmarshalJSON(raw []byte) error {
	d.Lock()
	defer d.Unlock()

	aux := struct {
		Deletes map[string]*DNSPendingDelete `json:"deletes,omitempty"`
	}{
		Deletes: d.deletes,
	}
	if err := json.Unmarshal(raw, &aux); err != nil {
		return err
	}
	d.deletes = aux.Deletes

	// Reset the active time to ensure no deletes happen until we run CT GC again
	for _, del := range d.deletes {
		del.ActiveAt = time.Time{}
	}
	return nil
}
