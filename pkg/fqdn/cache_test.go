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
	"fmt"
	"math/rand"
	"net"
	"sort"
	"time"

	. "gopkg.in/check.v1"
)

type DNSCacheTestSuite struct{}

var _ = Suite(&DNSCacheTestSuite{})

func sortByName(entries []*cacheEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
}

// TestUpdateLookup tests that we can insert DNS data and retrieve it. We
// iterate through time, ensuring that data is expired as appropriate. We also
// insert redundant DNS entries that should not change the output.
func (ds *DNSCacheTestSuite) TestUpdateLookup(c *C) {
	name := "test.com"
	now := time.Now()
	cache := NewDNSCache()
	endTimeSeconds := 4

	// Add 1 new entry "per second", and one with a redundant IP (with ttl/2).
	// The IP reflects the second in which it will expire, and should show up for
	// all now+ttl that is less than it.
	for i := 1; i <= endTimeSeconds; i++ {
		ttl := i
		cache.Update(now,
			name,
			[]net.IP{net.ParseIP(fmt.Sprintf("1.1.1.%d", i)), net.ParseIP(fmt.Sprintf("2.2.2.%d", i))},
			ttl)

		cache.Update(now,
			name,
			[]net.IP{net.ParseIP(fmt.Sprintf("1.1.1.%d", i))},
			ttl/2)
	}

	// lookup our entries
	//  - no redundant entries (the 1.1.1.x is not repeated)
	//  - with each step of secondsPastNow, fewer entries are returned
	for secondsPastNow := 1; secondsPastNow <= endTimeSeconds; secondsPastNow++ {
		ips := cache.lookupByTime(now.Add(time.Duration(secondsPastNow)*time.Second), name)
		c.Assert(len(ips), Equals, 2*(endTimeSeconds-secondsPastNow+1), Commentf("Incorrect number of IPs returned"))

		// Check that we returned each 1.1.1.x entry where x={1..endTimeSeconds}
		// These are sorted, and are in the first half of the array
		// Similarly, check the 2.2.2.x entries in the second half of the array
		j := secondsPastNow
		halfIndex := endTimeSeconds - secondsPastNow + 1
		for _, ip := range ips[:halfIndex] {
			c.Assert(ip.String(), Equals, fmt.Sprintf("1.1.1.%d", j), Commentf("Incorrect IP returned (j=%d, secondsPastNow=%d)", j, secondsPastNow))
			j++
		}
		j = secondsPastNow
		for _, ip := range ips[halfIndex:] {
			c.Assert(ip.String(), Equals, fmt.Sprintf("2.2.2.%d", j), Commentf("Incorrect IP returned (j=%d, secondsPastNow=%d)", j, secondsPastNow))
			j++
		}

	}
}

func (ds *DNSCacheTestSuite) TestReverseUpdateLookup(c *C) {
	names := map[string]net.IP{
		"test1.com": net.ParseIP("2.2.2.1"),
		"test2.com": net.ParseIP("2.2.2.2"),
		"test3.com": net.ParseIP("2.2.2.3")}
	sharedIP := net.ParseIP("1.1.1.1")
	now := time.Now()
	cache := NewDNSCache()

	// insert 2 records, with 1 shared IP
	cache.Update(now, "test1.com", []net.IP{sharedIP, names["test1.com"]}, 2)
	cache.Update(now, "test2.com", []net.IP{sharedIP, names["test2.com"]}, 4)

	// lookup within the TTL for both names should return 2 names for sharedIPs,
	// and one name for the 2.2.2.* IPs
	currentTime := now.Add(time.Second)
	lookupNames := cache.lookupIPByTime(currentTime, sharedIP)
	c.Assert(len(lookupNames), Equals, 2, Commentf("Incorrect number of names returned"))
	for _, name := range lookupNames {
		_, found := names[name]
		c.Assert(found, Equals, true, Commentf("Returned a DNS name that doesn't match IP"))
	}

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	c.Assert(len(lookupNames), Equals, 1, Commentf("Incorrect number of names returned"))
	c.Assert(lookupNames[0], Equals, "test1.com", Commentf("Returned a DNS name that doesn't match IP"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	c.Assert(len(lookupNames), Equals, 1, Commentf("Incorrect number of names returned"))
	c.Assert(lookupNames[0], Equals, "test2.com", Commentf("Returned a DNS name that doesn't match IP"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Returned names for IP not in cache"))

	// lookup between 2-4 seconds later (test1.com has expired) for both names
	// should return 2 names for sharedIPs, and one name for the 2.2.2.* IPs
	currentTime = now.Add(3 * time.Second)
	lookupNames = cache.lookupIPByTime(currentTime, sharedIP)
	c.Assert(len(lookupNames), Equals, 1, Commentf("Incorrect number of names returned"))
	c.Assert(lookupNames[0], Equals, "test2.com", Commentf("Returned a DNS name that doesn't match IP"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Incorrect number of names returned"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	c.Assert(len(lookupNames), Equals, 1, Commentf("Incorrect number of names returned"))
	c.Assert(lookupNames[0], Equals, "test2.com", Commentf("Returned a DNS name that doesn't match IP"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Returned names for IP not in cache"))

	// lookup between after 4 seconds later (all have expired) for both names
	// should return no names in all cases.
	currentTime = now.Add(5 * time.Second)
	lookupNames = cache.lookupIPByTime(currentTime, sharedIP)
	c.Assert(len(lookupNames), Equals, 0, Commentf("Incorrect number of names returned"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Incorrect number of names returned"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Incorrect number of names returned"))

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	c.Assert(len(lookupNames), Equals, 0, Commentf("Returned names for IP not in cache"))
}

/* Benchmarks
 * These are here to help gauge the relative costs of operations in DNSCache.
 * Note: some are on arrays `size` elements, so the benchmark "op time" is too
 * large.
 */

var (
	now         = time.Now()
	size        = 1000 // size of array to operate on
	entriesOrig = makeEntries(now, 1+size/3, 1+size/3, 1+size/3)
	ipsOrig     = func() []net.IP {
		ips := make([]net.IP, 0, size)
		for i := 0; i < size; i++ {
			ips = append(ips, net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i>>0)))
		}
		return ips
	}()
)

func makeEntries(now time.Time, live, redundant, expired int) (entries []*cacheEntry) {
	liveTTL := 120
	redundantTTL := 60

	for ; live > 0; live-- {
		ip := net.IPv4(byte(live>>24), byte(live>>16), byte(live>>8), byte(live>>0))

		entries = append(entries, &cacheEntry{
			Name:           fmt.Sprintf("live-%s", ip.String()),
			LookupTime:     now,
			ExpirationTime: now.Add(time.Duration(liveTTL) * time.Second),
			TTL:            liveTTL,
			IPs:            []net.IP{ip}})

		if redundant > 0 {
			redundant--
			entries = append(entries, &cacheEntry{
				Name:           fmt.Sprintf("redundant-%s", ip.String()),
				LookupTime:     now,
				ExpirationTime: now.Add(time.Duration(redundantTTL) * time.Second),
				TTL:            redundantTTL,
				IPs:            []net.IP{ip}})
		}

		if expired > 0 {
			expired--
			entries = append(entries, &cacheEntry{
				Name:           fmt.Sprintf("expired-%s", ip.String()),
				LookupTime:     now.Add(-time.Duration(liveTTL) * time.Second),
				ExpirationTime: now.Add(-time.Second),
				TTL:            liveTTL,
				IPs:            []net.IP{ip}})
		}
	}

	rand.Shuffle(len(entries), func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})

	return entries
}

// Note: each "op" works on size things
func (ds *DNSCacheTestSuite) BenchmarkGetIPs(c *C) {
	c.StopTimer()
	now := time.Now()
	cache := NewDNSCache()
	cache.Update(now, "test.com", []net.IP{net.ParseIP("1.2.3.4")}, 60)
	entries := cache.forward["test.com"]
	for _, entry := range entriesOrig {
		cache.updateWithEntryIPs(entries, entry)
	}
	c.StartTimer()

	for i := 0; i < c.N; i++ {
		entries.getIPs(now)
	}
}

// Note: each "op" works on size things
func (ds *DNSCacheTestSuite) BenchmarkUpdateIPs(c *C) {
	for i := 0; i < c.N; i++ {
		c.StopTimer()
		now := time.Now()
		cache := NewDNSCache()
		cache.Update(now, "test.com", []net.IP{net.ParseIP("1.2.3.4")}, 60)
		entries := cache.forward["test.com"]
		c.StartTimer()

		for _, entry := range entriesOrig {
			cache.updateWithEntryIPs(entries, entry)
			cache.removeExpired(entries, now)
		}
	}
}

func (ds *DNSCacheTestSuite) BenchmarkIPString(c *C) {
	for i := 0; i < c.N; i++ {
		_ = net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i>>0)).String()
	}
}

func (ds *DNSCacheTestSuite) BenchmarkParseIPSimple(c *C) {
	ip := ipsOrig[0].String()
	for i := 0; i < c.N; i++ {
		_ = net.ParseIP(ip)
	}
}

// Note: each "op" works on size things
func (ds *DNSCacheTestSuite) BenchmarkParseIP(c *C) {
	c.StopTimer()
	ips := make([]string, 0, len(ipsOrig))
	for _, ip := range ipsOrig {
		ips = append(ips, ip.String())
	}
	c.StartTimer()

	for i := 0; i < c.N; i++ {
		for _, ipStr := range ips {
			_ = net.ParseIP(ipStr)
		}
	}
}
