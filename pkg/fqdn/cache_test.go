// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ip"
)

// TestUpdateLookup tests that we can insert DNS data and retrieve it. We
// iterate through time, ensuring that data is expired as appropriate. We also
// insert redundant DNS entries that should not change the output.
func TestUpdateLookup(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	name := "test.com"
	now := time.Now()
	cache := NewDNSCache(0)
	endTimeSeconds := 4

	// Add 1 new entry "per second", and one with a redundant IP (with ttl/2).
	// The IP reflects the second in which it will expire, and should show up for
	// all now+ttl that is less than it.
	for i := 1; i <= endTimeSeconds; i++ {
		ttl := i
		cache.Update(now,
			name,
			[]netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i)), netip.MustParseAddr(fmt.Sprintf("2.2.2.%d", i))},
			ttl)

		cache.Update(now,
			name,
			[]netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))},
			ttl/2)
	}

	// lookup our entries
	//  - no redundant entries (the 1.1.1.x is not repeated)
	//  - with each step of secondsPastNow, fewer entries are returned
	for secondsPastNow := 1; secondsPastNow <= endTimeSeconds; secondsPastNow++ {
		ips := cache.lookupByTime(now.Add(time.Duration(secondsPastNow)*time.Second), name)
		require.Len(t, ips, 2*(endTimeSeconds-secondsPastNow+1), "Incorrect number of IPs returned")

		// This test expects ips sorted
		ip.SortAddrList(ips)

		// Check that we returned each 1.1.1.x entry where x={1..endTimeSeconds}
		// These are sorted, and are in the first half of the array
		// Similarly, check the 2.2.2.x entries in the second half of the array
		j := secondsPastNow
		halfIndex := endTimeSeconds - secondsPastNow + 1
		for _, ip := range ips[:halfIndex] {
			require.Equalf(t, fmt.Sprintf("1.1.1.%d", j), ip.String(), "Incorrect IP returned (j=%d, secondsPastNow=%d)", j, secondsPastNow)
			j++
		}
		j = secondsPastNow
		for _, ip := range ips[halfIndex:] {
			require.Equalf(t, fmt.Sprintf("2.2.2.%d", j), ip.String(), "Incorrect IP returned (j=%d, secondsPastNow=%d)", j, secondsPastNow)
			j++
		}
	}
}

// TestDelete tests that we can forcibly clear parts of the cache.
func TestDelete(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	names := map[string]netip.Addr{
		"test1.com": netip.MustParseAddr("2.2.2.1"),
		"test2.com": netip.MustParseAddr("2.2.2.2"),
		"test3.com": netip.MustParseAddr("2.2.2.3")}
	sharedIP := netip.MustParseAddr("1.1.1.1")
	now := time.Now()
	cache := NewDNSCache(0)

	// Insert 3 records with 1 shared IP and 3 with different IPs
	cache.Update(now, "test1.com", []netip.Addr{sharedIP, names["test1.com"]}, 5)
	cache.Update(now, "test2.com", []netip.Addr{sharedIP, names["test2.com"]}, 5)
	cache.Update(now, "test3.com", []netip.Addr{sharedIP, names["test3.com"]}, 5)

	now = now.Add(time.Second)

	// Test that a non-matching ForceExpire doesn't do anything. All data should
	// still be present.
	nameMatch, err := regexp.Compile("^notatest.com$")
	require.NoError(t, err)
	namesAffected := cache.ForceExpire(now, nameMatch)
	require.Emptyf(t, namesAffected, "Incorrect count of names removed %v", namesAffected)
	for _, name := range []string{"test1.com", "test2.com", "test3.com"} {
		ips := cache.lookupByTime(now, name)
		require.Lenf(t, ips, 2, "Wrong count of IPs returned (%v) for non-deleted name '%s'", ips, name)
		require.Containsf(t, cache.forward, name, "Expired name '%s' not deleted from forward", name)
		for _, ip := range ips {
			require.Containsf(t, cache.reverse, ip, "Expired IP '%s' not deleted from reverse", ip)
		}
	}

	// Delete a single name and check that
	// - It is returned in namesAffected
	// - Lookups for it show no data, but data remains for other names
	nameMatch, err = regexp.Compile("^test1.com$")
	require.NoError(t, err)
	namesAffected = cache.ForceExpire(now, nameMatch)
	require.Lenf(t, namesAffected, 1, "Incorrect count of names removed %v", namesAffected)
	require.Containsf(t, namesAffected, "test1.com", "Incorrect affected name returned on forced expire: %s", namesAffected)
	ips := cache.lookupByTime(now, "test1.com")
	require.Emptyf(t, ips, "IPs returned (%v) for deleted name 'test1.com'", ips)
	require.NotContains(t, cache.forward, "test1.com", "Expired name 'test1.com' not deleted from forward")
	for _, ip := range ips {
		require.Containsf(t, cache.reverse, ip, "Expired IP '%s' not deleted from reverse", ip)
	}
	for _, name := range []string{"test2.com", "test3.com"} {
		ips = cache.lookupByTime(now, name)
		require.Lenf(t, ips, 2, "Wrong count of IPs returned (%v) for non-deleted name '%s'", ips, name)
		require.Containsf(t, cache.forward, name, "Expired name '%s' not deleted from forward", name)
		for _, ip := range ips {
			require.Containsf(t, cache.reverse, ip, "Expired IP '%s' not deleted from reverse", ip)
		}
	}

	// Delete the whole cache. This should leave no data.
	namesAffected = cache.ForceExpire(now, nil)
	require.Lenf(t, namesAffected, 2, "Incorrect count of names removed %v", namesAffected)
	for _, name := range []string{"test2.com", "test3.com"} {
		require.Contains(t, namesAffected, name, "Incorrect affected name returned on forced expire")
	}
	for name := range names {
		ips = cache.lookupByTime(now, name)
		require.Emptyf(t, ips, "Returned IP data for %s after the cache was fully cleared: %v", name, ips)
	}
	require.Empty(t, cache.forward)
	require.Empty(t, cache.reverse)
	dump := cache.Dump()
	require.Emptyf(t, dump, "Returned cache entries from cache dump after the cache was fully cleared: %v", dump)
}

func Test_forceExpiredByNames(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	names := []string{"test1.com", "test2.com"}
	cache := NewDNSCache(0)
	for i := 1; i < 4; i++ {
		cache.Update(
			now,
			fmt.Sprintf("test%d.com", i),
			[]netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))},
			5)
	}

	require.Len(t, cache.forward, 3)
	cache.forceExpireByNames(time.Now(), names)
	require.NotNil(t, cache.forward["test3.com"])
}

func TestReverseUpdateLookup(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	names := map[string]netip.Addr{
		"test1.com": netip.MustParseAddr("2.2.2.1"),
		"test2.com": netip.MustParseAddr("2.2.2.2"),
		"test3.com": netip.MustParseAddr("2.2.2.3")}
	sharedIP := netip.MustParseAddr("1.1.1.1")
	now := time.Now()
	cache := NewDNSCache(0)

	// insert 2 records, with 1 shared IP
	cache.Update(now, "test1.com", []netip.Addr{sharedIP, names["test1.com"]}, 2)
	cache.Update(now, "test2.com", []netip.Addr{sharedIP, names["test2.com"]}, 4)

	// lookup within the TTL for both names should return 2 names for sharedIPs,
	// and one name for the 2.2.2.* IPs
	currentTime := now.Add(time.Second)
	lookupNames := cache.lookupIPByTime(currentTime, sharedIP)
	require.Len(t, lookupNames, 2, "Incorrect number of names returned")
	for _, name := range lookupNames {
		_, found := names[name]
		require.True(t, found, "Returned a DNS name that doesn't match IP")
	}

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	require.Len(t, lookupNames, 1, "Incorrect number of names returned")
	require.Equal(t, "test1.com", lookupNames[0], "Returned a DNS name that doesn't match IP")

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	require.Len(t, lookupNames, 1, "Incorrect number of names returned")
	require.Equal(t, "test2.com", lookupNames[0], "Returned a DNS name that doesn't match IP")

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	require.Empty(t, lookupNames, "Returned names for IP not in cache")

	// lookup between 2-4 seconds later (test1.com has expired) for both names
	// should return 2 names for sharedIPs, and one name for the 2.2.2.* IPs
	currentTime = now.Add(3 * time.Second)
	lookupNames = cache.lookupIPByTime(currentTime, sharedIP)
	require.Len(t, lookupNames, 1, "Incorrect number of names returned")
	require.Equal(t, "test2.com", lookupNames[0], "Returned a DNS name that doesn't match IP")

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	require.Empty(t, lookupNames, "Incorrect number of names returned")

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	require.Len(t, lookupNames, 1, "Incorrect number of names returned")
	require.Equal(t, "test2.com", lookupNames[0], "Returned a DNS name that doesn't match IP")

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	require.Empty(t, lookupNames, "Returned names for IP not in cache")

	// lookup between after 4 seconds later (all have expired) for both names
	// should return no names in all cases.
	currentTime = now.Add(5 * time.Second)
	lookupNames = cache.lookupIPByTime(currentTime, sharedIP)
	require.Empty(t, lookupNames, "Incorrect number of names returned")

	lookupNames = cache.lookupIPByTime(currentTime, names["test1.com"])
	require.Empty(t, lookupNames, "Incorrect number of names returned")

	lookupNames = cache.lookupIPByTime(currentTime, names["test2.com"])
	require.Empty(t, lookupNames, "Incorrect number of names returned")

	lookupNames = cache.lookupIPByTime(currentTime, names["test3.com"])
	require.Empty(t, lookupNames, "Returned names for IP not in cache")
}

func TestJSONMarshal(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	names := map[string]netip.Addr{
		"test1.com": netip.MustParseAddr("2.2.2.1"),
		"test2.com": netip.MustParseAddr("2.2.2.2"),
		"test3.com": netip.MustParseAddr("2.2.2.3")}
	sharedIP := netip.MustParseAddr("1.1.1.1")
	now := time.Now()
	cache := NewDNSCache(0)

	// insert 3 records with 1 shared IP and 3 with different IPs
	cache.Update(now, "test1.com", []netip.Addr{sharedIP}, 5)
	cache.Update(now, "test2.com", []netip.Addr{sharedIP}, 5)
	cache.Update(now, "test3.com", []netip.Addr{sharedIP}, 5)
	cache.Update(now, "test1.com", []netip.Addr{names["test1.com"]}, 5)
	cache.Update(now, "test2.com", []netip.Addr{names["test2.com"]}, 5)
	cache.Update(now, "test3.com", []netip.Addr{names["test3.com"]}, 5)

	// Marshal and unmarshal
	data, err := cache.MarshalJSON()
	require.NoError(t, err)

	newCache := NewDNSCache(0)
	err = newCache.UnmarshalJSON(data)
	require.NoError(t, err)

	// Marshalled data should have no duplicate entries Note: this is tightly
	// coupled with the implementation of DNSCache.MarshalJSON because the
	// unmarshalled instance will hide duplicates. We simply check the length
	// since we control the inserted data, and we test its correctness below.
	rawList := make([]*cacheEntry, 0)
	err = json.Unmarshal(data, &rawList)
	require.NoError(t, err)
	require.Len(t, rawList, 6)

	// Check that the unmarshalled instance contains all the data at now
	currentTime := now
	for name := range names {
		IPs := cache.lookupByTime(currentTime, name)
		ip.SortAddrList(IPs)
		require.Lenf(t, IPs, 2, "Incorrect number of IPs returned for %s", name)
		require.Equalf(t, sharedIP.String(), IPs[0].String(), "Returned an IP that doesn't match %s", name)
		require.Equalf(t, names[name].String(), IPs[1].String(), "Returned an IP name that doesn't match %s", name)
	}

	// Check that the unmarshalled data expires correctly
	currentTime = now.Add(10 * time.Second)
	for name := range names {
		IPs := cache.lookupByTime(currentTime, name)
		require.Empty(t, IPs, "Returned IPs that should be expired for %s", name)
	}
}

func TestCountIPs(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	names := map[string]netip.Addr{
		"test1.com": netip.MustParseAddr("1.1.1.1"),
		"test2.com": netip.MustParseAddr("2.2.2.2"),
		"test3.com": netip.MustParseAddr("3.3.3.3")}
	sharedIP := netip.MustParseAddr("8.8.8.8")
	cache := NewDNSCache(0)

	// Insert 3 records all sharing one IP and 1 unique IP.
	cache.Update(now, "test1.com", []netip.Addr{sharedIP, names["test1.com"]}, 5)
	cache.Update(now, "test2.com", []netip.Addr{sharedIP, names["test2.com"]}, 5)
	cache.Update(now, "test3.com", []netip.Addr{sharedIP, names["test3.com"]}, 5)

	fqdns, ips := cache.Count()

	// Dump() returns the deduplicated (or consolidated) list of entries with
	// length equal to CountFQDNs(), while CountIPs() returns the raw number of
	// IPs.
	require.Len(t, cache.Dump(), len(names))
	require.Equal(t, len(names), int(fqdns))
	require.Equal(t, len(names)*2, int(ips))
}

/* Benchmarks
 * These are here to help gauge the relative costs of operations in DNSCache.
 * Note: some are on arrays `size` elements, so the benchmark "op time" is too
 * large.
 */

var (
	now         = time.Now()
	size        = uint32(1000) // size of array to operate on
	entriesOrig = makeEntries(now, 1+size/3, 1+size/3, 1+size/3)
)

// makeIPs generates count sequential IPv4 IPs
func makeIPs(count uint32) []netip.Addr {
	ips := make([]netip.Addr, 0, count)
	for i := uint32(0); i < count; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i >> 0)}))
	}
	return ips
}

func makeEntries(now time.Time, live, redundant, expired uint32) (entries []*cacheEntry) {
	liveTTL := 120
	redundantTTL := 60

	for ; live > 0; live-- {
		ip := netip.AddrFrom4([4]byte{byte(live >> 24), byte(live >> 16), byte(live >> 8), byte(live >> 0)})

		entries = append(entries, &cacheEntry{
			Name:           fmt.Sprintf("live-%s", ip.String()),
			LookupTime:     now,
			ExpirationTime: now.Add(time.Duration(liveTTL) * time.Second),
			TTL:            liveTTL,
			IPs:            []netip.Addr{ip}})

		if redundant > 0 {
			redundant--
			entries = append(entries, &cacheEntry{
				Name:           fmt.Sprintf("redundant-%s", ip.String()),
				LookupTime:     now,
				ExpirationTime: now.Add(time.Duration(redundantTTL) * time.Second),
				TTL:            redundantTTL,
				IPs:            []netip.Addr{ip}})
		}

		if expired > 0 {
			expired--
			entries = append(entries, &cacheEntry{
				Name:           fmt.Sprintf("expired-%s", ip.String()),
				LookupTime:     now.Add(-time.Duration(liveTTL) * time.Second),
				ExpirationTime: now.Add(-time.Second),
				TTL:            liveTTL,
				IPs:            []netip.Addr{ip}})
		}
	}

	rand.Shuffle(len(entries), func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})

	return entries
}

// Note: each "op" works on size things
func BenchmarkGetIPs(b *testing.B) {
	logger := hivetest.Logger(b)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	cache := NewDNSCache(0)
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60)
	entries := cache.forward["test.com"]
	for _, entry := range entriesOrig {
		cache.updateWithEntryIPs(entries, entry)
	}

	for b.Loop() {
		entries.getIPs(now)
	}
}

// Note: each "op" works on size things
func BenchmarkUpdateIPs(b *testing.B) {
	logger := hivetest.Logger(b)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	for b.Loop() {
		b.StopTimer()
		now := time.Now()
		cache := NewDNSCache(0)
		cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 60)
		entries := cache.forward["test.com"]
		b.StartTimer()

		for _, entry := range entriesOrig {
			cache.updateWithEntryIPs(entries, entry)
			cache.removeExpired(entries, now, time.Time{})
		}
	}
}

// JSON Marshal/Unmarshal benchmarks
var numIPsPerEntry = 10 // number of IPs to generate in each entry

func BenchmarkMarshalJSON10(b *testing.B)    { benchmarkMarshalJSON(b, 10) }
func BenchmarkMarshalJSON100(b *testing.B)   { benchmarkMarshalJSON(b, 100) }
func BenchmarkMarshalJSON1000(b *testing.B)  { benchmarkMarshalJSON(b, 1000) }
func BenchmarkMarshalJSON10000(b *testing.B) { benchmarkMarshalJSON(b, 10000) }

func BenchmarkUnmarshalJSON10(b *testing.B)  { benchmarkUnmarshalJSON(b, 10) }
func BenchmarkUnmarshalJSON100(b *testing.B) { benchmarkUnmarshalJSON(b, 100) }
func BenchmarkUnmarshalJSON1000(b *testing.B) {
	benchmarkUnmarshalJSON(b, 1000)
}
func BenchmarkUnmarshalJSON10000(b *testing.B) {
	benchmarkUnmarshalJSON(b, 10000)
}

// BenchmarkMarshalJSON100Repeat2 tests whether repeating the whole
// serialization is notably slower than a single run.
func BenchmarkMarshalJSON100Repeat2(b *testing.B) {
	benchmarkMarshalJSON(b, 50)
	benchmarkMarshalJSON(b, 50)
}

func BenchmarkMarshalJSON1000Repeat2(b *testing.B) {
	benchmarkMarshalJSON(b, 500)
	benchmarkMarshalJSON(b, 500)
}

// benchmarkMarshalJSON benchmarks the cost of creating a json representation
// of DNSCache. Each benchmark "op" is on numDNSEntries.
// Note: It assumes the JSON only uses data in DNSCache.forward when generating
// the data. Changes to the implementation need to also change this benchmark.
func benchmarkMarshalJSON(b *testing.B, numDNSEntries int) {
	logger := hivetest.Logger(b)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	ips := makeIPs(uint32(numIPsPerEntry))

	cache := NewDNSCache(0)
	for i := range numDNSEntries {
		// TTL needs to be far enough in the future that the entry is serialized
		cache.Update(time.Now(), fmt.Sprintf("domain-%v.com", i), ips, 86400)
	}

	for b.Loop() {
		_, err := cache.MarshalJSON()
		require.NoError(b, err)
	}
}

// benchmarkUnmarshalJSON benchmarks the cost of parsing a json representation
// of DNSCache. Each benchmark "op" is on numDNSEntries.
// Note: It assumes the JSON only uses data in DNSCache.forward when generating
// the data. Changes to the implementation need to also change this benchmark.
func benchmarkUnmarshalJSON(b *testing.B, numDNSEntries int) {
	logger := hivetest.Logger(b)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	ips := makeIPs(uint32(numIPsPerEntry))

	cache := NewDNSCache(0)
	for i := range numDNSEntries {
		// TTL needs to be far enough in the future that the entry is serialized
		cache.Update(time.Now(), fmt.Sprintf("domain-%v.com", i), ips, 86400)
	}

	data, err := cache.MarshalJSON()
	require.NoError(b, err)

	n := b.N
	emptyCaches := make([]*DNSCache, n)
	for i := 0; i < n; i++ {
		emptyCaches[i] = NewDNSCache(0)
	}

	for i := 0; i < n; i++ {
		err := emptyCaches[i].UnmarshalJSON(data)
		require.NoError(b, err)
	}
}

func TestTTLInsertWithMinValue(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	cache := NewDNSCache(60)
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 3)

	// Checking just now to validate that is inserted correctly
	res := cache.lookupByTime(now, "test.com")
	require.Len(t, res, 1)
	require.Equal(t, "1.2.3.4", res[0].String())

	// Checking the latest match
	res = cache.lookupByTime(now.Add(time.Second*3), "test.com")
	require.Len(t, res, 1)
	require.Equal(t, "1.2.3.4", res[0].String())

	// Validate that in future time the value is correct
	future := time.Now().Add(time.Second * 70)
	res = cache.lookupByTime(future, "test.com")
	require.Empty(t, res)
}

func TestTTLInsertWithZeroValue(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	cache := NewDNSCache(0)
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 10)

	// Checking just now to validate that is inserted correctly
	res := cache.lookupByTime(now, "test.com")
	require.Len(t, res, 1)
	require.Equal(t, "1.2.3.4", res[0].String())

	// Checking the latest match
	res = cache.lookupByTime(now.Add(time.Second*10), "test.com")
	require.Len(t, res, 1)
	require.Equal(t, "1.2.3.4", res[0].String())

	// Checking that expires correctly
	future := now.Add(time.Second * 11)
	res = cache.lookupByTime(future, "test.com")
	require.Empty(t, res)
}

func TestTTLCleanupEntries(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	cache := NewDNSCache(0)
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 3)
	require.Len(t, cache.cleanup, 1)
	entries, _ := cache.cleanupExpiredEntries(time.Now().Add(5 * time.Second))
	require.Len(t, entries, 1)
	require.Empty(t, cache.cleanup)
	require.Empty(t, cache.Lookup("test.com"))
}

func TestTTLCleanupWithoutForward(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	cache := NewDNSCache(0)
	now := time.Now()
	cache.cleanup[now.Unix()] = []string{"test.com"}
	// To make sure that all entries are validated correctly
	cache.lastCleanup = time.Now().Add(-1 * time.Minute)
	entries, _ := cache.cleanupExpiredEntries(time.Now().Add(5 * time.Second))
	require.Empty(t, entries)
	require.Empty(t, cache.cleanup)
}

func TestOverlimitEntriesWithValidLimit(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	limit := 5
	cache := NewDNSCacheWithLimit(0, limit)

	cache.Update(now, "foo.bar", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1)
	cache.Update(now, "bar.foo", []netip.Addr{netip.MustParseAddr("2.1.1.1")}, 1)
	for i := 1; i < limit+2; i++ {
		cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))}, i)
	}
	affectedNames, _ := cache.cleanupOverLimitEntries()
	require.Equal(t, sets.New[string]("test.com"), affectedNames)

	require.Len(t, cache.Lookup("test.com"), limit)
	require.Equal(t, []string{"foo.bar"}, cache.LookupIP(netip.MustParseAddr("1.1.1.1")))
	require.Nil(t, cache.forward["test.com"][netip.MustParseAddr("1.1.1.1")])
	require.Len(t, cache.Lookup("foo.bar"), 1)
	require.Len(t, cache.Lookup("bar.foo"), 1)
	require.Empty(t, cache.overLimit)
}

func TestOverlimitEntriesWithoutLimit(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	limit := 0
	cache := NewDNSCacheWithLimit(0, limit)
	for i := range 5 {
		cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))}, i)
	}
	affectedNames, _ := cache.cleanupOverLimitEntries()
	require.Empty(t, affectedNames)
	require.Len(t, cache.Lookup("test.com"), 5)
}

func TestGCOverlimitAfterTTLCleanup(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	limit := 5
	cache := NewDNSCacheWithLimit(0, limit)

	// Make sure that the cleanup takes all the changes from 1 minute ago.
	cache.lastCleanup = time.Now().Add(-1 * time.Minute)
	for i := 1; i < limit+2; i++ {
		cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))}, 1)
	}

	require.Len(t, cache.Lookup("test.com"), limit+1)
	require.Len(t, cache.overLimit, 1)

	result, _ := cache.cleanupExpiredEntries(time.Now().Add(5 * time.Second))
	require.Equal(t, sets.New[string]("test.com"), result)

	// Due all entries are deleted on TTL, the overlimit should return 0 entries.
	affectedNames, _ := cache.cleanupOverLimitEntries()
	require.Empty(t, affectedNames)
}

func TestOverlimitAfterDeleteForwardEntry(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	// Validate if something delete the forward entry no invalid key access on
	// CG operation
	dnsCache := NewDNSCache(0)
	dnsCache.overLimit["test.com"] = true
	affectedNames, _ := dnsCache.cleanupOverLimitEntries()
	require.Empty(t, affectedNames)
}

func assertZombiesContain(t *testing.T, zombies []*DNSZombieMapping, expected map[string][]string) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	t.Helper()
	require.Lenf(t, zombies, len(expected), "Different number of zombies than expected: %+v", zombies)

	for _, zombie := range zombies {
		names, exists := expected[zombie.IP.String()]
		require.Truef(t, exists, "Unexpected zombie %s in zombies", zombie.IP.String())

		slices.Sort(zombie.Names)
		slices.Sort(names)

		require.Len(t, zombie.Names, len(names))
		for i := range zombie.Names {
			require.Equal(t, names[i], zombie.Names[i], "Unexpected name in zombie names list")
		}
	}
}

func TestZombiesSiblingsGC(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	// Siblings are IPs that resolve to the same name.
	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "test.com")
	zombies.Upsert(now, netip.MustParseAddr("1.1.1.2"), "test.com")
	zombies.Upsert(now, netip.MustParseAddr("3.3.3.3"), "pizza.com")

	// Mark 1.1.1.2 alive which should also keep 1.1.1.1 alive since they
	// have the same name
	now = now.Add(5 * time.Minute)
	next := now.Add(5 * time.Minute)
	zombies.SetCTGCTime(now, next)
	now = now.Add(time.Second)
	zombies.MarkAlive(now.Add(time.Second), netip.MustParseAddr("1.1.1.2"))
	zombies.SetCTGCTime(now, next)

	alive, dead := zombies.GC()
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"1.1.1.2": {"test.com"},
	})
	assertZombiesContain(t, dead, map[string][]string{
		"3.3.3.3": {"pizza.com"},
	})
}

func TestZombiesGC(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "test.com")
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "somethingelse.com")

	// Without any MarkAlive or SetCTGCTime, all entries remain alive
	alive, dead := zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"somethingelse.com"},
	})

	// Adding another name to 1.1.1.1 keeps it alive and adds the name to the
	// zombie
	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "anotherthing.com")
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com", "anotherthing.com"},
		"2.2.2.2": {"somethingelse.com"},
	})

	// Even when not marking alive, running CT GC the first time is ignored;
	// we must always complete 2 GC cycles before allowing a name to be dead
	now = now.Add(5 * time.Minute)
	next := now.Add(5 * time.Minute)
	zombies.SetCTGCTime(now, next)
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com", "anotherthing.com"},
		"2.2.2.2": {"somethingelse.com"},
	})

	// Cause 1.1.1.1 to die by not marking it alive before the second GC
	// zombies.MarkAlive(now, netip.MustParseAddr("1.1.1.1"))
	now = now.Add(5 * time.Minute)
	next = now.Add(5 * time.Minute)
	// Mark 2.2.2.2 alive with 1 second grace period
	zombies.MarkAlive(now.Add(time.Second), netip.MustParseAddr("2.2.2.2"))
	zombies.SetCTGCTime(now, next)

	// alive should contain 2.2.2.2 -> somethingelse.com
	// dead should contain 1.1.1.1 -> anotherthing.com, test.com
	alive, dead = zombies.GC()
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com"},
	})
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.1": {"test.com", "anotherthing.com"},
	})

	// A second GC call only returns alive entries
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	require.Len(t, alive, 1)

	// Update 2.2.2.2 with a new DNS name. It remains alive.
	// Add 1.1.1.1 again. It is alive.
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "thelastthing.com")
	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "onemorething.com")

	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"onemorething.com"},
		"2.2.2.2": {"somethingelse.com", "thelastthing.com"},
	})

	// Cause all zombies but 2.2.2.2 to die
	now = now.Add(5 * time.Minute)
	next = now.Add(5 * time.Minute)
	zombies.SetCTGCTime(now, next)
	now = now.Add(5 * time.Minute)
	next = now.Add(5 * time.Minute)
	zombies.MarkAlive(now.Add(time.Second), netip.MustParseAddr("2.2.2.2"))
	zombies.SetCTGCTime(now, next)
	alive, dead = zombies.GC()
	require.Len(t, alive, 1)
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com", "thelastthing.com"},
	})
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.1": {"onemorething.com"},
	})

	// Cause all zombies to die
	now = now.Add(2 * time.Second)
	zombies.SetCTGCTime(now, next)
	alive, dead = zombies.GC()
	require.Empty(t, alive)
	assertZombiesContain(t, dead, map[string][]string{
		"2.2.2.2": {"somethingelse.com", "thelastthing.com"},
	})
}

func TestZombiesGCOverLimit(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, 1)

	// Limit the total number of IPs to be associated with a specific host
	// to 1, but associate 'test.com' with multiple IPs.
	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "test.com")
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "somethingelse.com", "test.com")
	zombies.Upsert(now, netip.MustParseAddr("3.3.3.3"), "anothertest.com")

	// Based on the zombie liveness sorting, the '2.2.2.2' entry is more
	// important (as it could potentially impact multiple apps connecting
	// to different domains), so it should be kept alive when sweeping to
	// enforce the max per-host IP limit for names.
	alive, dead := zombies.GC()
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.1": {"test.com"},
	})
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com", "test.com"},
		"3.3.3.3": {"anothertest.com"},
	})
}

func TestZombiesGCOverLimitWithCTGC(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	afterNow := now.Add(1 * time.Nanosecond)
	maxConnections := 3
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, maxConnections)
	zombies.SetCTGCTime(now, afterNow)

	// Limit the number of IPs per hostname, but associate 'test.com' with
	// more IPs.
	for i := range maxConnections + 1 {
		zombies.Upsert(now, netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i+1)), "test.com")
	}

	// Simulate that CT garbage collection marks some IPs as live, we'll
	// use the first 'maxConnections' IPs just so we can sort the output
	// in the test below.
	for i := range maxConnections {
		zombies.MarkAlive(afterNow, netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i+1)))
	}
	zombies.SetCTGCTime(afterNow, afterNow.Add(5*time.Minute))

	// Garbage collection should now impose the maxConnections limit on
	// the name, prioritizing to keep the active IPs live and then marking
	// the inactive IP as dead (to delete).
	alive, dead := zombies.GC()
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.4": {"test.com"},
	})
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"1.1.1.2": {"test.com"},
		"1.1.1.3": {"test.com"},
	})
}

func TestZombiesGCDeferredDeletes(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	zombies.Upsert(now.Add(0*time.Second), netip.MustParseAddr("1.1.1.1"), "test.com")
	zombies.Upsert(now.Add(1*time.Second), netip.MustParseAddr("2.2.2.2"), "somethingelse.com")
	zombies.Upsert(now.Add(2*time.Second), netip.MustParseAddr("3.3.3.3"), "onemorething.com")

	// No zombies should be evicted because the limit is high
	alive, dead := zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"somethingelse.com"},
		"3.3.3.3": {"onemorething.com"},
	})

	zombies = NewDNSZombieMappings(logger, 2, defaults.ToFQDNsMaxIPsPerHost)
	zombies.Upsert(now.Add(0*time.Second), netip.MustParseAddr("1.1.1.1"), "test.com")

	// No zombies should be evicted because we are below the limit
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
	})

	// 1.1.1.1 is evicted because it was Upserted earlier in
	// time, implying an earlier DNS expiry.
	zombies.Upsert(now.Add(1*time.Second), netip.MustParseAddr("2.2.2.2"), "somethingelse.com")
	zombies.Upsert(now.Add(2*time.Second), netip.MustParseAddr("3.3.3.3"), "onemorething.com")
	alive, dead = zombies.GC()
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.1": {"test.com"},
	})
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com"},
		"3.3.3.3": {"onemorething.com"},
	})

	// Only 3.3.3.3 is evicted because it is not marked alive, despite having the
	// latest insert time.
	zombies.Upsert(now.Add(0*time.Second), netip.MustParseAddr("1.1.1.1"), "test.com")
	gcTime := now.Add(4 * time.Second)
	next := now.Add(4 * time.Second)
	zombies.MarkAlive(gcTime, netip.MustParseAddr("1.1.1.1"))
	zombies.MarkAlive(gcTime, netip.MustParseAddr("2.2.2.2"))
	zombies.SetCTGCTime(gcTime, next)

	alive, dead = zombies.GC()
	assertZombiesContain(t, dead, map[string][]string{
		"3.3.3.3": {"onemorething.com"},
	})
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com"},
		"1.1.1.1": {"test.com"},
	})
}

func TestZombiesForceExpire(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "test.com", "anothertest.com")
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "somethingelse.com")

	// Without any MarkAlive or SetCTGCTime, all entries remain alive
	alive, dead := zombies.GC()
	require.Empty(t, dead)
	require.Len(t, alive, 2)

	// Expire only 1 name on 1 zombie
	nameMatch, err := regexp.Compile("^test.com$")
	require.NoError(t, err)
	zombies.ForceExpire(time.Time{}, nameMatch)

	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"anothertest.com"},
		"2.2.2.2": {"somethingelse.com"},
	})

	// Expire the last name on a zombie. It will be deleted and not returned in a
	// GC
	nameMatch, err = regexp.Compile("^anothertest.com$")
	require.NoError(t, err)
	zombies.ForceExpire(time.Time{}, nameMatch)
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com"},
	})

	// Setup again with 2 names for test.com
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "test.com")

	// Don't expire if the IP doesn't match
	zombies.ForceExpireByNameIP(time.Time{}, "somethingelse.com", netip.MustParseAddr("1.1.1.1"))
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"somethingelse.com", "test.com"},
	})

	// Expire 1 name for this IP but leave other names
	zombies.ForceExpireByNameIP(time.Time{}, "somethingelse.com", netip.MustParseAddr("2.2.2.2"))
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"test.com"},
	})

	// Don't remove if the name doesn't match
	zombies.ForceExpireByNameIP(time.Time{}, "blarg.com", netip.MustParseAddr("2.2.2.2"))
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"2.2.2.2": {"test.com"},
	})

	// Clear everything
	zombies.ForceExpireByNameIP(time.Time{}, "test.com", netip.MustParseAddr("2.2.2.2"))
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	require.Empty(t, alive)
	assertZombiesContain(t, alive, map[string][]string{})
}

func TestCacheToZombiesGCCascade(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	cache := NewDNSCache(0)
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	// Add entries that should expire at different times
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")}, 3)
	cache.Update(now, "test.com", []netip.Addr{netip.MustParseAddr("3.3.3.3")}, 5)

	// Cascade expirations from cache to zombies. The 3.3.3.3 lookup has not expired
	now = now.Add(4 * time.Second)
	expired := cache.GC(now, zombies)
	require.Equal(t, 1, expired.Len()) // test.com
	// Not all IPs expired (3.3.3.3 still alive) so we expect test.com to be
	// present in the cache.
	require.Contains(t, cache.forward, "test.com")
	require.Contains(t, cache.reverse, netip.MustParseAddr("3.3.3.3"))
	require.NotContains(t, cache.reverse, netip.MustParseAddr("1.1.1.1"))
	require.NotContains(t, cache.reverse, netip.MustParseAddr("2.2.2.2"))
	alive, dead := zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"test.com"},
	})

	// Cascade expirations from cache to zombies. The 3.3.3.3 lookup has expired
	// but the older zombies are still alive.
	now = now.Add(4 * time.Second)
	expired = cache.GC(now, zombies)
	require.Equal(t, 1, expired.Len()) // test.com
	// Now all IPs expired so we expect test.com to be removed from the cache.
	require.NotContains(t, cache.forward, "test.com")
	require.Empty(t, cache.forward)
	require.NotContains(t, cache.reverse, "3.3.3.")
	require.Empty(t, cache.reverse)
	alive, dead = zombies.GC()
	require.Empty(t, dead)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"test.com"},
		"3.3.3.3": {"test.com"},
	})
}

func TestZombiesDumpAlive(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	now := time.Now()
	zombies := NewDNSZombieMappings(logger, defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)

	alive := zombies.DumpAlive(nil)
	require.Empty(t, alive)

	zombies.Upsert(now, netip.MustParseAddr("1.1.1.1"), "test.com")
	zombies.Upsert(now, netip.MustParseAddr("2.2.2.2"), "example.com")
	zombies.Upsert(now, netip.MustParseAddr("3.3.3.3"), "example.org")

	alive = zombies.DumpAlive(nil)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"example.com"},
		"3.3.3.3": {"example.org"},
	})

	// Simulate an interleaved CTGC and DNS GC
	// Ensure that two GC runs must progress before
	// marking zombies dead.
	now = now.Add(time.Second)
	next := now.Add(5 * time.Minute)
	zombies.SetCTGCTime(now, next)
	alive = zombies.DumpAlive(nil)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"example.com"},
		"3.3.3.3": {"example.org"},
	})

	now = now.Add(5 * time.Minute) // Need to step the clock 5 minutes ahead here, to account for the grace period
	next = now.Add(5 * time.Minute)
	zombies.MarkAlive(now, netip.MustParseAddr("1.1.1.1"))
	zombies.MarkAlive(now, netip.MustParseAddr("2.2.2.2"))
	zombies.SetCTGCTime(now, next)

	alive = zombies.DumpAlive(nil)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"example.com"},
	})

	cidrMatcher := func(addr netip.Addr) bool { return false }
	alive = zombies.DumpAlive(cidrMatcher)
	require.Empty(t, alive)

	cidrMatcher = func(_ netip.Addr) bool { return true }
	alive = zombies.DumpAlive(cidrMatcher)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"2.2.2.2": {"example.com"},
	})

	prefix := netip.MustParsePrefix("1.1.1.0/24")
	cidrMatcher = func(a netip.Addr) bool { return prefix.Contains(a) }
	alive = zombies.DumpAlive(cidrMatcher)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
	})

	zombies.Upsert(now, netip.MustParseAddr("1.1.1.2"), "test2.com")

	alive = zombies.DumpAlive(cidrMatcher)
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.1": {"test.com"},
		"1.1.1.2": {"test2.com"},
	})

	prefix = netip.MustParsePrefix("4.4.0.0/16")
	cidrMatcher = func(a netip.Addr) bool { return prefix.Contains(a) }
	alive = zombies.DumpAlive(cidrMatcher)
	require.Empty(t, alive)
}

func TestOverlimitPreferNewerEntries(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	toFQDNsMinTTL := 100
	toFQDNsMaxIPsPerHost := 5
	cache := NewDNSCacheWithLimit(toFQDNsMinTTL, toFQDNsMaxIPsPerHost)

	toFQDNsMaxDeferredConnectionDeletes := 10
	zombies := NewDNSZombieMappings(logger, toFQDNsMaxDeferredConnectionDeletes, toFQDNsMaxIPsPerHost)

	name := "test.com"
	IPs := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("1.1.1.2"),
		netip.MustParseAddr("1.1.1.3"),
		netip.MustParseAddr("1.1.1.4"),
		netip.MustParseAddr("1.1.1.5"),
		netip.MustParseAddr("1.1.1.6"),
		netip.MustParseAddr("1.1.1.7"),
		netip.MustParseAddr("1.1.1.8"),
		netip.MustParseAddr("1.1.1.9"),
		netip.MustParseAddr("1.1.1.10"),
		netip.MustParseAddr("1.1.1.11"),
		netip.MustParseAddr("1.1.1.12"),
		netip.MustParseAddr("1.1.1.13"),
		netip.MustParseAddr("1.1.1.14"),
		netip.MustParseAddr("1.1.1.15"),
		netip.MustParseAddr("1.1.1.16"),
		netip.MustParseAddr("1.1.1.17"),
		netip.MustParseAddr("1.1.1.18"),
		netip.MustParseAddr("1.1.1.19"),
		netip.MustParseAddr("1.1.1.20"),
	}
	ttl := 0 // will be overwritten with toFQDNsMinTTL

	now := time.Now()
	for i, ip := range IPs {
		// Entries with lower values in last IP octet will expire earlier
		lookupTime := now.Add(-time.Duration(len(IPs)-i) * time.Second)
		cache.Update(lookupTime, name, []netip.Addr{ip}, ttl)
	}

	affected := cache.GC(time.Now(), zombies)

	require.Equal(t, 1, affected.Len())
	require.True(t, affected.Has(name))

	// No entries have expired, but no more than toFQDNsMaxIPsPerHost can be
	// kept in the cache.
	// The exceeding ones will be moved to the zombies cache due to overlimit
	require.Len(t, cache.forward[name], toFQDNsMaxIPsPerHost)

	alive, dead := zombies.GC()

	// No more than toFQDNsMaxIPsPerHost entries will be kept
	// alive in the zombies cache as well
	require.Len(t, alive, toFQDNsMaxIPsPerHost)

	// More recent entries (i.e. entries with later expire time) will be kept alive
	assertZombiesContain(t, alive, map[string][]string{
		"1.1.1.11": {name},
		"1.1.1.12": {name},
		"1.1.1.13": {name},
		"1.1.1.14": {name},
		"1.1.1.15": {name},
	})

	// Older entries will be evicted
	assertZombiesContain(t, dead, map[string][]string{
		"1.1.1.1":  {name},
		"1.1.1.2":  {name},
		"1.1.1.3":  {name},
		"1.1.1.4":  {name},
		"1.1.1.5":  {name},
		"1.1.1.6":  {name},
		"1.1.1.7":  {name},
		"1.1.1.8":  {name},
		"1.1.1.9":  {name},
		"1.1.1.10": {name},
	})
}

// This test tests the over limit behaviour of DNS Mapping zombies for repeated
// lookups to the same domain (e.g. an S3 bucket). It tries to mimic the "fun"
// interactions between the CT GC, FQDN GC and per-host IP limits. It covers a
// case which, prior to the commit introducing this test, zombies were reaped
// erroneously, since their "AliveAt" field was zero (and they thus sorted to
// the front).
func TestPerHostLimitBehaviourForS3(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	someDomain := "s3.example.com"
	maxIPs := 5
	dnsTTL := 4 // seconds

	tc := NewDNSCacheWithLimit(0, maxIPs)
	z := NewDNSZombieMappings(logger, 10000, maxIPs)

	// These are simulated lookup results for someDomain.
	reallyOldLookup := []netip.Addr{
		netip.MustParseAddr("1.0.0.1"),
	}
	recentLookup := []netip.Addr{
		netip.MustParseAddr("1.1.0.1"),
		netip.MustParseAddr("1.1.0.2"),
		netip.MustParseAddr("1.1.0.3"),
		netip.MustParseAddr("1.1.0.4"),
		netip.MustParseAddr("1.1.0.5"),
	}
	keepaliveLookup := netip.MustParseAddr("1.2.0.1")

	simulateFQDNGC := func(when time.Time) sets.Set[string] {
		t.Helper()
		names := tc.GC(when, z)
		z.GC()
		return names
	}

	simulateCTGC := func(when time.Time, alive []netip.Addr) {
		t.Helper()
		for _, ip := range alive {
			z.MarkAlive(when, ip)
		}
		z.SetCTGCTime(when, when.Add(10*time.Second))
	}

	// Simulates a lookup and runs all GCs
	tick := func(tock time.Time) {
		t.Helper()
		tc.Update(tock, someDomain, []netip.Addr{keepaliveLookup}, dnsTTL)
		// Must be past TTL
		simulateFQDNGC(tock.Add((2*time.Duration(dnsTTL)*time.Second + 1)))
		simulateCTGC(tock.Add(2*time.Duration(dnsTTL)*time.Second+2), nil)
	}

	now := time.Now()
	aLongTimeAgo := now.Add(-10 * time.Hour)
	sevenSecondsAgo := now.Add(-7 * time.Second) // TTL expired by "now"

	// A long time ago, we looked up example.com
	tc.Update(aLongTimeAgo, someDomain, reallyOldLookup, dnsTTL)
	// At some point past the lookup's TTL, a FQDN GC happens. The lookup now
	// moves to the DNSMappingZombies. It's not yet dead, since the zombie
	// tracking doesn't know whether its dead or alive (since CT GC hasn't run).
	simulateFQDNGC(aLongTimeAgo.Add(8 * time.Second))
	// Turns out it was a long-standing connection and hence CT GC marked it
	// alive. The entry is still a zombie, but a live one.
	simulateCTGC(aLongTimeAgo.Add(10*time.Second), reallyOldLookup)
	if _, found := z.deletes[reallyOldLookup[0]]; !found {
		t.Errorf("expected really old lookup to still be present")
	}

	// During these "ticks", we simulate lookups to someDomain. We call these
	// keep-alive lookups because they keep the really old lookup alive. Any
	// alive IP for a name keeps that name alive, and any name keeps
	// corresponding zombies alive. Cilium wants to keep these alive to not
	// break applications which resolve someDomain once, early, and then assume
	// the resolved IPs to be alive for longer than TTL.
	tick(aLongTimeAgo.Add(20 * time.Second))
	tick(aLongTimeAgo.Add(30 * time.Second))
	tick(aLongTimeAgo.Add(40 * time.Second))
	tick(aLongTimeAgo.Add(50 * time.Second))
	if _, found := z.deletes[reallyOldLookup[0]]; !found {
		t.Errorf("expected really old lookup to still be present")
	}

	// Seven seconds ago, we looked example.com up again. To test the over-limit
	// behaviour, this lookup gets multiple IPs back.
	tc.Update(sevenSecondsAgo, someDomain, recentLookup, dnsTTL)
	// FQDN GC should collect all but the newest five IPs due to the perHost limit.
	affectedNames := simulateFQDNGC(now)
	if len(affectedNames) != 1 || !affectedNames.Has(someDomain) {
		t.Errorf("expected affected name to contain only %s but it is %+v", someDomain, affectedNames)
	}

	// Assert that the zombies respect the limit.
	if len(z.deletes) != maxIPs {
		t.Errorf("expected zombies to contain %v entries, but has %v", maxIPs, len(z.deletes))
	}
	// Assert that the old lookup was thrown out.
	if _, found := z.deletes[reallyOldLookup[0]]; found {
		t.Errorf("expected really old lookup not to be present")
	}
	// Asser that the new lookups are present.
	for _, ip := range recentLookup {
		if _, found := z.deletes[ip]; !found {
			t.Errorf("expected recent lookup %v to be present", ip)
		}
	}
}

// Define a test-only string representation to make the output below more readable.
func (z *DNSZombieMapping) String() string {
	return fmt.Sprintf(
		"DNSZombieMapping{AliveAt: %s, DeletePendingAt: %s, Names: %v}",
		z.AliveAt, z.DeletePendingAt, z.Names,
	)
}

func validateZombieSort(t *testing.T, zombies []*DNSZombieMapping) {
	t.Helper()
	sl := len(zombies)

	logFailure := func(t *testing.T, zs []*DNSZombieMapping, prop string, i, j int) {
		t.Helper()
		t.Logf("order property fail %v: want zombie[i] < zombie[j]", prop)
		t.Log("zombie[i]: ", zs[i])
		t.Log("zombie[j]: ", zs[j])
		t.Log("all mappings: ")
		for i, z := range zs {
			t.Log(fmt.Sprintf("%2d", i), z)
		}
	}
	// Don't try to be efficient, just check that the properties we want hold
	// for every pair of zombie mappings.
	for i := range sl {
		for j := i + 1; j < sl; j++ {
			if zombies[i].AliveAt.Before(zombies[j].AliveAt) {
				continue
			} else if zombies[i].AliveAt.After(zombies[j].AliveAt) {
				logFailure(t, zombies, "AliveAt", i, j)
				t.Fatalf("order wrong: AliveAt: %v is after %v", zombies[i].AliveAt, zombies[j].AliveAt)
				return
			}

			if zombies[i].DeletePendingAt.Before(zombies[j].DeletePendingAt) {
				continue
			} else if zombies[i].DeletePendingAt.After(zombies[j].DeletePendingAt) {
				logFailure(t, zombies, "DeletePendingAt", i, j)
				t.Fatalf("order wrong: DeletePendingAt: %v is after %v", zombies[i].DeletePendingAt, zombies[j].DeletePendingAt)
				return
			}

			if len(zombies[i].Names) > len(zombies[j].Names) {
				logFailure(t, zombies, "len(names)", i, j)
				t.Fatalf("order wrong: len(names): %v is longer than %v", zombies[i].Names, zombies[j].Names)
			}
		}
	}
}

func Test_sortZombieMappingSlice(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)

	// Create three moments in time, so we can have before, equal and after.
	moments := []time.Time{
		time.Date(2001, time.January, 1, 1, 1, 1, 0, time.Local),
		time.Date(2002, time.February, 2, 2, 2, 2, 0, time.Local),
		time.Date(2003, time.March, 3, 3, 3, 3, 0, time.Local),
	}

	// Couple of edge cases/hand-picked scenarios. To be complemented by the
	// randomly generated ones, below.
	type args struct {
		zombies []*DNSZombieMapping
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"empty",
			args{zombies: nil},
		},
		{
			"single",
			args{zombies: []*DNSZombieMapping{{
				Names:           []string{"test.com"},
				AliveAt:         moments[0],
				DeletePendingAt: moments[1],
			}}},
		},
		{
			"swapped alive at",
			args{zombies: []*DNSZombieMapping{
				{
					AliveAt: moments[2],
				},
				{
					AliveAt: moments[0],
				},
			}},
		},
		{
			"equal alive, swapped delete pending at",
			args{zombies: []*DNSZombieMapping{
				{
					AliveAt:         moments[0],
					DeletePendingAt: moments[2],
				},
				{
					AliveAt:         moments[0],
					DeletePendingAt: moments[1],
				},
			}},
		},
		{
			"swapped equal times, tiebreaker",
			args{zombies: []*DNSZombieMapping{
				{
					Names:           []string{"test.com", "test2.com"},
					AliveAt:         moments[0],
					DeletePendingAt: moments[1],
				},
				{
					Names:           []string{"test.com"},
					AliveAt:         moments[0],
					DeletePendingAt: moments[1],
				},
			}},
		},
	}

	// Generate zombie mappings which cover all cases of the two times
	// being either moment 0, 1 or 2, as well as with 0, 1 or 2 names.
	names := []string{"example.org", "test.com"}
	nMoments := len(moments)
	allMappings := make([]*DNSZombieMapping, 0, nMoments*nMoments*nMoments)
	for _, mi := range moments {
		for _, mj := range moments {
			for k := range names {
				m := DNSZombieMapping{
					AliveAt:         mi,
					DeletePendingAt: mj,
					Names:           names[:k],
				}
				allMappings = append(allMappings, &m)
			}
		}
	}

	// Five random tests:
	for range 5 {
		ts := make([]*DNSZombieMapping, len(allMappings))
		copy(ts, allMappings)
		rand.Shuffle(len(ts), func(i, j int) {
			ts[i], ts[j] = ts[j], ts[i]
		})
		tests = append(tests, struct {
			name string
			args args
		}{
			name: "Randomised sorting test",
			args: args{
				zombies: ts,
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ol := len(tt.args.zombies)
			sortZombieMappingSlice(tt.args.zombies)
			if len(tt.args.zombies) != ol {
				t.Fatalf("length of slice changed by sorting")
			}
			validateZombieSort(t, tt.args.zombies)
		})
	}
}
