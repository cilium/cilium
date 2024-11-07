// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"fmt"
	"math/bits"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type uint16Range struct {
	start, end uint16
}

func (pr uint16Range) prefix() uint {
	return prefixFromRange(pr.start, max(pr.end, pr.start))
}

func prefixFromRange(start, end uint16) uint {
	return 16 - uint(bits.TrailingZeros16(^uint16(end-start)))
}

func (pr uint16Range) String() string {
	return fmt.Sprintf("%d-%d", pr.start, pr.end)
}

var uint16RangeMap = map[uint]uint16{
	0:  0b1111_1111_1111_1111,
	1:  0b111_1111_1111_1111,
	2:  0b11_1111_1111_1111,
	3:  0b1_1111_1111_1111,
	4:  0b1111_1111_1111,
	5:  0b111_1111_1111,
	6:  0b11_1111_1111,
	7:  0b1_1111_1111,
	8:  0b1111_1111,
	9:  0b111_1111,
	10: 0b11_1111,
	11: 0b1_1111,
	12: 0b1111,
	13: 0b111,
	14: 0b11,
	15: 0b1,
	16: 0,
}

func endFromPrefix(prefix uint, start uint16) uint16 {
	return start + uint16RangeMap[prefix]
}

var (
	uint16Range65535 = []uint16Range{
		{start: 65535, end: 65535},
	}
	uint16Range0_65535 = []uint16Range{
		{start: 0, end: 65535},
	}
	uint16Range1_65534 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
		{start: 8, end: 15},
		{start: 16, end: 31},
		{start: 32, end: 63},
		{start: 64, end: 127},
		{start: 128, end: 255},
		{start: 256, end: 511},
		{start: 512, end: 1023},
		{start: 1024, end: 2047},
		{start: 2048, end: 4095},
		{start: 4096, end: 8191},
		{start: 8192, end: 16383},
		{start: 16384, end: 32767},
		{start: 32768, end: 49151},
		{start: 49152, end: 57343},
		{start: 57344, end: 61439},
		{start: 61440, end: 63487},
		{start: 63488, end: 64511},
		{start: 64512, end: 65023},
		{start: 65024, end: 65279},
		{start: 65280, end: 65407},
		{start: 65408, end: 65471},
		{start: 65472, end: 65503},
		{start: 65504, end: 65519},
		{start: 65520, end: 65527},
		{start: 65528, end: 65531},
		{start: 65532, end: 65533},
		{start: 65534, end: 65534},
	}
	uint16Range0_1023 = []uint16Range{
		{start: 0, end: 1023},
	}
	uint16Range1_1023 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
		{start: 8, end: 15},
		{start: 16, end: 31},
		{start: 32, end: 63},
		{start: 64, end: 127},
		{start: 128, end: 255},
		{start: 256, end: 511},
		{start: 512, end: 1023},
	}
	uint16Range0_7 = []uint16Range{
		{start: 0, end: 7},
	}
	uint16Range1_7 = []uint16Range{
		{start: 1, end: 1},
		{start: 2, end: 3},
		{start: 4, end: 7},
	}
	uint16Range0_1 = []uint16Range{
		{start: 0, end: 1},
	}
	uint16Range1_1 = []uint16Range{
		{start: 1, end: 1},
	}
)

// TestUnsignedUpsert tests to see that a trie contains
// all the values it should after every update.
func TestUnsignedUpsert(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%d_%d%s", tt.ranges[0].start,
			tt.ranges[len(tt.ranges)-1].end, tt.name)
		// Check that the whole trie is what it should be
		// on each update.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for i, pr := range tt.ranges {
				ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
				var got []uint16Range
				ut.ForEach(func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				})
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[:i+1]) {
					t.Fatalf("When updating an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[:i+1])
				}
			}
		})
	}
}

// TestUnsignedUpsertReturnValue tests to see that the Upsert method
// of the Trie returns true only when a new key is being inserted.
func TestUnsignedUpsertReturnValue(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%d_%d%s", tt.ranges[0].start,
			tt.ranges[len(tt.ranges)-1].end, tt.name)
		// Check that the whole trie is what it should be
		// on each update.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				isNewA := ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
				if !isNewA {
					t.Fatalf("Expected Upsert of port-range (%d-%d) to be a new insert, but it is not...", pr.start, pr.end)
				}
				isNewB := ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d-replace", pr.start, pr.end))
				if isNewB {
					t.Fatalf("Expected Upsert of port-range (%d-%d) to be a replacement, but it is not...", pr.start, pr.end)
				}
			}
		})
	}
}

// TestUnsignedExactLookup looks up every entry expressed
// in a trie structure to ensure that exact lookup only returns
// on when keys match exactly.
func TestUnsignedExactLookup(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		firstRange := tt.ranges[0]
		lastRange := tt.ranges[len(tt.ranges)-1]
		name := fmt.Sprintf("%d_%d%s", firstRange.start, lastRange.end, tt.name)
		// Check that every valid key returns the correct
		// entry and every invalid key returns nothing.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for _, pr := range tt.ranges {
				entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
				pref := pr.prefix()
				// check if one-less than an exact prefix returns anything
				if pref > 0 {
					_, ok := ut.ExactLookup(pref-1, pr.start)
					if ok {
						t.Fatalf("ExactLookup returned a non-existent key-entry for prefix (%d), key (%d)", pr.prefix()-1, pr.start)
					}
				}
				// check if one-more than an exact prefix returns anything
				if pref < 16 {
					_, ok := ut.ExactLookup(pref+1, pr.start)
					if ok {
						t.Fatalf("ExactLookup returned a non-existent key-entry for prefix (%d), key (%d)", pr.prefix()+1, pr.start)
					}
				}
				// check if an exact lookup works
				got, ok := ut.ExactLookup(pr.prefix(), pr.start)
				if !ok || got != entry {
					t.Fatalf("ExactLookup did not return the expected prefix (%d), key (%d); got %s", pr.prefix(), pr.start, got)
				}
			}
		})
	}
}

// TestUnsignedLongestPrefixMatch looks up every possible value expressed
// in a trie structure by the most specific prefix.
func TestUnsignedLongestPrefixMatch(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		firstRange := tt.ranges[0]
		lastRange := tt.ranges[len(tt.ranges)-1]
		name := fmt.Sprintf("%d_%d%s", firstRange.start, lastRange.end, tt.name)
		// Check that every valid key returns the correct
		// entry and every invalid key returns nothing.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for _, pr := range tt.ranges {
				entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
				start := pr.start
				end := pr.end
				// uint16 should be converted to uint for the
				// purpose of the loop condition as some tests
				// overflow uint16 causing an infinite loop.
				for p := uint(start); p <= uint(end); p++ {
					_, got, _ := ut.LongestPrefixMatch(uint16(p))
					if entry != got {
						t.Fatalf("Looking up key %d, expected entry %q, but got %q", p, entry, got)
					}
				}
			}
			// look up all the missing keys.
			start := firstRange.start
			end := lastRange.end
			for p := uint(0); p < uint(start); p++ {
				_, got, ok := ut.LongestPrefixMatch(uint16(p))
				if ok {
					t.Fatalf("Looking up key %d, expected no entry, but got %q", p, got)
				}
			}
			for p := uint(end) + 1; p <= uint(65535); p++ {
				_, got, ok := ut.LongestPrefixMatch(uint16(p))
				if ok {
					t.Fatalf("Looking up key %d, expected no entry, but got %q", p, got)
				}
			}
		})
	}
}

// TestUnsignedAncestorsRange tests looking up keys with
// a non-full prefix (i.e. a range of keys), by creating tries
// in different ranges and ensuring that the trie returns
// in-range queries from other known in-range lookups, and that
// known out-of-range lookups fail.
func TestUnsignedAncestorsRange(t *testing.T) {
	ranges := [][]uint16Range{
		uint16Range65535,
		uint16Range0_65535,
		uint16Range1_65534,
		uint16Range0_1023,
		uint16Range1_1023,
		uint16Range0_7,
		uint16Range1_7,
		uint16Range0_1,
		uint16Range1_1,
	}
	// eliminate duplicate range lookups
	rangeLookupMap := make(map[string]uint16Range)
	for _, r := range ranges {
		for _, pr := range r {
			entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
			if _, ok := rangeLookupMap[entry]; !ok {
				rangeLookupMap[entry] = pr
			}
		}
	}
	for _, r := range ranges {
		rangeStart := r[0].start
		rangeEnd := r[len(r)-1].end
		name := fmt.Sprintf("%d_%d", rangeStart, rangeEnd)
		t.Run(name, func(t *testing.T) {
			tu := NewUintTrie[uint16, string]()
			for _, pr := range r {
				entry := fmt.Sprintf("%d-%d", pr.start, pr.end)
				tu.Upsert(pr.prefix(), pr.start, entry)
			}
			for _, pr := range rangeLookupMap {
				var gotEntry string
				tu.Ancestors(pr.prefix(), pr.start, func(prefix uint, _ uint16, v string) bool {
					gotEntry = v
					return true
				})
				if pr.start < rangeStart || pr.end > rangeEnd {
					if gotEntry != "" {
						t.Fatalf("Expected to get an emty entry from key-prefix %d/%d, got %q",
							pr.start, pr.prefix(), gotEntry)
					}
				} else {
					if gotEntry == "" {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got no entry",
							pr.start, pr.prefix())
					}
					rangeS := strings.Split(gotEntry, "-")
					start, err := strconv.ParseUint(rangeS[0], 10, 16)
					if err != nil {
						t.Fatalf("Error parsing start value of range entry %q", gotEntry)
					}
					if uint16(start) > pr.start {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got %q",
							pr.start, pr.prefix(), gotEntry)
					}
					end, err := strconv.ParseUint(rangeS[1], 10, 16)
					if err != nil {
						t.Fatalf("Error parsing end value of range entry %q", gotEntry)
					}
					if uint16(end) < pr.end {
						t.Fatalf("Expected to get an in range entry from key-prefix %d/%d, but got %q",
							pr.start, pr.prefix(), gotEntry)
					}
				}
			}
		})
	}
}

// TestUnsignedAncestors tests searching for all keys
// that match a searched-for key and prefix.
func TestUnsignedAncestors(t *testing.T) {
	// Create a uint Trie that contains overlapping ranges
	// from 0-65535.
	tu := NewUintTrie[uint16, string]()
	for i := uint(0); i < 16; i++ {
		rng := uint16RangeMap[i]
		entry := fmt.Sprintf("%d-%d", 0, rng)
		tu.Upsert(i, rng, entry)
	}
	// Check to see that each range
	// lookup returns all ranges that contain
	// it.
	for i := uint(0); i < 16; i++ {
		rng := uint16RangeMap[i]
		entry := fmt.Sprintf("%d-%d", 0, rng)
		t.Run(entry, func(t *testing.T) {
			expectedRes := make([]string, 0, i+1)
			for t := uint(0); t <= i; t++ {
				rng2 := uint16RangeMap[t]
				expectedRes = append(expectedRes, fmt.Sprintf("%d-%d", 0, rng2))
			}
			gotRes := make([]string, 0, i+1)
			tu.Ancestors(i, rng, func(prefix uint, key uint16, v string) bool {
				gotRes = append(gotRes, v)
				return true
			})
			if !reflect.DeepEqual(expectedRes, gotRes) {
				t.Fatalf("Ancestors range %s, expected to get %v, but got: %v", entry, expectedRes, gotRes)
			}
		})
	}
}

// TestUnsignedDescendants tests searching for all keys
// that are match by a searched-for key and prefix.
func TestUnsignedDescendants(t *testing.T) {
	// Create a uint Trie that contains overlapping ranges
	// from 0-65535.
	tu := NewUintTrie[uint16, string]()
	for i := uint(0); i <= 16; i++ {
		rng := uint16RangeMap[i]
		entry := fmt.Sprintf("%d-%d", 0, rng)
		tu.Upsert(i, rng, entry)
	}
	// Check to see that each range lookup returns
	// all ranges that contain it.
	for i := uint(0); i < 16; i++ {
		rng := uint16RangeMap[i]
		entry := fmt.Sprintf("%d-%d", 0, rng)
		t.Run(entry, func(t *testing.T) {
			expectedRes := make([]string, 0, 16-i)
			for t := i; t <= 16; t++ {
				rng2 := uint16RangeMap[t]
				expectedRes = append(expectedRes, fmt.Sprintf("%d-%d", 0, rng2))
			}
			gotRes := make([]string, 0, 16-i)
			tu.Descendants(i, rng, func(prefix uint, key uint16, v string) bool {
				gotRes = append(gotRes, v)
				return true
			})
			if !reflect.DeepEqual(expectedRes, gotRes) {
				t.Fatalf("Descendants range %s, expected to get %v, but got: %v", entry, expectedRes, gotRes)
			}
			// It should still work even if the entry is not present
			tu.Delete(i, rng)
			expectedRes = expectedRes[1:]
			gotRes = make([]string, 0, 16-i-1)
			tu.Descendants(i, rng, func(prefix uint, key uint16, v string) bool {
				gotRes = append(gotRes, v)
				return true
			})
			if !reflect.DeepEqual(expectedRes, gotRes) {
				t.Fatalf("Descendants range %s, expected to get %v, but got: %v", entry, expectedRes, gotRes)
			}
		})
	}
}

// TestUnsignedDelete creates a trie from a set of ranges
// and then incrementally deletes each entry, checking
// that the trie contains all the values it should after
// each delete. It checks deleting the trie both
// from the bottom of a range up, and the top of the range
// down.
func TestUnsignedDelete(t *testing.T) {
	tests := []struct {
		name   string
		ranges []uint16Range
	}{
		{
			ranges: uint16Range65535,
		},
		{
			name:   " least entries for largest range",
			ranges: uint16Range0_65535,
		},
		{
			name:   " most entries for largest range",
			ranges: uint16Range1_65534,
		},
		{
			ranges: uint16Range0_1023,
		},
		{
			ranges: uint16Range1_1023,
		},
		{
			ranges: uint16Range0_7,
		},
		{
			ranges: uint16Range1_7,
		},
		{
			ranges: uint16Range0_1,
		},
		{
			ranges: uint16Range1_1,
		},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%d_%d%s", tt.ranges[0].start,
			tt.ranges[len(tt.ranges)-1].end, tt.name)
		// Check that the whole trie is what it should be
		// on each deletion in order.
		t.Run(name, func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for i, pr := range tt.ranges {
				// The "got" slice cannot be nil for the DeepEqual
				// comparison, even if it is empty.
				got := make([]uint16Range, 0, len(tt.ranges)-i-1)
				ok := ut.Delete(pr.prefix(), pr.start)
				if !ok {
					t.Fatalf("Key-prefix %d/%d not deleted", pr.start, pr.prefix())
				}
				ut.ForEach(func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				})
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[i+1:]) {
					t.Fatalf("When deleting an entry from an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[i+1:])
				}
			}
		})
		// Delete in reverse order.
		t.Run(fmt.Sprintf("In_Reverse_%s", name), func(t *testing.T) {
			ut := NewUintTrie[uint16, string]()
			for _, pr := range tt.ranges {
				ut.Upsert(pr.prefix(), pr.start, fmt.Sprintf("%d-%d", pr.start, pr.end))
			}
			for i := len(tt.ranges) - 1; i >= 0; i-- {
				pr := tt.ranges[i]
				// The "got" slice cannot be nil for the DeepEqual
				// comparison, even if it is empty.
				got := make([]uint16Range, 0, i+1)
				ok := ut.Delete(pr.prefix(), pr.start)
				if !ok {
					t.Fatalf("Key-prefix %d/%d not deleted", pr.start, pr.prefix())
				}
				ut.ForEach(func(prefix uint, key uint16, value string) bool {
					got = append(got, uint16Range{start: key, end: endFromPrefix(prefix, key)})
					return true
				})
				sort.Slice(got, func(i, j int) bool {
					return got[i].start < got[j].start
				})
				if !reflect.DeepEqual(got, tt.ranges[:i]) {
					t.Fatalf("When deleting an entry from an unsigned trie with the key-prefix %d/%d: got %+v, but expected %+v", pr.start, pr.prefix(), got, tt.ranges[:i])
				}
			}
		})
	}
}

func BenchmarkTrieUpsert(b *testing.B) {
	tri := NewUintTrie[uint32, struct{}]()
	emptyS := struct{}{}
	count := uint(0)
	b.ReportAllocs()
	b.ResetTimer()

	// mimic adding 2 octets worth of addresses
	tri.Upsert(16, 0xffff_0000, emptyS)
	count++
	for i := uint32(0); i < 255; i++ {
		upperThree := 0xffff_0000 | i<<8
		tri.Upsert(24, upperThree, emptyS)
		count++
		for t := uint32(0); t < 255; t++ {
			tri.Upsert(32, upperThree|t, emptyS)
			count++
		}
	}
	b.StopTimer()
	if tri.Len() != count {
		b.Fatalf("expected count (%d) to agree with trie length (%d)", count, tri.Len())
	}
}

func BenchmarkMapUpdate(b *testing.B) {
	map32 := make(map[uint32]struct{}, 256*256)
	emptyS := struct{}{}
	count := 0
	b.ReportAllocs()
	b.ResetTimer()
	// mimic adding 2 octets worth of addresses
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			map32[0xffff_0000|upperOct|t] = emptyS
			count++
		}
	}
	b.StopTimer()
	if len(map32) != count {
		b.Fatalf("expected count (%d) to agree with map length (%d)", count, len(map32))
	}
}

func BenchmarkTrieAncestorsRange(b *testing.B) {
	tri := NewUintTrie[uint32, *struct{}]()
	emptyS := &struct{}{}
	count := uint(0)
	// mimic adding 2 octets worth of addresses
	tri.Upsert(16, 0xffff_0000, emptyS)
	count++
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		tri.Upsert(24, 0xffff_0000|upperOct, emptyS)
		count++
		for t := uint32(0); t < 255; t++ {
			tri.Upsert(32, 0xffff_0000|upperOct|t, emptyS)
			count++
		}
	}
	if tri.Len() != count {
		b.Fatalf("expected count (%d) to agree with trie length (%d)", count, tri.Len())
	}

	b.ReportAllocs()
	b.ResetTimer()
	var st *struct{}
	tri.Ancestors(16, 0xffff_0000, func(_ uint, _ uint32, v *struct{}) bool {
		st = v
		return true
	})
	if st == nil {
		b.Fatal("expected valid lookup, but got nil")
	}
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		var st *struct{}
		tri.Ancestors(24, 0xffff_0000|upperOct, func(_ uint, _ uint32, v *struct{}) bool {
			st = v
			return true
		})
		if st == nil {
			b.Fatal("expected valid lookup, but got nil")
		}
		for t := uint32(0); t < 255; t++ {
			var st *struct{}
			tri.Ancestors(32, 0xffff_0000|upperOct|t, func(_ uint, _ uint32, v *struct{}) bool {
				st = v
				return true
			})
			if st == nil {
				b.Fatal("expected valid lookup, but got nil")
			}
		}
	}
}

func BenchmarkTrieLongestPrefixMatch(b *testing.B) {
	tri := NewUintTrie[uint32, *struct{}]()
	emptyS := &struct{}{}
	count := uint(0)
	// mimic adding 2 octets worth of addresses
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		tri.Upsert(24, 0xffff_0000|upperOct, emptyS)
		count++
		for t := uint32(0); t < 255; t++ {
			tri.Upsert(32, 0xffff_0000|upperOct|t, emptyS)
			count++
		}
	}
	if tri.Len() != count {
		b.Fatalf("expected count (%d) to agree with trie length (%d)", count, tri.Len())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			_, _, ok := tri.LongestPrefixMatch(0xffff_0000 | upperOct | t)
			if !ok {
				b.Fatal("expected valid lookup, but got nil")
			}
		}
	}
}

func BenchmarkMapLookup(b *testing.B) {
	map32 := make(map[uint32]*struct{}, 256*256)
	emptyS := &struct{}{}
	count := 0
	// mimic adding 2 octets worth of addresses
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			map32[0xffff_0000|upperOct|t] = emptyS
			count++
		}
	}
	if len(map32) != count {
		b.Fatalf("expected count (%d) to agree with map length (%d)", count, len(map32))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			v, ok := map32[0xffff_0000|upperOct|t]
			if !ok || v == nil {
				b.Fatalf("expected to get value from map lookup, got nil")
			}
		}
	}
}

func BenchmarkTrieDelete(b *testing.B) {
	tri := NewUintTrie[uint32, *struct{}]()
	emptyS := &struct{}{}
	count := uint(0)
	// mimic adding 2 octets worth of addresses
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		tri.Upsert(24, 0xffff_0000|upperOct, emptyS)
		count++
		for t := uint32(0); t < 255; t++ {
			tri.Upsert(32, 0xffff_0000|upperOct|t, emptyS)
			count++
		}
	}
	if tri.Len() != count {
		b.Fatalf("expected count (%d) to agree with trie length (%d)", count, tri.Len())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		if !tri.Delete(24, 0xffff_0000|upperOct) {
			b.Fatal("expected valid delete, but got nil")
		}
		for t := uint32(0); t < 255; t++ {
			if !tri.Delete(32, 0xffff_0000|upperOct|t) {
				b.Fatal("expected valid lookup, but got nil")
			}
		}
	}
	b.StopTimer()
	if tri.Len() != 0 {
		b.Fatalf("expected Trie length of 0, but got %d", tri.Len())
	}
}

func BenchmarkMapDelete(b *testing.B) {
	map32 := make(map[uint32]*struct{}, 256*256)
	emptyS := &struct{}{}
	count := 0
	// mimic adding 2 octets worth of addresses
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			map32[0xffff_0000|upperOct|t] = emptyS
			count++
		}
	}
	if len(map32) != count {
		b.Fatalf("expected count (%d) to agree with map length (%d)", count, len(map32))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := uint32(0); i < 255; i++ {
		upperOct := i << 8
		for t := uint32(0); t < 255; t++ {
			delete(map32, 0xffff_0000|upperOct|t)
		}
	}
	b.StopTimer()
	if len(map32) != 0 {
		b.Fatalf("expected map length of 0, but got %d", len(map32))
	}

}

func mask(v, bitcnt uint8) uint8 {
	m := ^(^uint8(0) >> bitcnt)
	return v & m
}

func FuzzUint8(f *testing.F) {
	// has the fuzzing engine generate a set of []uint8, which it interprets as
	// a sequence of (val, prefixlen) pairs.

	// Then, checks invariants

	f.Add([]byte{0b1111_1111, 4})

	f.Fuzz(func(t *testing.T, sequence []byte) {

		type testEntry struct {
			k    uint8
			plen uint8
			val  uint16 // a placeholder
		}

		tree := NewUintTrie[uint8, testEntry]()

		seen := map[string]testEntry{}

		// Insert every item in to the tree, recording the prefix in to a hash as well
		// so we know what we've set
		for i := 0; i < len(sequence)-1; i += 2 {
			k := sequence[i]
			prefixLen := sequence[i+1] % 8

			seenk := fmt.Sprintf("%#b/%d", mask(k, prefixLen), prefixLen)

			seen[seenk] = testEntry{
				k:    k,
				plen: prefixLen,
				val:  uint16(k)<<8 + uint16(prefixLen),
			}

			tree.Upsert(uint(prefixLen), k, seen[seenk]) // may overwrite

		}

		if tree.Len() != uint(len(seen)) {
			t.Errorf("unexpected length: %d (expected %d)", tree.Len(), len(seen))
		}

		// Now, validate
		for seenK, seenV := range seen {
			var val testEntry
			tree.Ancestors(uint(seenV.plen), seenV.k, func(_ uint, _ uint8, v testEntry) bool {
				val = v
				return true
			})
			if val.val != seenV.val {
				t.Errorf("seenKey %s: got val %#b expected %#b", seenK, val.val, seenV.val)
			}
		}

		// Now, delete seen keys and validate
		expectedLength := len(seen)
		for seenK, seenV := range seen {
			t.Logf("Deleting key %s", seenK)
			tree.Delete(uint(seenV.plen), seenV.k)
			expectedLength--

			if tree.Len() != uint(expectedLength) {
				t.Errorf("unexpected length: %d (expected %d)", tree.Len(), expectedLength)
			}
		}
	})
}
