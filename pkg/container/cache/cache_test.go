// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"maps"
	"strings"
	"testing"
	"unique"

	"github.com/cespare/xxhash/v2"
	"github.com/stretchr/testify/assert"
)

func TestStringsCache(t *testing.T) {
	tests := []string{
		"",
		"foo",
		"foobar",
	}
	for _, test := range tests {
		x := Strings.Get(test)
		assert.Equal(t, x, test)
	}
}
func TestGetOrPutWith(t *testing.T) {
	type o struct {
		s string
		x int
	}
	tests := []string{
		"",
		"foo",
		"foobar",
	}

	cache := New(
		func(o o) uint64 { return xxhash.Sum64String(o.s) },
		nil,
		func(a, b o) bool {
			return b.x != 0 && // don't confuse with zero value cache entries
				a.s == b.s
		},
	)

	for _, test := range tests {
		x := GetOrPutWith(
			cache,
			xxhash.Sum64String(test),
			func(o o) bool { return o.x != 0 && o.s == test },
			func() o { return o{test, 1} },
		)
		assert.Equal(t, test, x.s)
		assert.Equal(t, 1, x.x)
	}
}

func BenchmarkStringsCache(b *testing.B) {
	s := "foobar"
	for b.Loop() {
		x := Strings.Get(s)
		if x != s {
			b.Fatalf("strings not equal, %q vs %q", s, x)
		}
	}
}

// BenchmarkStringCache_Large shows that lookups of long strings from the cache
// are skipped.
func BenchmarkStringsCache_Large(b *testing.B) {
	s := strings.Repeat("ni", 500)
	for b.Loop() {
		x := Strings.Get(s)
		if x != s {
			b.Fatalf("strings not equal, %q vs %q", s, x)
		}
	}
}

func BenchmarkUniqueString(b *testing.B) {
	s := "foobar"
	for b.Loop() {
		x := unique.Make(s)
		if x.Value() != s {
			b.Fatalf("strings not equal, %q vs %q", s, x.Value())
		}
	}
}

func TestStringMapsCache(t *testing.T) {
	tests := []map[string]string{
		nil,
		{"": ""},
		{"foo": "bar"},
	}
	for _, test := range tests {
		x := StringMaps.Get(test)
		assert.True(t, maps.Equal(x, test), "maps equal")
	}
}

func BenchmarkStringMapsCache(b *testing.B) {
	m := map[string]string{"foo": "bar"}
	for b.Loop() {
		x := StringMaps.Get(m)
		if !maps.Equal(x, m) {
			b.Fatalf("maps not equal, %q vs %q", m, x)
		}
	}
}

// BenchmarkStringMapsCache_Large shows that lookups of large maps from the cache
// are skipped.
func BenchmarkStringMapsCache_Large(b *testing.B) {
	m := map[string]string{}
	s := strings.Repeat("ni", 500)
	for range 500 {
		m[s] = s
	}

	for b.Loop() {
		x := StringMaps.Get(m)
		if !maps.Equal(x, m) {
			b.Fatalf("maps not equal, %q vs %q", m, x)
		}
	}
}
