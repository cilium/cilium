// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"maps"
	"strings"
	"testing"
	"unique"

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
