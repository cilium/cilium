// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRTrie(t *testing.T) {
	trie := NewCIDRTrie[string]()
	prefixes := map[string]netip.Prefix{
		"0":    netip.MustParsePrefix("0.0.0.0/0"),
		"1":    netip.MustParsePrefix("1.0.0.0/8"),
		"2a":   netip.MustParsePrefix("1.1.0.0/16"),
		"2b":   netip.MustParsePrefix("1.2.0.0/16"),
		"3a":   netip.MustParsePrefix("1.1.1.0/24"),
		"3b":   netip.MustParsePrefix("1.2.1.0/24"),
		"4a":   netip.MustParsePrefix("1.1.1.0/25"),
		"4b":   netip.MustParsePrefix("1.1.1.128/25"),
		"last": netip.MustParsePrefix("1.1.1.129/32"),
	}

	// These are prefixes that have a direct longer match
	overridden := []string{
		"3a", // because 1.1.1.0/24 -> 1.1.1.0/25
	}

	for name, prefix := range prefixes {
		trie.Upsert(prefix, name)
	}

loop:
	for name := range prefixes {
		for _, over := range overridden {
			if name == over {
				continue loop
			}
		}
		_, have, _ := trie.LongestPrefixMatch(prefixes[name].Addr())
		if have != name {
			t.Errorf("LongestPrefixMatch(%s) returned %s want %s", prefixes[name].String(), have, name)
		}
	}

	// Search should return the complete path to the prefix
	// will look up 1.1.1.128/25.
	wantPath := []string{
		"0",    // 0.0.0.0/0
		"1",    // 1.0.0.0/8
		"2a",   // 1.1.0.0/16
		"3a",   // 1.1.1.0/24
		"4b",   // 1.1.1.128/25
		"last", // 1.1.1.129/32
	}

	havePath := []string{}
	trie.Ancestors(prefixes["last"], func(k netip.Prefix, v string) bool {
		wantK := prefixes[v]
		if wantK != k {
			t.Errorf("Search(%s) returned an unexpected key-value pair: k %s v %s", prefixes["last"], k.String(), v)
		}
		havePath = append(havePath, v)
		return true
	})
	t.Log(havePath)
	assert.Equal(t, wantPath, havePath)

	// Search should return the complete path to the prefix
	// will look up 1.1.1.128/25.
	wantPath = []string{
		"last", // 1.1.1.129/32
		"4b",   // 1.1.1.128/25
		"3a",   // 1.1.1.0/24
		"2a",   // 1.1.0.0/16
		"1",    // 1.0.0.0/8
		"0",    // 0.0.0.0/0
	}

	havePath = []string{}
	trie.AncestorsLongestPrefixFirst(prefixes["last"], func(k netip.Prefix, v string) bool {
		wantK := prefixes[v]
		if wantK != k {
			t.Errorf("Search(%s) returned an unexpected key-value pair: k %s v %s", prefixes["last"], k.String(), v)
		}
		havePath = append(havePath, v)
		return true
	})
	t.Log(havePath)
	assert.Equal(t, wantPath, havePath)

	for _, tc := range []struct {
		k string
		v string
	}{
		{
			"1.1.1.130/32",
			"4b",
		},
		{
			"1.1.1.1/32",
			"4a",
		},
		{
			"1.24.0.0/32",
			"1",
		},
		{
			"24.24.24.24/32",
			"0",
		},
	} {
		k, v, ok := trie.LongestPrefixMatch(netip.MustParsePrefix(tc.k).Addr())
		assert.True(t, k.IsValid())
		assert.True(t, ok)
		assert.Equal(t, tc.v, v)
	}

}

func TestDescendants(t *testing.T) {
	tests := []struct {
		name     string
		prefixes map[int]netip.Prefix
	}{
		{
			name: "all",
			prefixes: map[int]netip.Prefix{
				0:  netip.MustParsePrefix("0.0.0.0/0"),
				1:  netip.MustParsePrefix("0.0.0.0/1"),
				2:  netip.MustParsePrefix("0.0.0.0/2"),
				3:  netip.MustParsePrefix("0.0.0.0/3"),
				4:  netip.MustParsePrefix("0.0.0.0/4"),
				5:  netip.MustParsePrefix("0.0.0.0/5"),
				6:  netip.MustParsePrefix("0.0.0.0/6"),
				7:  netip.MustParsePrefix("0.0.0.0/7"),
				8:  netip.MustParsePrefix("0.0.0.0/8"),
				9:  netip.MustParsePrefix("0.0.0.0/9"),
				10: netip.MustParsePrefix("0.0.0.0/10"),
				11: netip.MustParsePrefix("0.0.0.0/11"),
				12: netip.MustParsePrefix("0.0.0.0/12"),
				13: netip.MustParsePrefix("0.0.0.0/13"),
				14: netip.MustParsePrefix("0.0.0.0/14"),
				15: netip.MustParsePrefix("0.0.0.0/15"),
				16: netip.MustParsePrefix("0.0.0.0/16"),
				17: netip.MustParsePrefix("0.0.0.0/17"),
				18: netip.MustParsePrefix("0.0.0.0/18"),
				19: netip.MustParsePrefix("0.0.0.0/19"),
				20: netip.MustParsePrefix("0.0.0.0/20"),
				21: netip.MustParsePrefix("0.0.0.0/21"),
				22: netip.MustParsePrefix("0.0.0.0/22"),
				23: netip.MustParsePrefix("0.0.0.0/23"),
				24: netip.MustParsePrefix("0.0.0.0/24"),
				25: netip.MustParsePrefix("0.0.0.0/25"),
				26: netip.MustParsePrefix("0.0.0.0/26"),
				27: netip.MustParsePrefix("0.0.0.0/27"),
				28: netip.MustParsePrefix("0.0.0.0/28"),
				29: netip.MustParsePrefix("0.0.0.0/29"),
				30: netip.MustParsePrefix("0.0.0.0/30"),
				31: netip.MustParsePrefix("0.0.0.0/31"),
				32: netip.MustParsePrefix("0.0.0.0/32"),
			},
		}, {
			name: "sparse",
			prefixes: map[int]netip.Prefix{
				0:  netip.MustParsePrefix("0.0.0.0/0"),
				16: netip.MustParsePrefix("0.0.0.0/16"),
				32: netip.MustParsePrefix("0.0.0.0/32"),
			},
		},
	}
	for _, tt := range tests {
		t.Logf("Running test case %q", tt.name)
		tr := NewCIDRTrie[string]()
		for _, v := range tt.prefixes {
			tr.Upsert(v, v.String())
		}
		for i := 0; i <= 32; i++ {
			pref, ok := tt.prefixes[i]
			if !ok {
				// No such prefix
				continue
			}
			expectedRes := make([]string, 0, 32-i)
			for t := i; t <= 32; t++ {
				p, ok := tt.prefixes[t]
				if !ok {
					continue
				}
				expectedRes = append(expectedRes, p.String())
			}
			gotRes := make([]string, 0, 32-i)
			tr.Descendants(pref, func(_ netip.Prefix, v string) bool {
				gotRes = append(gotRes, v)
				return true
			})
			if !reflect.DeepEqual(expectedRes, gotRes) {
				t.Fatalf("Descendants prefix %s, expected to get %v, but got: %v", pref.String(), expectedRes, gotRes)
			}
		}
	}
}

func TestDescendantsShortestPrefixFirst(t *testing.T) {
	tests := []struct {
		name     string
		prefixes map[int]netip.Prefix
	}{
		{
			name: "all",
			prefixes: map[int]netip.Prefix{
				0:  netip.MustParsePrefix("0.0.0.0/0"),
				1:  netip.MustParsePrefix("0.0.0.0/1"),
				2:  netip.MustParsePrefix("0.0.0.0/2"),
				3:  netip.MustParsePrefix("0.0.0.0/3"),
				4:  netip.MustParsePrefix("0.0.0.0/4"),
				5:  netip.MustParsePrefix("0.0.0.0/5"),
				6:  netip.MustParsePrefix("0.0.0.0/6"),
				7:  netip.MustParsePrefix("0.0.0.0/7"),
				8:  netip.MustParsePrefix("0.0.0.0/8"),
				9:  netip.MustParsePrefix("0.0.0.0/9"),
				10: netip.MustParsePrefix("0.0.0.0/10"),
				11: netip.MustParsePrefix("0.0.0.0/11"),
				12: netip.MustParsePrefix("0.0.0.0/12"),
				13: netip.MustParsePrefix("0.0.0.0/13"),
				14: netip.MustParsePrefix("0.0.0.0/14"),
				15: netip.MustParsePrefix("0.0.0.0/15"),
				16: netip.MustParsePrefix("0.0.0.0/16"),
				17: netip.MustParsePrefix("0.0.0.0/17"),
				18: netip.MustParsePrefix("0.0.0.0/18"),
				19: netip.MustParsePrefix("0.0.0.0/19"),
				20: netip.MustParsePrefix("0.0.0.0/20"),
				21: netip.MustParsePrefix("0.0.0.0/21"),
				22: netip.MustParsePrefix("0.0.0.0/22"),
				23: netip.MustParsePrefix("0.0.0.0/23"),
				24: netip.MustParsePrefix("0.0.0.0/24"),
				25: netip.MustParsePrefix("0.0.0.0/25"),
				26: netip.MustParsePrefix("0.0.0.0/26"),
				27: netip.MustParsePrefix("0.0.0.0/27"),
				28: netip.MustParsePrefix("0.0.0.0/28"),
				29: netip.MustParsePrefix("0.0.0.0/29"),
				30: netip.MustParsePrefix("0.0.0.0/30"),
				31: netip.MustParsePrefix("0.0.0.0/31"),
				32: netip.MustParsePrefix("0.0.0.0/32"),
			},
		}, {
			name: "sparse",
			prefixes: map[int]netip.Prefix{
				0:  netip.MustParsePrefix("0.0.0.0/0"),
				16: netip.MustParsePrefix("0.0.0.0/16"),
				32: netip.MustParsePrefix("0.0.0.0/32"),
			},
		}, {
			name: "trie",
			prefixes: map[int]netip.Prefix{
				0:  netip.MustParsePrefix("0.0.0.0/0"),
				1:  netip.MustParsePrefix("128.0.0.0/1"),
				2:  netip.MustParsePrefix("64.0.0.0/2"),
				3:  netip.MustParsePrefix("192.0.0.0/3"),
				4:  netip.MustParsePrefix("32.0.0.0/4"),
				5:  netip.MustParsePrefix("16.0.0.0/5"),
				6:  netip.MustParsePrefix("48.0.0.0/6"),
				7:  netip.MustParsePrefix("4.0.0.0/7"),
				8:  netip.MustParsePrefix("1.0.0.0/8"),
				9:  netip.MustParsePrefix("128.128.0.0/9"),
				10: netip.MustParsePrefix("64.64.0.0/10"),
				11: netip.MustParsePrefix("192.192.0.0/11"),
				12: netip.MustParsePrefix("32.32.0.0/12"),
				13: netip.MustParsePrefix("16.16.0.0/13"),
				14: netip.MustParsePrefix("48.48.0.0/14"),
				15: netip.MustParsePrefix("4.4.0.0/15"),
				16: netip.MustParsePrefix("1.1.0.0/16"),
				17: netip.MustParsePrefix("128.128.128.0/17"),
				18: netip.MustParsePrefix("64.64.64.0/18"),
				19: netip.MustParsePrefix("192.192.192.0/19"),
				20: netip.MustParsePrefix("32.32.32.0/20"),
				21: netip.MustParsePrefix("16.16.16.0/21"),
				22: netip.MustParsePrefix("48.48.48.0/22"),
				23: netip.MustParsePrefix("4.4.4.0/23"),
				24: netip.MustParsePrefix("1.1.1.0/24"),
				25: netip.MustParsePrefix("128.128.128.128/25"),
				26: netip.MustParsePrefix("64.64.64.64/26"),
				27: netip.MustParsePrefix("192.192.192.192/27"),
				28: netip.MustParsePrefix("32.32.32.32/28"),
				29: netip.MustParsePrefix("16.16.16.16/29"),
				30: netip.MustParsePrefix("48.48.48.48/30"),
				31: netip.MustParsePrefix("4.4.4.4/31"),
				32: netip.MustParsePrefix("1.1.1.1/32"),
			},
		},
	}
	for _, tt := range tests {
		t.Logf("Running test case %q", tt.name)
		tr := NewCIDRTrie[string]()
		for _, v := range tt.prefixes {
			tr.Upsert(v, v.String())
		}
		for i := 0; i <= 32; i++ {
			pref, ok := tt.prefixes[i]
			if !ok {
				// No such prefix
				continue
			}
			expectedRes := make([]string, 0, 32-i)
			for t := i; t <= 32; t++ {
				p, ok := tt.prefixes[t]
				if !ok {
					continue
				}
				if pref.Contains(p.Addr()) {
					expectedRes = append(expectedRes, p.String())
				}
			}
			gotRes := make([]string, 0, 32-i)
			tr.DescendantsShortestPrefixFirst(pref, func(_ netip.Prefix, v string) bool {
				gotRes = append(gotRes, v)
				return true
			})
			if !reflect.DeepEqual(expectedRes, gotRes) {
				t.Fatalf("LPM Descendants prefix %s, expected to get %v, but got: %v", pref.String(), expectedRes, gotRes)
			}
		}
	}
}

func TestBitValueAt(t *testing.T) {
	for i, tc := range []struct {
		v    netip.Prefix
		i    uint
		want uint8
	}{
		// note: prefix length does not matter
		{
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    0,
			want: 0,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    7,
			want: 0,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    8,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:ffff::/128"),
			i:    9,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    16,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    17,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    18,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    19,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    20,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    21,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    22,
			want: 1,
		}, {
			v:    netip.MustParsePrefix("00ff:fe00::/128"),
			i:    23,
			want: 0,
		},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			have := cidrKey(tc.v).BitValueAt(tc.i)
			if have != tc.want {
				t.Errorf("Prefix %s index %d got bit %d, want %d", tc.v.String(), tc.i, have, tc.want)
			}
		})
	}
}

func TestCommonPrefix(t *testing.T) {
	for i, tc := range []struct {
		v1   netip.Prefix
		v2   netip.Prefix
		want uint
	}{
		{
			v1:   netip.MustParsePrefix("00ff::/128"),
			v2:   netip.MustParsePrefix("00fe::/128"),
			want: 15,
		},
		{
			v1:   netip.MustParsePrefix("f0ff::/128"),
			v2:   netip.MustParsePrefix("00fe::/128"),
			want: 0,
		},
		{
			v1:   netip.MustParsePrefix("ffff::/128"),
			v2:   netip.MustParsePrefix("ff7f::/128"),
			want: 8,
		},
		{
			v1:   netip.MustParsePrefix("ffff::/128"),
			v2:   netip.MustParsePrefix("fe7f::/128"),
			want: 7,
		},
		{
			v1:   netip.MustParsePrefix("::/128"),
			v2:   netip.MustParsePrefix("::/128"),
			want: 128,
		}, {
			v1:   netip.MustParsePrefix("::/128"),
			v2:   netip.MustParsePrefix("::1/128"),
			want: 127,
		},
	} {

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			have := cidrKey(tc.v1).CommonPrefix(tc.v2)
			if have != tc.want {
				t.Errorf("p1 %v p2 %v got %d want %d", tc.v1, tc.v2, have, tc.want)
			}
		})
	}
}

func generatePrefix(b *testing.B, r *rand.Rand) netip.Prefix {
	var addr4 [4]byte
	prefixlen := r.IntN(33)
	if prefixlen > 0 {
		mask := ^uint32(0)
		if prefixlen < 32 {
			mask <<= (32 - prefixlen)
		}
		masked := r.Uint32() & mask
		addr4[0] = byte(masked >> 24)
		addr4[1] = byte(masked >> 16)
		addr4[2] = byte(masked >> 8)
		addr4[3] = byte(masked)
	}
	addr := netip.AddrFrom4(addr4)
	assert.True(b, addr.IsValid())
	p := netip.PrefixFrom(addr, prefixlen)
	assert.True(b, p.IsValid())
	assert.Equal(b, prefixlen, p.Bits())
	return p
}

func generateCIDRs(b *testing.B, r *rand.Rand, n int) *CIDRTrie[struct{}] {
	t := NewCIDRTrie[struct{}]()
	for i := 0; i < n; i++ {
		if !t.Upsert(generatePrefix(b, r), struct{}{}) {
			n++
		}
	}
	return t
}

func BenchmarkTraversal(b *testing.B) {
	const (
		nCIDRs      = 100000
		prefixLen   = 16
		randomSeed1 = uint64(42)
		randomSeed2 = uint64(733)
	)
	r := rand.New(rand.NewPCG(randomSeed1, randomSeed2))
	t := generateCIDRs(b, r, nCIDRs)
	assert.Equal(b, uint(nCIDRs), t.Len())
	rnd := r.Uint32()
	prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(rnd >> 24), byte(rnd >> 16), 0, 0}), prefixLen)
	assert.True(b, prefix.IsValid())
	assert.Equal(b, prefixLen, prefix.Bits())

	b.Run("ancestors root-first", func(b *testing.B) {
		n := 0

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			n = 0
			t.Ancestors(prefix, func(k netip.Prefix, _ struct{}) bool {
				n++
				return true
			})
		}
	})

	b.Run("Ancestors longest-prefix-first", func(b *testing.B) {
		n := 0
		lastLen := 0

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			n = 0
			lastLen = prefixLen
			t.AncestorsLongestPrefixFirst(prefix, func(k netip.Prefix, _ struct{}) bool {
				pLen := prefix.Bits()
				assert.True(b, pLen <= lastLen)
				lastLen = pLen
				n++
				return true
			})
		}
	})

	b.Run("descendants depth-first", func(b *testing.B) {
		n := 0

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			n = 0
			t.Descendants(prefix, func(k netip.Prefix, _ struct{}) bool {
				n++
				return true
			})
		}
	})

	b.Run("descendants shortest-prefix-first", func(b *testing.B) {
		n := 0
		lastLen := 0

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			n = 0
			lastLen = 0
			t.DescendantsShortestPrefixFirst(prefix, func(k netip.Prefix, _ struct{}) bool {
				pLen := prefix.Bits()
				assert.True(b, pLen >= lastLen)
				lastLen = pLen
				n++
				return true
			})
		}
	})
}
