// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package random

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
)

// mpp is a abbreviation and panics on non masked prefixes.
//
//nolint:gochecknoglobals
var mpp = func(s string) netip.Prefix {
	pfx := netip.MustParsePrefix(s)
	if pfx == pfx.Masked() {
		return pfx
	}
	panic(fmt.Sprintf("%s is not canonicalized as %s", s, pfx.Masked()))
}

// Prefix returns a randomly generated prefix
func Prefix(prng *rand.Rand) netip.Prefix {
	if prng.IntN(2) == 1 {
		return Prefix4(prng)
	}
	return Prefix6(prng)
}

func Prefix4(prng *rand.Rand) netip.Prefix {
	bits := prng.IntN(33)
	return netip.PrefixFrom(IP4(prng), bits).Masked()
}

func Prefix6(prng *rand.Rand) netip.Prefix {
	bits := prng.IntN(129)
	return netip.PrefixFrom(IP6(prng), bits).Masked()
}

func IP4(prng *rand.Rand) netip.Addr {
	var b [4]byte
	for i := range b {
		b[i] = byte(prng.UintN(256))
	}
	return netip.AddrFrom4(b)
}

func IP6(prng *rand.Rand) netip.Addr {
	var b [16]byte
	for i := range b {
		b[i] = byte(prng.UintN(256))
	}
	return netip.AddrFrom16(b)
}

func IP(prng *rand.Rand) netip.Addr {
	if prng.IntN(2) == 1 {
		return IP4(prng)
	}
	return IP6(prng)
}

func RealWorldPrefixes4(prng *rand.Rand, n int) []netip.Prefix {
	set := make(map[netip.Prefix]struct{})
	pfxs := make([]netip.Prefix, 0, n)

	for len(set) < n {
		pfx := Prefix4(prng)

		// skip too small or too big masks
		if pfx.Bits() < 8 || pfx.Bits() > 28 {
			continue
		}

		// skip reserved/experimental ranges (e.g., 240.0.0.0/8)
		if pfx.Overlaps(mpp("240.0.0.0/8")) {
			continue
		}

		if _, ok := set[pfx]; !ok {
			set[pfx] = struct{}{}
			pfxs = append(pfxs, pfx)
		}
	}
	return pfxs
}

func RealWorldPrefixes6(prng *rand.Rand, n int) []netip.Prefix {
	set := make(map[netip.Prefix]struct{})
	pfxs := make([]netip.Prefix, 0, n)

	for len(set) < n {
		pfx := Prefix6(prng)

		// skip too small or too big masks
		if pfx.Bits() < 16 || pfx.Bits() > 56 {
			continue
		}

		// skip non global routes seen in the real world
		if !pfx.Overlaps(mpp("2000::/3")) {
			continue
		}
		if pfx.Addr().Compare(mpp("2c0f::/16").Addr()) == 1 {
			continue
		}

		if _, ok := set[pfx]; !ok {
			set[pfx] = struct{}{}
			pfxs = append(pfxs, pfx)
		}
	}
	return pfxs
}

func RealWorldPrefixes(prng *rand.Rand, n int) []netip.Prefix {
	pfxs := make([]netip.Prefix, 0, n)
	pfxs = append(pfxs, RealWorldPrefixes4(prng, n/2)...)
	pfxs = append(pfxs, RealWorldPrefixes6(prng, n-len(pfxs))...)

	prng.Shuffle(len(pfxs), func(i, j int) {
		pfxs[i], pfxs[j] = pfxs[j], pfxs[i]
	})

	return pfxs
}
