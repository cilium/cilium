// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"maps"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReferenceTracker(t *testing.T) {
	v4Prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.0.0/15"),
		netip.MustParsePrefix("192.0.0.0/15"),
		netip.MustParsePrefix("192.0.2.2/31"),
		netip.MustParsePrefix("192.0.2.3/32"),
	}
	v4PrefixesLengths := map[int]int{
		0:  1,
		15: 2,
		31: 1,
		32: 1,
	}

	result := NewPrefixLengthCounter(128, 32)

	// Expected output is the combination of defaults and the above prefixes.
	expectedPrefixLengths := make(IntCounter, len(v4PrefixesLengths))
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	// New prefixes are added (return true)
	changed, err := result.Add(v4Prefixes)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v4)

	// When we add the prefixes again, we should increase the reference
	// counts appropriately
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	// This time, there are no new prefix lengths (return false).
	changed, err = result.Add(v4Prefixes)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v4)

	// Delete the /15 prefix and see that it is removed and doesn't affect
	// other counts
	prefixes15 := []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/15"),
	}
	expectedPrefixLengths[15]--
	require.False(t, result.Delete(prefixes15))
	require.Equal(t, expectedPrefixLengths, result.v4)

	// Delete some prefix lengths
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] -= v
	}
	// No change in prefix lengths; each 'prefixes' was referenced twice.
	require.False(t, result.Delete(v4Prefixes))
	require.Equal(t, expectedPrefixLengths, result.v4)

	// Re-add the /32 prefix and see that it is added back properly.
	expectedPrefixLengths[15]++
	changed, err = result.Add(prefixes15)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v4)

	// When removing the 'prefixes' again, return true and the set of
	// prefixes should be empty
	require.True(t, result.Delete(v4Prefixes))
	require.Equal(t, IntCounter{}, result.v4)

	// Add back the v4 prefixes while we add v6 prefixes.
	changed, err = result.Add(v4Prefixes)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v4)

	v6Prefixes := []netip.Prefix{
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("FD33:DEAD:BEEF:CAFE::/76"),
		netip.MustParsePrefix("FD33:DEAD:BEEF:CAFE::/96"),
		netip.MustParsePrefix("fd33:dead:beef:cafe::91b2:b600/120"),
	}
	v6PrefixesLengths := map[int]int{
		0:   1,
		76:  1,
		96:  1,
		120: 1,
	}

	expectedPrefixLengths = make(IntCounter, len(v6PrefixesLengths))

	// Add the v6 prefixes (changed: true)
	maps.Copy(expectedPrefixLengths, v6PrefixesLengths)
	changed, err = result.Add(v6Prefixes)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v6)

	// Add the v6 prefixes again (changed: false)
	for k, v := range v6PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	changed, err = result.Add(v6Prefixes)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, expectedPrefixLengths, result.v6)

	// Now, remove them (changed: false)
	for k, v := range v6PrefixesLengths {
		expectedPrefixLengths[k] -= v
	}
	require.False(t, result.Delete(v6Prefixes))
	require.Equal(t, expectedPrefixLengths, result.v6)

	// Delete them again (changed: true)
	require.True(t, result.Delete(v6Prefixes))
	require.Equal(t, IntCounter{}, result.v6)

	// Our v4 prefixes should still be here, unchanged
	expectedPrefixLengths = make(map[int]int, len(v4PrefixesLengths))
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	require.Equal(t, expectedPrefixLengths, result.v4)
}

func TestCheckLimits(t *testing.T) {
	result := NewPrefixLengthCounter(4, 4)
	require.NoError(t, checkLimits(0, 4, result.maxUniquePrefixes4))
	require.Error(t, checkLimits(0, 5, result.maxUniquePrefixes4))
	require.NoError(t, checkLimits(0, 4, result.maxUniquePrefixes6))
	require.Error(t, checkLimits(0, 5, result.maxUniquePrefixes6))

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.0.0/15"),
		netip.MustParsePrefix("192.0.2.2/31"),
		netip.MustParsePrefix("192.0.2.3/32"),
	}
	changed, err := result.Add(prefixes)
	require.NoError(t, err)
	require.True(t, changed)

	changed, err = result.Add([]netip.Prefix{netip.MustParsePrefix("192.0.0.0/8")})
	require.Error(t, err)
	require.False(t, changed)
}

func TestToBPFData(t *testing.T) {
	result := NewPrefixLengthCounter(42, 32)

	prefixes := []string{
		"192.0.2.0/24",
		"192.0.2.0/32",
		"192.0.64.0/20",
	}
	prefixesToAdd := []netip.Prefix{}
	for _, prefix := range prefixes {
		net := netip.MustParsePrefix(prefix)
		prefixesToAdd = append(prefixesToAdd, net)
	}

	_, err := result.Add(prefixesToAdd)
	require.NoError(t, err)

	s6, s4 := result.ToBPFData()
	require.Equal(t, []int{}, s6)
	require.Equal(t, []int{32, 24, 20}, s4)
}

func TestDefaultPrefixLengthCounter(t *testing.T) {
	result := DefaultPrefixLengthCounter()
	require.Equal(t, 1, result.v4[0])
	require.Equal(t, 1, result.v6[0])
	require.Equal(t, 1, result.v4[net.IPv4len*8])
	require.Equal(t, 1, result.v6[net.IPv6len*8])
}
