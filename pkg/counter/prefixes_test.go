// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"net"
	"net/netip"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func (cs *CounterTestSuite) TestReferenceTracker(c *C) {
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
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, true)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

	// When we add the prefixes again, we should increase the reference
	// counts appropriately
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	// This time, there are no new prefix lengths (return false).
	changed, err = result.Add(v4Prefixes)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, false)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

	// Delete the /15 prefix and see that it is removed and doesn't affect
	// other counts
	prefixes15 := []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/15"),
	}
	expectedPrefixLengths[15]--
	c.Assert(result.Delete(prefixes15), Equals, false)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

	// Delete some prefix lengths
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] -= v
	}
	// No change in prefix lengths; each 'prefixes' was referenced twice.
	c.Assert(result.Delete(v4Prefixes), Equals, false)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

	// Re-add the /32 prefix and see that it is added back properly.
	expectedPrefixLengths[15]++
	changed, err = result.Add(prefixes15)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, false)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

	// When removing the 'prefixes' again, return true and the set of
	// prefixes should be empty
	c.Assert(result.Delete(v4Prefixes), Equals, true)
	c.Assert(result.v4, checker.DeepEquals, IntCounter{})

	// Add back the v4 prefixes while we add v6 prefixes.
	changed, err = result.Add(v4Prefixes)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, true)
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)

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
	for k, v := range v6PrefixesLengths {
		expectedPrefixLengths[k] = v
	}
	changed, err = result.Add(v6Prefixes)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, true)
	c.Assert(result.v6, checker.DeepEquals, expectedPrefixLengths)

	// Add the v6 prefixes again (changed: false)
	for k, v := range v6PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	changed, err = result.Add(v6Prefixes)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, false)
	c.Assert(result.v6, checker.DeepEquals, expectedPrefixLengths)

	// Now, remove them (changed: false)
	for k, v := range v6PrefixesLengths {
		expectedPrefixLengths[k] -= v
	}
	c.Assert(result.Delete(v6Prefixes), Equals, false)
	c.Assert(result.v6, checker.DeepEquals, expectedPrefixLengths)

	// Delete them again (changed: true)
	c.Assert(result.Delete(v6Prefixes), Equals, true)
	c.Assert(result.v6, checker.DeepEquals, IntCounter{})

	// Our v4 prefixes should still be here, unchanged
	expectedPrefixLengths = make(map[int]int, len(v4PrefixesLengths))
	for k, v := range v4PrefixesLengths {
		expectedPrefixLengths[k] += v
	}
	c.Assert(result.v4, checker.DeepEquals, expectedPrefixLengths)
}

func (cs *CounterTestSuite) TestCheckLimits(c *C) {
	result := NewPrefixLengthCounter(4, 4)
	c.Assert(checkLimits(0, 4, result.maxUniquePrefixes4), IsNil)
	c.Assert(checkLimits(0, 5, result.maxUniquePrefixes4), NotNil)
	c.Assert(checkLimits(0, 4, result.maxUniquePrefixes6), IsNil)
	c.Assert(checkLimits(0, 5, result.maxUniquePrefixes6), NotNil)

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.0.0.0/15"),
		netip.MustParsePrefix("192.0.2.2/31"),
		netip.MustParsePrefix("192.0.2.3/32"),
	}
	changed, err := result.Add(prefixes)
	c.Assert(err, IsNil)
	c.Assert(changed, Equals, true)

	changed, err = result.Add([]netip.Prefix{netip.MustParsePrefix("192.0.0.0/8")})
	c.Assert(err, NotNil)
	c.Assert(changed, Equals, false)
}

func (cs *CounterTestSuite) TestToBPFData(c *C) {
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
	c.Assert(err, IsNil)

	s6, s4 := result.ToBPFData()
	c.Assert(s6, checker.DeepEquals, []int{})
	c.Assert(s4, checker.DeepEquals, []int{32, 24, 20})
}

func (cs *CounterTestSuite) TestDefaultPrefixLengthCounter(c *C) {
	result := DefaultPrefixLengthCounter(net.IPv6len*8, net.IPv4len*8)
	c.Assert(result.v4[0], Equals, 1)
	c.Assert(result.v6[0], Equals, 1)
	c.Assert(result.v4[net.IPv4len*8], Equals, 1)
	c.Assert(result.v6[net.IPv6len*8], Equals, 1)
}
