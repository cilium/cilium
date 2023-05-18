// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"math/big"
	"net"
	"net/netip"
	"sort"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
type IPTestSuite struct{}

var _ = Suite(&IPTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *IPTestSuite) TestCountIPs(c *C) {
	tests := map[string]*big.Int{
		"192.168.0.1/32": big.NewInt(0),
		"192.168.0.1/31": big.NewInt(0).Sub(big.NewInt(1), big.NewInt(1)),
		"192.168.0.1/30": big.NewInt(2),
		"192.168.0.1/24": big.NewInt(254),
		"192.168.0.1/16": big.NewInt(65534),
		"::1/128":        big.NewInt(0),
		"::1/120":        big.NewInt(254),
		"fd02:1::/32":    big.NewInt(0).Sub(big.NewInt(2).Exp(big.NewInt(2), big.NewInt(96), nil), big.NewInt(2)),
	}
	for cidr, nIPs := range tests {
		_, ipnet, err := net.ParseCIDR(cidr)
		c.Assert(err, IsNil)
		count := CountIPsInCIDR(ipnet)
		c.Assert(count, checker.DeepEquals, nIPs)
	}
}

func (s *IPTestSuite) TestFirstIP(c *C) {
	// Test IPv4.
	desiredIPv4_1 := net.IP{0xa, 0, 0, 0}
	testNetv4_1 := net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(8, 32)}
	ipNetv4_1 := getNetworkPrefix(&testNetv4_1)
	for k := range *ipNetv4_1 {
		c.Assert((*ipNetv4_1)[k], Equals, desiredIPv4_1[k])
	}
	testNetv4_2 := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	ipNetv4_2 := getNetworkPrefix(&testNetv4_2)
	for k := range *ipNetv4_2 {
		c.Assert((*ipNetv4_2)[k], Equals, desiredIPv4_1[k])
	}

	// Test IPv6
	desiredIPv6_1, testNetv6_1, _ := net.ParseCIDR("fd44:7089:ff32:712b::/64")

	ipNetv6_1 := getNetworkPrefix(testNetv6_1)
	for k := range *ipNetv6_1 {
		c.Assert((*ipNetv6_1)[k], Equals, desiredIPv6_1[k])
	}
}

func (s *IPTestSuite) testIPNetsEqual(created, expected []*net.IPNet, c *C) {
	c.Assert(created, HasLen, len(expected))
	for index := range created {
		c.Assert(created[index].String(), Equals, expected[index].String())
		c.Assert(created[index].Mask.String(), Equals, expected[index].Mask.String())
	}
}

func (s *IPTestSuite) testIPsEqual(created, expected net.IP, c *C) {
	c.Assert(created, HasLen, len(expected))
	for k := range created {
		c.Assert(created[k], Equals, expected[k])
	}
}

func createIPNet(address string, maskSize int, bitLen int) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(address), Mask: net.CIDRMask(maskSize, bitLen)}
}

func createIPRange(first string, last string) *netWithRange {
	firstIP := net.ParseIP(first)
	lastIP := net.ParseIP(last)
	return &netWithRange{First: &firstIP, Last: &lastIP}
}

func (s *IPTestSuite) TestRemoveRedundant(c *C) {
	CIDRs := []*net.IPNet{
		createIPNet("10.96.0.0", 12, ipv4BitLen),
		createIPNet("10.112.0.0", 13, ipv4BitLen),
	}
	expectedCIDRs := []*net.IPNet{
		createIPNet("10.96.0.0", 12, ipv4BitLen),
		createIPNet("10.112.0.0", 13, ipv4BitLen),
	}
	nonRedundantCIDRs := removeRedundantCIDRs(CIDRs)
	s.testIPNetsEqual(nonRedundantCIDRs, expectedCIDRs, c)

	CIDRs = []*net.IPNet{
		createIPNet("10.96.0.0", 11, ipv4BitLen),
		createIPNet("10.112.0.0", 12, ipv4BitLen),
	}
	expectedCIDRs = []*net.IPNet{
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	nonRedundantCIDRs = removeRedundantCIDRs(CIDRs)
	s.testIPNetsEqual(nonRedundantCIDRs, expectedCIDRs, c)

	CIDRs = []*net.IPNet{
		createIPNet("10.112.0.0", 12, ipv4BitLen),
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	nonRedundantCIDRs = removeRedundantCIDRs(CIDRs)
	s.testIPNetsEqual(nonRedundantCIDRs, expectedCIDRs, c)

	CIDRs = []*net.IPNet{
		createIPNet("10.120.0.0", 13, ipv4BitLen),
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.112.0.0", 12, ipv4BitLen),
		createIPNet("10.62.0.33", 32, ipv4BitLen),
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	expectedCIDRs = []*net.IPNet{
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.62.0.33", 32, ipv4BitLen),
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	nonRedundantCIDRs = removeRedundantCIDRs(CIDRs)
	s.testIPNetsEqual(nonRedundantCIDRs, expectedCIDRs, c)

	CIDRs = []*net.IPNet{
		createIPNet("10.120.0.0", 13, ipv4BitLen),
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.112.0.0", 12, ipv4BitLen),
		createIPNet("10.62.0.33", 32, ipv4BitLen),
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	expectedCIDRs = []*net.IPNet{
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.62.0.33", 32, ipv4BitLen),
		createIPNet("10.96.0.0", 11, ipv4BitLen),
	}
	nonRedundantCIDRs = removeRedundantCIDRs(CIDRs)
	s.testIPNetsEqual(nonRedundantCIDRs, expectedCIDRs, c)
}

func (s *IPTestSuite) TestRemoveCIDRs(c *C) {
	allowCIDRs := []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	removeCIDRs := []*net.IPNet{createIPNet("10.96.0.0", 12, ipv4BitLen),
		createIPNet("10.112.0.0", 13, ipv4BitLen),
	}
	expectedCIDRs := []*net.IPNet{createIPNet("10.128.0.0", 9, ipv4BitLen),
		createIPNet("10.0.0.0", 10, ipv4BitLen),
		createIPNet("10.64.0.0", 11, ipv4BitLen),
		createIPNet("10.120.0.0", 13, ipv4BitLen)}
	allowedCIDRs := RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	// Removing superset removes the allowed CIDR
	allowCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 12, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	expectedCIDRs = []*net.IPNet{}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	allowCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 12, ipv4BitLen),
		createIPNet("10.112.0.0", 13, ipv4BitLen),
		createIPNet("10.62.0.33", 32, ipv4BitLen),
		createIPNet("10.93.0.4", 30, ipv4BitLen),
		createIPNet("10.63.0.5", 13, ipv4BitLen),
	}
	expectedCIDRs = []*net.IPNet{createIPNet("10.128.0.0", 9, ipv4BitLen),
		createIPNet("10.0.0.0", 11, ipv4BitLen),
		createIPNet("10.32.0.0", 12, ipv4BitLen),
		createIPNet("10.48.0.0", 13, ipv4BitLen),
		createIPNet("10.120.0.0", 13, ipv4BitLen),
		createIPNet("10.64.0.0", 12, ipv4BitLen),
		createIPNet("10.80.0.0", 13, ipv4BitLen),
		createIPNet("10.88.0.0", 14, ipv4BitLen),
		createIPNet("10.94.0.0", 15, ipv4BitLen),
		createIPNet("10.92.0.0", 16, ipv4BitLen),
		createIPNet("10.93.128.0", 17, ipv4BitLen),
		createIPNet("10.93.64.0", 18, ipv4BitLen),
		createIPNet("10.93.32.0", 19, ipv4BitLen),
		createIPNet("10.93.16.0", 20, ipv4BitLen),
		createIPNet("10.93.8.0", 21, ipv4BitLen),
		createIPNet("10.93.4.0", 22, ipv4BitLen),
		createIPNet("10.93.2.0", 23, ipv4BitLen),
		createIPNet("10.93.1.0", 24, ipv4BitLen),
		createIPNet("10.93.0.128", 25, ipv4BitLen),
		createIPNet("10.93.0.64", 26, ipv4BitLen),
		createIPNet("10.93.0.32", 27, ipv4BitLen),
		createIPNet("10.93.0.16", 28, ipv4BitLen),
		createIPNet("10.93.0.8", 29, ipv4BitLen),
		createIPNet("10.93.0.0", 30, ipv4BitLen),
	}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	// Cannot remove CIDRs that are of a different address family.
	allowCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b::", 66, ipv6BitLen)}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, allowCIDRs, c)

	allowCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("a000::", 8, ipv6BitLen)}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, allowCIDRs, c)

	allowCIDRs = []*net.IPNet{createIPNet("a000::", 8, ipv6BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen)}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, allowCIDRs, c)

	//IPv6 tests
	allowCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b:ff00::", 64, ipv6BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b::", 66, ipv6BitLen)}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	expectedCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b:8000::", 65, ipv6BitLen),
		createIPNet("fd44:7089:ff32:712b:4000::", 66, ipv6BitLen)}
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

}

func (s *IPTestSuite) TestRemoveSameCIDR(c *C) {
	allowCIDRs := []*net.IPNet{createIPNet("10.96.0.0", 32, ipv4BitLen)}

	allowedCIDRs := RemoveCIDRs(allowCIDRs, allowCIDRs)
	c.Assert(allowedCIDRs, HasLen, 0)
}

func (s *IPTestSuite) TestRemoveCIDRsEdgeCases(c *C) {
	// Remote some /32s
	allowCIDRs := []*net.IPNet{createIPNet("10.96.0.0", 30, ipv4BitLen)}
	removeCIDRs := []*net.IPNet{createIPNet("10.96.0.0", 32, ipv4BitLen), createIPNet("10.96.0.1", 32, ipv4BitLen)}
	expectedCIDRs := []*net.IPNet{createIPNet("10.96.0.2", 31, ipv4BitLen)}
	allowedCIDRs := RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	// Remove some subnets
	allowCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 22, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 24, ipv4BitLen), createIPNet("10.96.1.0", 24, ipv4BitLen)}
	expectedCIDRs = []*net.IPNet{createIPNet("10.96.2.0", 23, ipv4BitLen)}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	// Remove all subnets
	allowCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 23, ipv4BitLen)}
	removeCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 24, ipv4BitLen), createIPNet("10.96.1.0", 24, ipv4BitLen)}
	expectedCIDRs = []*net.IPNet{}
	allowedCIDRs = RemoveCIDRs(allowCIDRs, removeCIDRs)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)
}

func (s *IPTestSuite) TestByteFunctions(c *C) {
	//flipNthHighestBit
	testBytes := net.IP{0x0, 0x0, 0x0, 0x0}
	expectedBytes := net.IP{0x0, 0x0, 0x0, 0x80}
	flipNthHighestBit(testBytes, 24)
	for k := range expectedBytes {
		c.Assert(expectedBytes[k], Equals, testBytes[k])
	}

	testBytes = net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}
	expectedBytes = net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0}
	flipNthHighestBit(testBytes, 95)
	for k := range expectedBytes {
		c.Assert(expectedBytes[k], Equals, testBytes[k])
	}
}

func (s *IPTestSuite) TestIPNetToRange(c *C) {

	testRange := ipNetToRange(*createIPNet("192.0.128.0", 24, ipv4BitLen))
	var expectedFirst, expectedLast []byte
	expectedFirst = append(expectedFirst, v4Mappedv6Prefix...)
	expectedFirst = append(expectedFirst, []byte{192, 0, 128, 0}...)
	expectedFirstIP := net.IP(expectedFirst)

	expectedLast = append(expectedLast, v4Mappedv6Prefix...)
	expectedLast = append(expectedLast, []byte{192, 0, 128, 255}...)
	expectedLastIP := net.IP(expectedLast)
	expectedRange := netWithRange{First: &expectedFirstIP, Last: &expectedLastIP}

	s.checkRangesEqual(&expectedRange, &testRange, c)

	// Check that all bits are masked correctly.
	testRange = ipNetToRange(*createIPNet("192.0.128.255", 24, ipv4BitLen))
	s.checkRangesEqual(&expectedRange, &testRange, c)

	testRange = ipNetToRange(*createIPNet("fd44:7089:ff32:712b:ff00::", 64, ipv6BitLen))
	testRange = ipNetToRange(*createIPNet("::ffff:0", 128, ipv6BitLen))

}

func (s *IPTestSuite) checkRangesEqual(range1, range2 *netWithRange, c *C) {
	for l := range *range1.First {
		c.Assert((*range1.First)[l], Equals, (*range2.First)[l])
	}
	for l := range *range1.Last {
		c.Assert((*range1.Last)[l], Equals, (*range2.Last)[l])
	}
}

func (s *IPTestSuite) TestNetsByRange(c *C) {
	ranges := []*netWithRange{}

	// Check sorting by last IP first
	cidrs := []*net.IPNet{createIPNet("10.0.0.0", 8, ipv4BitLen),
		createIPNet("10.0.0.0", 10, ipv4BitLen),
		createIPNet("10.64.0.0", 11, ipv4BitLen),
		createIPNet("10.112.0.0", 12, ipv4BitLen)}

	for _, network := range cidrs {
		newNetToRange := ipNetToRange(*network)
		ranges = append(ranges, &newNetToRange)
	}

	expectedRanges := []*netWithRange{
		createIPRange("10.0.0.0", "10.63.255.255"),
		createIPRange("10.64.0.0", "10.95.255.255"),
		createIPRange("10.112.0.0", "10.127.255.255"),
		createIPRange("10.0.0.0", "10.255.255.255")}
	sort.Sort(NetsByRange(ranges))
	// Ensure that length of ranges isn't modified first.
	c.Assert(len(ranges), Equals, len(expectedRanges))
	for k := range ranges {
		s.checkRangesEqual(ranges[k], expectedRanges[k], c)
	}

	ranges = []*netWithRange{createIPRange("10.0.0.0", "10.255.255.255"),
		createIPRange("10.255.255.254", "10.255.255.255")}
	expectedRanges = []*netWithRange{createIPRange("10.0.0.0", "10.255.255.255"),
		createIPRange("10.255.255.254", "10.255.255.255")}
	sort.Sort(NetsByRange(ranges))
	// Ensure that length of ranges isn't modified first.
	c.Assert(len(ranges), Equals, len(expectedRanges))
	for k := range ranges {
		s.checkRangesEqual(ranges[k], expectedRanges[k], c)
	}

}

func (s *IPTestSuite) TestCoalesceCIDRs(c *C) {

	cidrs := []*net.IPNet{createIPNet("192.0.128.0", 24, ipv4BitLen),
		createIPNet("192.0.129.0", 24, ipv4BitLen)}
	expected := []*net.IPNet{createIPNet("192.0.128.0", 23, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs := CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.129.0", 24, ipv4BitLen),
		createIPNet("192.0.130.0", 24, ipv4BitLen)}
	expected = []*net.IPNet{createIPNet("192.0.129.0", 24, ipv4BitLen),
		createIPNet("192.0.130.0", 24, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 30, ipv4BitLen),
		createIPNet("192.0.2.116", 31, ipv4BitLen),
		createIPNet("192.0.2.118", 31, ipv4BitLen)}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 29, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 30, ipv4BitLen),
		createIPNet("192.0.2.116", 32, ipv4BitLen),
		createIPNet("192.0.2.118", 31, ipv4BitLen)}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 30, ipv4BitLen),
		createIPNet("192.0.2.116", 32, ipv4BitLen),
		createIPNet("192.0.2.118", 31, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 31, ipv4BitLen),
		createIPNet("192.0.2.116", 31, ipv4BitLen),
		createIPNet("192.0.2.118", 31, ipv4BitLen)}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 31, ipv4BitLen),
		createIPNet("192.0.2.116", 30, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.1.254", 31, ipv4BitLen),
		createIPNet("192.0.2.0", 28, ipv4BitLen),
		createIPNet("192.0.2.16", 28, ipv4BitLen),
		createIPNet("192.0.2.32", 28, ipv4BitLen),
		createIPNet("192.0.2.48", 28, ipv4BitLen),
		createIPNet("192.0.2.64", 28, ipv4BitLen),
		createIPNet("192.0.2.80", 28, ipv4BitLen),
		createIPNet("192.0.2.96", 28, ipv4BitLen),
		createIPNet("192.0.2.112", 28, ipv4BitLen),
		createIPNet("192.0.2.128", 28, ipv4BitLen),
		createIPNet("192.0.2.144", 28, ipv4BitLen),
		createIPNet("192.0.2.160", 28, ipv4BitLen),
		createIPNet("192.0.2.176", 28, ipv4BitLen),
		createIPNet("192.0.2.192", 28, ipv4BitLen),
		createIPNet("192.0.2.208", 28, ipv4BitLen),
		createIPNet("192.0.2.224", 28, ipv4BitLen),
		createIPNet("192.0.2.240", 28, ipv4BitLen),
		createIPNet("192.0.3.0", 28, ipv4BitLen),
	}

	expected = []*net.IPNet{createIPNet("192.0.1.254", 31, ipv4BitLen),
		createIPNet("192.0.2.0", 24, ipv4BitLen),
		createIPNet("192.0.3.0", 28, ipv4BitLen)}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("::", 0, ipv6BitLen),
		createIPNet("fe80::1", 128, ipv6BitLen)}
	expected = []*net.IPNet{createIPNet("::", 0, ipv6BitLen)}
	_, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV6CIDRs, expected, c)

	// assert cidr_merge(['::/0', '::192.0.2.0/124', 'ff00::101']) == [IPNetwork('::/0')]
	cidrs = []*net.IPNet{createIPNet("::", 0, ipv6BitLen),
		createIPNet("::192.0.2.0", 124, ipv6BitLen),
		createIPNet("ff00::101", 128, ipv6BitLen)}
	_, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV6CIDRs, expected, c)
}

func (s *IPTestSuite) TestRangeToCIDRs(c *C) {
	// IPv4 worst case.
	ipNets := rangeToCIDRs(net.ParseIP("0.0.0.1"), net.ParseIP("255.255.255.254"))
	expected := []*net.IPNet{createIPNet("0.0.0.1", 32, ipv4BitLen),
		createIPNet("0.0.0.2", 31, ipv4BitLen),
		createIPNet("0.0.0.4", 30, ipv4BitLen),
		createIPNet("0.0.0.8", 29, ipv4BitLen),
		createIPNet("0.0.0.16", 28, ipv4BitLen),
		createIPNet("0.0.0.32", 27, ipv4BitLen),
		createIPNet("0.0.0.64", 26, ipv4BitLen),
		createIPNet("0.0.0.128", 25, ipv4BitLen),
		createIPNet("0.0.1.0", 24, ipv4BitLen),
		createIPNet("0.0.2.0", 23, ipv4BitLen),
		createIPNet("0.0.4.0", 22, ipv4BitLen),
		createIPNet("0.0.8.0", 21, ipv4BitLen),
		createIPNet("0.0.16.0", 20, ipv4BitLen),
		createIPNet("0.0.32.0", 19, ipv4BitLen),
		createIPNet("0.0.64.0", 18, ipv4BitLen),
		createIPNet("0.0.128.0", 17, ipv4BitLen),
		createIPNet("0.1.0.0", 16, ipv4BitLen),
		createIPNet("0.2.0.0", 15, ipv4BitLen),
		createIPNet("0.4.0.0", 14, ipv4BitLen),
		createIPNet("0.8.0.0", 13, ipv4BitLen),
		createIPNet("0.16.0.0", 12, ipv4BitLen),
		createIPNet("0.32.0.0", 11, ipv4BitLen),
		createIPNet("0.64.0.0", 10, ipv4BitLen),
		createIPNet("0.128.0.0", 9, ipv4BitLen),
		createIPNet("1.0.0.0", 8, ipv4BitLen),
		createIPNet("2.0.0.0", 7, ipv4BitLen),
		createIPNet("4.0.0.0", 6, ipv4BitLen),
		createIPNet("8.0.0.0", 5, ipv4BitLen),
		createIPNet("16.0.0.0", 4, ipv4BitLen),
		createIPNet("32.0.0.0", 3, ipv4BitLen),
		createIPNet("64.0.0.0", 2, ipv4BitLen),
		createIPNet("128.0.0.0", 2, ipv4BitLen),
		createIPNet("192.0.0.0", 3, ipv4BitLen),
		createIPNet("224.0.0.0", 4, ipv4BitLen),
		createIPNet("240.0.0.0", 5, ipv4BitLen),
		createIPNet("248.0.0.0", 6, ipv4BitLen),
		createIPNet("252.0.0.0", 7, ipv4BitLen),
		createIPNet("254.0.0.0", 8, ipv4BitLen),
		createIPNet("255.0.0.0", 9, ipv4BitLen),
		createIPNet("255.128.0.0", 10, ipv4BitLen),
		createIPNet("255.192.0.0", 11, ipv4BitLen),
		createIPNet("255.224.0.0", 12, ipv4BitLen),
		createIPNet("255.240.0.0", 13, ipv4BitLen),
		createIPNet("255.248.0.0", 14, ipv4BitLen),
		createIPNet("255.252.0.0", 15, ipv4BitLen),
		createIPNet("255.254.0.0", 16, ipv4BitLen),
		createIPNet("255.255.0.0", 17, ipv4BitLen),
		createIPNet("255.255.128.0", 18, ipv4BitLen),
		createIPNet("255.255.192.0", 19, ipv4BitLen),
		createIPNet("255.255.224.0", 20, ipv4BitLen),
		createIPNet("255.255.240.0", 21, ipv4BitLen),
		createIPNet("255.255.249.0", 22, ipv4BitLen),
		createIPNet("255.255.252.0", 23, ipv4BitLen),
		createIPNet("255.255.254.0", 24, ipv4BitLen),
		createIPNet("255.255.255.0", 25, ipv4BitLen),
		createIPNet("255.255.255.128", 26, ipv4BitLen),
		createIPNet("255.255.255.192", 27, ipv4BitLen),
		createIPNet("255.255.255.224", 28, ipv4BitLen),
		createIPNet("255.255.255.240", 29, ipv4BitLen),
		createIPNet("255.255.255.248", 30, ipv4BitLen),
		createIPNet("255.255.255.252", 31, ipv4BitLen),
		createIPNet("255.255.255.254", 32, ipv4BitLen),
	}

	// Sort both so we can compare easily
	sort.Sort(NetsByMask(expected))
	sort.Sort(NetsByMask(ipNets))
	c.Assert(len(ipNets), Equals, len(expected))
}

func (s *IPTestSuite) TestPreviousIP(c *C) {
	ip := net.ParseIP("10.0.0.0")
	expectedPrev := net.ParseIP("9.255.255.255")
	prevIP := getPreviousIP(ip)
	s.testIPsEqual(prevIP, expectedPrev, c)

	// Check that underflow does not occur.
	ip = net.ParseIP("0.0.0.0")
	prevIP = getPreviousIP(ip)
	expectedPrev = ip
	s.testIPsEqual(prevIP, expectedPrev, c)

	ip = net.ParseIP("::")
	prevIP = getPreviousIP(ip)
	expectedPrev = ip
	s.testIPsEqual(prevIP, expectedPrev, c)

	ip = net.ParseIP("10.0.0.1")
	prevIP = getPreviousIP(ip)
	expectedPrev = net.ParseIP("10.0.0.0")
	s.testIPsEqual(prevIP, expectedPrev, c)

	ip = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	expectedPrev = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	prevIP = getPreviousIP(ip)
	s.testIPsEqual(prevIP, expectedPrev, c)
}

func (s *IPTestSuite) TestNextIP(c *C) {
	expectedNext := net.ParseIP("10.0.0.0")
	ip := net.ParseIP("9.255.255.255")
	nextIP := GetNextIP(ip)
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	// Check that overflow does not occur.
	ip = net.ParseIP("255.255.255.255")
	nextIP = GetNextIP(ip)
	expectedNext = ip
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	nextIP = GetNextIP(ip)
	expectedNext = ip
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = []byte{0xa, 0, 0, 0}
	nextIP = GetNextIP(ip)
	expectedNext = []byte{0xa, 0, 0, 1}
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = []byte{0xff, 0xff, 0xff, 0xff}
	nextIP = GetNextIP(ip)
	expectedNext = []byte{0xff, 0xff, 0xff, 0xff}
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = net.ParseIP("10.0.0.0")
	nextIP = GetNextIP(ip)
	expectedNext = net.ParseIP("10.0.0.1")
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = net.ParseIP("0:0:0:0:ffff:ffff:ffff:ffff")
	nextIP = GetNextIP(ip)
	expectedNext = net.ParseIP("0:0:0:1:0:0:0:0")
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = net.ParseIP("ffff:ffff:ffff:fffe:ffff:ffff:ffff:ffff")
	nextIP = GetNextIP(ip)
	expectedNext = net.ParseIP("ffff:ffff:ffff:ffff:0:0:0:0")
	c.Assert(nextIP, checker.DeepEquals, expectedNext)

	ip = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	nextIP = GetNextIP(ip)
	expectedNext = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	c.Assert(nextIP, checker.DeepEquals, expectedNext)
}

func (s *IPTestSuite) TestCreateSpanningCIDR(c *C) {
	netRange := createIPRange("10.0.0.0", "10.255.255.255")
	expectedSpanningCIDR := createIPNet("10.0.0.0", 8, ipv4BitLen)
	spanningCIDR := createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.0", "10.255.255.254")
	expectedSpanningCIDR = createIPNet("10.0.0.0", 8, ipv4BitLen)
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.1", "10.0.0.1")
	expectedSpanningCIDR = createIPNet("10.0.0.1", 32, ipv4BitLen)
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.1", "10.0.0.2")
	expectedSpanningCIDR = createIPNet("10.0.0.0", 30, ipv4BitLen)
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("9.0.0.0", "10.0.0.0")
	expectedSpanningCIDR = createIPNet("8.0.0.0", 6, ipv4BitLen)
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("FD44:7089:FF32:712B:FF00:0000:0000:0000", "FD44:7089:FF32:712B:FFFF:FFFF:FFFF:FFFF")
	expectedSpanningCIDR = createIPNet("fd44:7089:ff32:712b:ff00::", 72, ipv6BitLen)
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

}

func (s *IPTestSuite) TestPartitionCIDR(c *C) {
	targetCIDR := createIPNet("10.0.0.0", 8, ipv4BitLen)
	excludeCIDR := createIPNet("10.255.255.255", 32, ipv4BitLen)
	left, exclude, right := PartitionCIDR(*targetCIDR, *excludeCIDR)
	// Exclude should just contain exclude CIDR
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
	// Nothing should be in right list.
	c.Assert(len(right), Equals, 0)
	expectedLeft := []*net.IPNet{createIPNet("10.0.0.0", 9, ipv4BitLen),
		createIPNet("10.128.0.0", 10, ipv4BitLen),
		createIPNet("10.192.0.0", 11, ipv4BitLen),
		createIPNet("10.224.0.0", 12, ipv4BitLen),
		createIPNet("10.240.0.0", 13, ipv4BitLen),
		createIPNet("10.248.0.0", 14, ipv4BitLen),
		createIPNet("10.252.0.0", 15, ipv4BitLen),
		createIPNet("10.254.0.0", 16, ipv4BitLen),
		createIPNet("10.255.0.0", 17, ipv4BitLen),
		createIPNet("10.255.128.0", 18, ipv4BitLen),
		createIPNet("10.255.192.0", 19, ipv4BitLen),
		createIPNet("10.255.224.0", 20, ipv4BitLen),
		createIPNet("10.255.240.0", 21, ipv4BitLen),
		createIPNet("10.255.248.0", 22, ipv4BitLen),
		createIPNet("10.255.252.0", 23, ipv4BitLen),
		createIPNet("10.255.254.0", 24, ipv4BitLen),
		createIPNet("10.255.255.0", 25, ipv4BitLen),
		createIPNet("10.255.255.128", 26, ipv4BitLen),
		createIPNet("10.255.255.192", 27, ipv4BitLen),
		createIPNet("10.255.255.224", 28, ipv4BitLen),
		createIPNet("10.255.255.240", 29, ipv4BitLen),
		createIPNet("10.255.255.248", 30, ipv4BitLen),
		createIPNet("10.255.255.252", 31, ipv4BitLen),
		createIPNet("10.255.255.254", 32, ipv4BitLen),
	}
	s.testIPNetsEqual(expectedLeft, left, c)

	targetCIDR = createIPNet("10.0.0.0", 8, ipv4BitLen)
	excludeCIDR = createIPNet("10.0.0.0", 32, ipv4BitLen)
	left, exclude, right = PartitionCIDR(*targetCIDR, *excludeCIDR)
	// Exclude should just contain exclude CIDR
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
	// Nothing should be in left list.
	c.Assert(len(left), Equals, 0)
	expectedRight := []*net.IPNet{createIPNet("10.128.0.0", 9, ipv4BitLen),
		createIPNet("10.64.0.0", 10, ipv4BitLen),
		createIPNet("10.32.0.0", 11, ipv4BitLen),
		createIPNet("10.16.0.0", 12, ipv4BitLen),
		createIPNet("10.8.0.0", 13, ipv4BitLen),
		createIPNet("10.4.0.0", 14, ipv4BitLen),
		createIPNet("10.2.0.0", 15, ipv4BitLen),
		createIPNet("10.1.0.0", 16, ipv4BitLen),
		createIPNet("10.0.128.0", 17, ipv4BitLen),
		createIPNet("10.0.64.0", 18, ipv4BitLen),
		createIPNet("10.0.32.0", 19, ipv4BitLen),
		createIPNet("10.0.16.0", 20, ipv4BitLen),
		createIPNet("10.0.8.0", 21, ipv4BitLen),
		createIPNet("10.0.4.0", 22, ipv4BitLen),
		createIPNet("10.0.2.0", 23, ipv4BitLen),
		createIPNet("10.0.1.0", 24, ipv4BitLen),
		createIPNet("10.0.0.128", 25, ipv4BitLen),
		createIPNet("10.0.0.64", 26, ipv4BitLen),
		createIPNet("10.0.0.32", 27, ipv4BitLen),
		createIPNet("10.0.0.16", 28, ipv4BitLen),
		createIPNet("10.0.0.8", 29, ipv4BitLen),
		createIPNet("10.0.0.4", 30, ipv4BitLen),
		createIPNet("10.0.0.2", 31, ipv4BitLen),
		createIPNet("10.0.0.1", 32, ipv4BitLen),
	}
	s.testIPNetsEqual(expectedRight, right, c)

	// exclude is not in target CIDR and is to left.
	targetCIDR = createIPNet("10.0.0.0", 8, ipv4BitLen)
	excludeCIDR = createIPNet("9.0.0.255", 32, ipv4BitLen)
	left, exclude, right = PartitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(left), Equals, 0)
	c.Assert(len(exclude), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, right, c)

	// exclude is not in target CIDR and is to right.
	targetCIDR = createIPNet("10.255.255.254", 32, ipv4BitLen)
	excludeCIDR = createIPNet("10.255.255.255", 32, ipv4BitLen)
	left, exclude, right = PartitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(right), Equals, 0)
	c.Assert(len(exclude), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, left, c)

	// exclude CIDR larger than target CIDR
	targetCIDR = createIPNet("10.96.0.0", 12, ipv4BitLen)
	excludeCIDR = createIPNet("10.0.0.0", 8, ipv4BitLen)
	left, exclude, right = PartitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(left), Equals, 0)
	c.Assert(len(right), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, exclude, c)

	targetCIDR = createIPNet("fd44:7089:ff32:712b:ff00::", 64, ipv6BitLen)
	excludeCIDR = createIPNet("fd44:7089:ff32:712b::", 66, ipv6BitLen)

	_, exclude, right = PartitionCIDR(*targetCIDR, *excludeCIDR)

	expectedCIDRs := []*net.IPNet{createIPNet("fd44:7089:ff32:712b:8000::", 65, ipv6BitLen),
		createIPNet("fd44:7089:ff32:712b:4000::", 66, ipv6BitLen)}
	s.testIPNetsEqual(expectedCIDRs, right, c)
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
}

// TestKeepUniqueIPs tests that KeepUniqueIPs returns a slice with only the unique IPs
func (s *IPTestSuite) TestKeepUniqueIPs(c *C) {
	// test nil/empty handling
	ips := KeepUniqueIPs(nil)
	c.Assert(len(ips), Equals, 0, Commentf("Non-empty slice returned with empty input"))

	// test all duplicate
	ips = KeepUniqueIPs([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1")})
	c.Assert(len(ips), Equals, 1, Commentf("Too many IPs returned for only 1 unique"))
	c.Assert(ips[0].String(), Equals, "1.1.1.1", Commentf("Incorrect unique IP returned"))

	// test all unique
	ipSource := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3")}
	ips = KeepUniqueIPs(ipSource)
	c.Assert(len(ips), Equals, 3, Commentf("Too few IPs returned for only 3 uniques"))
	for i := range ipSource {
		c.Assert(ips[i].String(), Equals, ipSource[i].String(), Commentf("Incorrect unique IP returned"))
	}

	// test mixed
	ipSource = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3"), net.ParseIP("2.2.2.2")}
	ips = KeepUniqueIPs(ipSource)
	c.Assert(len(ips), Equals, 3, Commentf("Too few IPs returned for only 3 uniques"))
	for i := range ipSource[:3] {
		c.Assert(ips[i].String(), Equals, ipSource[i].String(), Commentf("Incorrect unique IP returned"))
	}
}

func TestKeepUniqueAddrs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []netip.Addr
		want  []netip.Addr
	}{
		{
			name:  "nil slice",
			addrs: nil,
			want:  nil,
		},
		{
			name:  "empty slice",
			addrs: []netip.Addr{},
			want:  []netip.Addr{},
		},
		{
			name:  "one element slice",
			addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			want:  []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		},
		{
			name: "IPv4 all duplicates",
			addrs: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("1.1.1.1"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
			},
		},
		{
			name: "IPv4 all unique",
			addrs: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("3.3.3.3"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("3.3.3.3"),
			},
		},
		{
			name: "IPv4 mixed",
			addrs: []netip.Addr{
				netip.MustParseAddr("3.3.3.3"),
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("2.2.2.2"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("3.3.3.3"),
			},
		},
		{
			name: "IPv6 all duplicates",
			addrs: []netip.Addr{
				netip.MustParseAddr("f00d::1"),
				netip.MustParseAddr("f00d::1"),
				netip.MustParseAddr("f00d::1"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("f00d::1"),
			},
		},
		{
			name: "Mixed IPv4 & IPv6",
			addrs: []netip.Addr{
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("f00d::1"),
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("f00d::1"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("f00d::1"),
			},
		},
		{
			name: "With IPv6-in-IPv6",
			addrs: []netip.Addr{
				netip.MustParseAddr("::ffff:0101:0101"),
				netip.MustParseAddr("::ffff:1.1.1.1"),
				netip.MustParseAddr("1.1.1.1"),
			},
			want: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::ffff:1.1.1.1"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := KeepUniqueAddrs(tc.addrs)
			if len(tc.want) != len(got) {
				t.Errorf("%s: KeepUniqueAddrs(%q): got %d unique addresses, want %d",
					tc.name, tc.addrs, len(got), len(tc.want))
			}
			for i := range got {
				if tc.want[i] != got[i] {
					t.Errorf("%s: KeepUniqueAddrs(%q): mismatching address at index %d: got %v, want %v",
						tc.name, tc.addrs, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func (s *IPTestSuite) TestIPVersion(c *C) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name string
		args args
		v4   bool
		v6   bool
	}{
		{
			name: "test-1",
			args: args{
				ip: nil,
			},
			v4: false,
			v6: false,
		},
		{
			name: "test-2",
			args: args{
				ip: net.ParseIP("1.1.1.1"),
			},
			v4: true,
			v6: false,
		},
		{
			name: "test-3",
			args: args{
				ip: net.ParseIP("fd00::1"),
			},
			v4: false,
			v6: true,
		},
	}
	for _, tt := range tests {
		got := IsIPv4(tt.args.ip)
		c.Assert(got, checker.DeepEquals, tt.v4, Commentf("v4 test Name: %s", tt.name))

		got = IsIPv6(tt.args.ip)
		c.Assert(got, checker.DeepEquals, tt.v6, Commentf("v6 test Name: %s", tt.name))
	}
}

func (s *IPTestSuite) TestIPListEquals(c *C) {
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("fd00::1"), net.ParseIP("8.8.8.8")}
	sorted := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8"), net.ParseIP("fd00::1")}

	sortedIPs := getSortedIPList(ips)
	c.Assert(SortedIPListsAreEqual(sorted, sortedIPs), checker.Equals, true)

	c.Assert(UnsortedIPListsAreEqual(ips, sorted), checker.Equals, true)
}

func (s *IPTestSuite) TestGetIPFromListByFamily(c *C) {
	tests := []struct {
		name          string
		ips           []net.IP
		needsV4Family bool
		wants         net.IP
	}{
		{
			name:          "test-1",
			ips:           []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("fd00::1"), net.ParseIP("8.8.8.8")},
			needsV4Family: true,
			wants:         net.ParseIP("1.1.1.1"),
		},
		{
			name:          "test-2",
			ips:           []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("fd00::1"), net.ParseIP("8.8.8.8")},
			needsV4Family: false,
			wants:         net.ParseIP("fd00::1"),
		},
		{
			name:          "test-2",
			ips:           []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
			needsV4Family: false,
			wants:         nil,
		},
	}

	for _, tt := range tests {
		got := GetIPFromListByFamily(tt.ips, tt.needsV4Family)
		c.Assert(got.String(), checker.DeepEquals, tt.wants.String(), Commentf("Test Name: %s", tt.name))
	}
}

func (s *IPTestSuite) TestGetIPAtIndex(c *C) {
	type args struct {
		cidr  string
		index int64
		want  net.IP
	}

	tests := []args{
		{
			cidr:  "10.0.0.0/29",
			index: -1,
			want:  net.ParseIP("10.0.0.7"),
		}, {
			cidr:  "10.0.0.0/29",
			index: 0,
			want:  net.ParseIP("10.0.0.0"),
		}, {
			cidr:  "10.0.0.0/29",
			index: 1,
			want:  net.ParseIP("10.0.0.1"),
		}, {
			cidr:  "10.0.0.16/28",
			index: -3,
			want:  net.ParseIP("10.0.0.29"),
		}, {
			cidr:  "10.0.0.0/29",
			index: -3,
			want:  net.ParseIP("10.0.0.5"),
		}, {
			cidr:  "10.0.0.0/25",
			index: -3,
			want:  net.ParseIP("10.0.0.125"),
		}, {
			cidr:  "10.0.0.128/25",
			index: -3,
			want:  net.ParseIP("10.0.0.253"),
		}, {
			cidr:  "10.0.8.0/21",
			index: -3,
			want:  net.ParseIP("10.0.15.253"),
		}, {
			cidr:  "fd00::/64",
			index: -3,
			want:  net.ParseIP("fd00::ffff:ffff:ffff:fffd"),
		},
	}
	for _, tt := range tests {
		_, ipNet, _ := net.ParseCIDR(tt.cidr)
		if got := GetIPAtIndex(*ipNet, tt.index); !got.Equal(tt.want) {
			c.Errorf("GetIPAtIndex() = %v, want %v", got, tt.want)
		}

	}
}

func (s *IPTestSuite) TestAddrFromIP(c *C) {
	type args struct {
		ip       net.IP
		wantAddr netip.Addr
		wantOk   bool
	}

	tests := []args{
		{
			net.ParseIP("10.0.0.1"),
			netip.MustParseAddr("10.0.0.1"),
			true,
		},
		{
			net.ParseIP("a::1"),
			netip.MustParseAddr("a::1"),
			true,
		},
		{
			net.ParseIP("::ffff:10.0.0.1"),
			netip.MustParseAddr("10.0.0.1"),
			true,
		},
	}
	for _, tt := range tests {
		addr, ok := AddrFromIP(tt.ip)
		if ok != tt.wantOk {
			c.Errorf("AddrFromIP(net.IP(%v)) should success", []byte(tt.ip))
		}

		if addr != tt.wantAddr {
			c.Errorf("AddrFromIP(net.IP(%v)) = %v want %v", []byte(tt.ip), addr, tt.wantAddr)
		}
	}
}

func (s *IPTestSuite) TestMustAddrsFromIPs(c *C) {
	type args struct {
		ips   []net.IP
		addrs []netip.Addr
	}
	for _, tt := range []args{
		{
			ips:   []net.IP{},
			addrs: []netip.Addr{},
		},
		{
			ips:   []net.IP{net.ParseIP("1.1.1.1")},
			addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		},
		{
			ips:   []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("0.0.0.0")},
			addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("0.0.0.0")},
		},
	} {
		addrs := MustAddrsFromIPs(tt.ips)
		c.Assert(addrs, checker.DeepEquals, tt.addrs)
	}

	nilIPs := []net.IP{nil}
	defer func() {
		if r := recover(); r == nil {
			c.Errorf("MustAddrsFromIPs(%v) should panic", nilIPs)
		}
	}()
	_ = MustAddrsFromIPs(nilIPs)
}
