// Copyright 2017 Authors of Cilium
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

package ip

import (
	"net"
	"sort"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type IPTestSuite struct{}

var _ = Suite(&IPTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
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
	for index := range created {
		c.Assert(created[index].String(), Equals, expected[index].String())
		c.Assert(created[index].Mask.String(), Equals, expected[index].Mask.String())
	}
}

func (s *IPTestSuite) testIPsEqual(created, expected net.IP, c *C) {
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

func (s *IPTestSuite) TestRemoveCIDRs(c *C) {
	allowCIDRs := []*net.IPNet{createIPNet("10.0.0.0", 8, int(ipv4BitLen))}
	removeCIDRs := []*net.IPNet{createIPNet("10.96.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.112.0.0", 13, int(ipv4BitLen)),
	}
	expectedCIDRs := []*net.IPNet{createIPNet("10.128.0.0", 9, int(ipv4BitLen)),
		createIPNet("10.0.0.0", 10, int(ipv4BitLen)),
		createIPNet("10.64.0.0", 11, int(ipv4BitLen)),
		createIPNet("10.120.0.0", 13, int(ipv4BitLen))}

	allowedCIDRs, err := RemoveCIDRs(allowCIDRs, removeCIDRs)
	c.Assert(err, IsNil)

	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	allowCIDRs = []*net.IPNet{createIPNet("10.0.0.0", 8, int(ipv4BitLen))}
	removeCIDRs = []*net.IPNet{createIPNet("10.96.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.112.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.62.0.33", 32, int(ipv4BitLen)),
		createIPNet("10.93.0.4", 30, int(ipv4BitLen)),
		createIPNet("10.63.0.5", 13, int(ipv4BitLen)),
	}

	expectedCIDRs = []*net.IPNet{createIPNet("10.128.0.0", 9, int(ipv4BitLen)),
		createIPNet("10.0.0.0", 11, int(ipv4BitLen)),
		createIPNet("10.32.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.48.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.120.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.64.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.80.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.88.0.0", 14, int(ipv4BitLen)),
		createIPNet("10.94.0.0", 15, int(ipv4BitLen)),
		createIPNet("10.92.0.0", 16, int(ipv4BitLen)),
		createIPNet("10.93.128.0", 17, int(ipv4BitLen)),
		createIPNet("10.93.64.0", 18, int(ipv4BitLen)),
		createIPNet("10.93.32.0", 19, int(ipv4BitLen)),
		createIPNet("10.93.16.0", 20, int(ipv4BitLen)),
		createIPNet("10.93.8.0", 21, int(ipv4BitLen)),
		createIPNet("10.93.4.0", 22, int(ipv4BitLen)),
		createIPNet("10.93.2.0", 23, int(ipv4BitLen)),
		createIPNet("10.93.1.0", 24, int(ipv4BitLen)),
		createIPNet("10.93.0.128", 25, int(ipv4BitLen)),
		createIPNet("10.93.0.64", 26, int(ipv4BitLen)),
		createIPNet("10.93.0.32", 27, int(ipv4BitLen)),
		createIPNet("10.93.0.16", 28, int(ipv4BitLen)),
		createIPNet("10.93.0.8", 29, int(ipv4BitLen)),
		createIPNet("10.93.0.0", 30, int(ipv4BitLen)),
	}

	allowedCIDRs, err = RemoveCIDRs(allowCIDRs, removeCIDRs)
	c.Assert(err, IsNil)
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

	// Cannot remove CIDRs that are of a different address family.
	removeCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b::", 66, int(ipv6BitLen))}
	allowedCIDRs, err = RemoveCIDRs(allowCIDRs, removeCIDRs)
	c.Assert(err, NotNil)

	//IPv6 tests
	allowCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b:ff00::", 64, int(ipv6BitLen))}
	allowedCIDRs, err = RemoveCIDRs(allowCIDRs, removeCIDRs)

	c.Assert(err, IsNil)
	expectedCIDRs = []*net.IPNet{createIPNet("fd44:7089:ff32:712b:8000::", 65, int(ipv6BitLen)),
		createIPNet("fd44:7089:ff32:712b:4000::", 66, int(ipv6BitLen))}
	s.testIPNetsEqual(allowedCIDRs, expectedCIDRs, c)

}

func (s *IPTestSuite) TestByteFunctions(c *C) {

	//getByteIndexofBit
	byteNum := getByteIndexOfBit(0)
	c.Assert(byteNum, Equals, uint(15))
	byteNum = getByteIndexOfBit(1)
	c.Assert(byteNum, Equals, uint(15))
	byteNum = getByteIndexOfBit(8)
	c.Assert(byteNum, Equals, uint(14))
	byteNum = getByteIndexOfBit(9)
	c.Assert(byteNum, Equals, uint(14))

	//getNthBit
	testNet := net.IPNet{IP: net.ParseIP("10.96.0.0"), Mask: net.CIDRMask(12, int(ipv4BitLen))}
	bit := getNthBit(&(testNet.IP), 20)
	c.Assert(bit, Equals, uint8(0))
	bit = getNthBit(&(testNet.IP), 22)
	c.Assert(bit, Equals, uint8(1))

	//flipNthBit
	testBytes := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}
	newBytes := flipNthBit(&testBytes, 10)
	expectedBytes := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x4, 0x0}
	for k := range expectedBytes {
		c.Assert(expectedBytes[k], Equals, (*newBytes)[k])
	}

	newBytes = flipNthBit(&testBytes, 32)
	expectedBytes = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0}
	for k := range expectedBytes {
		c.Assert(expectedBytes[k], Equals, (*newBytes)[k])
	}

}

func (s *IPTestSuite) TestIPNetToRange(c *C) {

	testRange := ipNetToRange(*createIPNet("192.0.128.0", 24, int(ipv4BitLen)))
	var expectedFirst, expectedLast []byte
	expectedFirst = append(expectedFirst, v4Asv6...)
	expectedFirst = append(expectedFirst, []byte{192, 0, 128, 0}...)
	expectedFirstIP := net.IP(expectedFirst)

	expectedLast = append(expectedLast, v4Asv6...)
	expectedLast = append(expectedLast, []byte{192, 0, 128, 255}...)
	expectedLastIP := net.IP(expectedLast)
	expectedRange := netWithRange{First: &expectedFirstIP, Last: &expectedLastIP}

	s.checkRangesEqual(&expectedRange, &testRange, c)

	// Check that all bits are masked correctly.
	testRange = ipNetToRange(*createIPNet("192.0.128.255", 24, int(ipv4BitLen)))
	s.checkRangesEqual(&expectedRange, &testRange, c)

	testRange = ipNetToRange(*createIPNet("fd44:7089:ff32:712b:ff00::", 64, int(ipv6BitLen)))
	testRange = ipNetToRange(*createIPNet("::ffff:0", 128, int(ipv6BitLen)))

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
	cidrs := []*net.IPNet{createIPNet("10.0.0.0", 8, int(ipv4BitLen)),
		createIPNet("10.0.0.0", 10, int(ipv4BitLen)),
		createIPNet("10.64.0.0", 11, int(ipv4BitLen)),
		createIPNet("10.112.0.0", 12, int(ipv4BitLen))}

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

	cidrs := []*net.IPNet{createIPNet("192.0.128.0", 24, int(ipv4BitLen)),
		createIPNet("192.0.129.0", 24, int(ipv4BitLen))}
	expected := []*net.IPNet{createIPNet("192.0.128.0", 23, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs := CoalesceCIDRs(cidrs)
	c.Assert(len(mergedV6CIDRs), Equals, 0)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.129.0", 24, int(ipv4BitLen)),
		createIPNet("192.0.130.0", 24, int(ipv4BitLen))}
	expected = []*net.IPNet{createIPNet("192.0.129.0", 24, int(ipv4BitLen)),
		createIPNet("192.0.130.0", 24, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 30, int(ipv4BitLen)),
		createIPNet("192.0.2.116", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.118", 31, int(ipv4BitLen))}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 29, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 30, int(ipv4BitLen)),
		createIPNet("192.0.2.116", 32, int(ipv4BitLen)),
		createIPNet("192.0.2.118", 31, int(ipv4BitLen))}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 30, int(ipv4BitLen)),
		createIPNet("192.0.2.116", 32, int(ipv4BitLen)),
		createIPNet("192.0.2.118", 31, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.2.112", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.116", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.118", 31, int(ipv4BitLen))}
	expected = []*net.IPNet{createIPNet("192.0.2.112", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.116", 30, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("192.0.1.254", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.0", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.16", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.32", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.48", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.64", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.80", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.96", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.112", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.128", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.144", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.160", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.176", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.192", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.208", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.224", 28, int(ipv4BitLen)),
		createIPNet("192.0.2.240", 28, int(ipv4BitLen)),
		createIPNet("192.0.3.0", 28, int(ipv4BitLen)),
	}

	expected = []*net.IPNet{createIPNet("192.0.1.254", 31, int(ipv4BitLen)),
		createIPNet("192.0.2.0", 24, int(ipv4BitLen)),
		createIPNet("192.0.3.0", 28, int(ipv4BitLen))}
	mergedV4CIDRs, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV4CIDRs, expected, c)

	cidrs = []*net.IPNet{createIPNet("::", 0, int(ipv6BitLen)),
		createIPNet("fe80::1", 128, int(ipv6BitLen))}
	expected = []*net.IPNet{createIPNet("::", 0, int(ipv6BitLen))}
	_, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV6CIDRs, expected, c)

	// assert cidr_merge(['::/0', '::192.0.2.0/124', 'ff00::101']) == [IPNetwork('::/0')]
	cidrs = []*net.IPNet{createIPNet("::", 0, int(ipv6BitLen)),
		createIPNet("::192.0.2.0", 124, int(ipv6BitLen)),
		createIPNet("ff00::101", 128, int(ipv6BitLen))}
	_, mergedV6CIDRs = CoalesceCIDRs(cidrs)
	s.testIPNetsEqual(mergedV6CIDRs, expected, c)
}

func (s *IPTestSuite) TestRangeToCIDRs(c *C) {
	// IPv4 worst case.
	ipNets := rangeToCIDRs(net.ParseIP("0.0.0.1"), net.ParseIP("255.255.255.254"))
	expected := []*net.IPNet{createIPNet("0.0.0.1", 32, int(ipv4BitLen)),
		createIPNet("0.0.0.2", 31, int(ipv4BitLen)),
		createIPNet("0.0.0.4", 30, int(ipv4BitLen)),
		createIPNet("0.0.0.8", 29, int(ipv4BitLen)),
		createIPNet("0.0.0.16", 28, int(ipv4BitLen)),
		createIPNet("0.0.0.32", 27, int(ipv4BitLen)),
		createIPNet("0.0.0.64", 26, int(ipv4BitLen)),
		createIPNet("0.0.0.128", 25, int(ipv4BitLen)),
		createIPNet("0.0.1.0", 24, int(ipv4BitLen)),
		createIPNet("0.0.2.0", 23, int(ipv4BitLen)),
		createIPNet("0.0.4.0", 22, int(ipv4BitLen)),
		createIPNet("0.0.8.0", 21, int(ipv4BitLen)),
		createIPNet("0.0.16.0", 20, int(ipv4BitLen)),
		createIPNet("0.0.32.0", 19, int(ipv4BitLen)),
		createIPNet("0.0.64.0", 18, int(ipv4BitLen)),
		createIPNet("0.0.128.0", 17, int(ipv4BitLen)),
		createIPNet("0.1.0.0", 16, int(ipv4BitLen)),
		createIPNet("0.2.0.0", 15, int(ipv4BitLen)),
		createIPNet("0.4.0.0", 14, int(ipv4BitLen)),
		createIPNet("0.8.0.0", 13, int(ipv4BitLen)),
		createIPNet("0.16.0.0", 12, int(ipv4BitLen)),
		createIPNet("0.32.0.0", 11, int(ipv4BitLen)),
		createIPNet("0.64.0.0", 10, int(ipv4BitLen)),
		createIPNet("0.128.0.0", 9, int(ipv4BitLen)),
		createIPNet("1.0.0.0", 8, int(ipv4BitLen)),
		createIPNet("2.0.0.0", 7, int(ipv4BitLen)),
		createIPNet("4.0.0.0", 6, int(ipv4BitLen)),
		createIPNet("8.0.0.0", 5, int(ipv4BitLen)),
		createIPNet("16.0.0.0", 4, int(ipv4BitLen)),
		createIPNet("32.0.0.0", 3, int(ipv4BitLen)),
		createIPNet("64.0.0.0", 2, int(ipv4BitLen)),
		createIPNet("128.0.0.0", 2, int(ipv4BitLen)),
		createIPNet("192.0.0.0", 3, int(ipv4BitLen)),
		createIPNet("224.0.0.0", 4, int(ipv4BitLen)),
		createIPNet("240.0.0.0", 5, int(ipv4BitLen)),
		createIPNet("248.0.0.0", 6, int(ipv4BitLen)),
		createIPNet("252.0.0.0", 7, int(ipv4BitLen)),
		createIPNet("254.0.0.0", 8, int(ipv4BitLen)),
		createIPNet("255.0.0.0", 9, int(ipv4BitLen)),
		createIPNet("255.128.0.0", 10, int(ipv4BitLen)),
		createIPNet("255.192.0.0", 11, int(ipv4BitLen)),
		createIPNet("255.224.0.0", 12, int(ipv4BitLen)),
		createIPNet("255.240.0.0", 13, int(ipv4BitLen)),
		createIPNet("255.248.0.0", 14, int(ipv4BitLen)),
		createIPNet("255.252.0.0", 15, int(ipv4BitLen)),
		createIPNet("255.254.0.0", 16, int(ipv4BitLen)),
		createIPNet("255.255.0.0", 17, int(ipv4BitLen)),
		createIPNet("255.255.128.0", 18, int(ipv4BitLen)),
		createIPNet("255.255.192.0", 19, int(ipv4BitLen)),
		createIPNet("255.255.224.0", 20, int(ipv4BitLen)),
		createIPNet("255.255.240.0", 21, int(ipv4BitLen)),
		createIPNet("255.255.249.0", 22, int(ipv4BitLen)),
		createIPNet("255.255.252.0", 23, int(ipv4BitLen)),
		createIPNet("255.255.254.0", 24, int(ipv4BitLen)),
		createIPNet("255.255.255.0", 25, int(ipv4BitLen)),
		createIPNet("255.255.255.128", 26, int(ipv4BitLen)),
		createIPNet("255.255.255.192", 27, int(ipv4BitLen)),
		createIPNet("255.255.255.224", 28, int(ipv4BitLen)),
		createIPNet("255.255.255.240", 29, int(ipv4BitLen)),
		createIPNet("255.255.255.248", 30, int(ipv4BitLen)),
		createIPNet("255.255.255.252", 31, int(ipv4BitLen)),
		createIPNet("255.255.255.254", 32, int(ipv4BitLen)),
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
	nextIP := getNextIP(ip)
	s.testIPsEqual(nextIP, expectedNext, c)

	// Check that overflow does not occur.
	ip = net.ParseIP("255.255.255.255")
	nextIP = getNextIP(ip)
	expectedNext = ip
	s.testIPsEqual(nextIP, expectedNext, c)

	ip = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	nextIP = getNextIP(ip)
	expectedNext = ip
	s.testIPsEqual(nextIP, expectedNext, c)

	ip = net.ParseIP("10.0.0.0")
	nextIP = getNextIP(ip)
	expectedNext = net.ParseIP("10.0.0.1")
	s.testIPsEqual(nextIP, expectedNext, c)

	ip = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")
	expectedNext = net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	nextIP = getNextIP(ip)
	s.testIPsEqual(nextIP, expectedNext, c)
}

func (s *IPTestSuite) TestCreateSpanningCIDR(c *C) {
	netRange := createIPRange("10.0.0.0", "10.255.255.255")
	expectedSpanningCIDR := createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	spanningCIDR := createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.0", "10.255.255.254")
	expectedSpanningCIDR = createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.1", "10.0.0.1")
	expectedSpanningCIDR = createIPNet("10.0.0.1", 32, int(ipv4BitLen))
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("10.0.0.1", "10.0.0.2")
	expectedSpanningCIDR = createIPNet("10.0.0.0", 30, int(ipv4BitLen))
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("9.0.0.0", "10.0.0.0")
	expectedSpanningCIDR = createIPNet("8.0.0.0", 6, int(ipv4BitLen))
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

	netRange = createIPRange("FD44:7089:FF32:712B:FF00:0000:0000:0000", "FD44:7089:FF32:712B:FFFF:FFFF:FFFF:FFFF")
	expectedSpanningCIDR = createIPNet("fd44:7089:ff32:712b:ff00::", 72, int(ipv6BitLen))
	spanningCIDR = createSpanningCIDR(*netRange)
	s.testIPNetsEqual([]*net.IPNet{expectedSpanningCIDR}, []*net.IPNet{&spanningCIDR}, c)

}

func (s *IPTestSuite) TestPartitionCIDR(c *C) {
	targetCIDR := createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	excludeCIDR := createIPNet("10.255.255.255", 32, int(ipv4BitLen))
	left, exclude, right := partitionCIDR(*targetCIDR, *excludeCIDR)
	// Exclude should just contain exclude CIDR
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
	// Nothing should be in right list.
	c.Assert(len(right), Equals, 0)
	expectedLeft := []*net.IPNet{createIPNet("10.0.0.0", 9, int(ipv4BitLen)),
		createIPNet("10.128.0.0", 10, int(ipv4BitLen)),
		createIPNet("10.192.0.0", 11, int(ipv4BitLen)),
		createIPNet("10.224.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.240.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.248.0.0", 14, int(ipv4BitLen)),
		createIPNet("10.252.0.0", 15, int(ipv4BitLen)),
		createIPNet("10.254.0.0", 16, int(ipv4BitLen)),
		createIPNet("10.255.0.0", 17, int(ipv4BitLen)),
		createIPNet("10.255.128.0", 18, int(ipv4BitLen)),
		createIPNet("10.255.192.0", 19, int(ipv4BitLen)),
		createIPNet("10.255.224.0", 20, int(ipv4BitLen)),
		createIPNet("10.255.240.0", 21, int(ipv4BitLen)),
		createIPNet("10.255.248.0", 22, int(ipv4BitLen)),
		createIPNet("10.255.252.0", 23, int(ipv4BitLen)),
		createIPNet("10.255.254.0", 24, int(ipv4BitLen)),
		createIPNet("10.255.255.0", 25, int(ipv4BitLen)),
		createIPNet("10.255.255.128", 26, int(ipv4BitLen)),
		createIPNet("10.255.255.192", 27, int(ipv4BitLen)),
		createIPNet("10.255.255.224", 28, int(ipv4BitLen)),
		createIPNet("10.255.255.240", 29, int(ipv4BitLen)),
		createIPNet("10.255.255.248", 30, int(ipv4BitLen)),
		createIPNet("10.255.255.252", 31, int(ipv4BitLen)),
		createIPNet("10.255.255.254", 32, int(ipv4BitLen)),
	}
	s.testIPNetsEqual(expectedLeft, left, c)

	targetCIDR = createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	excludeCIDR = createIPNet("10.0.0.0", 32, int(ipv4BitLen))
	left, exclude, right = partitionCIDR(*targetCIDR, *excludeCIDR)
	// Exclude should just contain exclude CIDR
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
	// Nothing should be in left list.
	c.Assert(len(left), Equals, 0)
	expectedRight := []*net.IPNet{createIPNet("10.128.0.0", 9, int(ipv4BitLen)),
		createIPNet("10.64.0.0", 10, int(ipv4BitLen)),
		createIPNet("10.32.0.0", 11, int(ipv4BitLen)),
		createIPNet("10.16.0.0", 12, int(ipv4BitLen)),
		createIPNet("10.8.0.0", 13, int(ipv4BitLen)),
		createIPNet("10.4.0.0", 14, int(ipv4BitLen)),
		createIPNet("10.2.0.0", 15, int(ipv4BitLen)),
		createIPNet("10.1.0.0", 16, int(ipv4BitLen)),
		createIPNet("10.0.128.0", 17, int(ipv4BitLen)),
		createIPNet("10.0.64.0", 18, int(ipv4BitLen)),
		createIPNet("10.0.32.0", 19, int(ipv4BitLen)),
		createIPNet("10.0.16.0", 20, int(ipv4BitLen)),
		createIPNet("10.0.8.0", 21, int(ipv4BitLen)),
		createIPNet("10.0.4.0", 22, int(ipv4BitLen)),
		createIPNet("10.0.2.0", 23, int(ipv4BitLen)),
		createIPNet("10.0.1.0", 24, int(ipv4BitLen)),
		createIPNet("10.0.0.128", 25, int(ipv4BitLen)),
		createIPNet("10.0.0.64", 26, int(ipv4BitLen)),
		createIPNet("10.0.0.32", 27, int(ipv4BitLen)),
		createIPNet("10.0.0.16", 28, int(ipv4BitLen)),
		createIPNet("10.0.0.8", 29, int(ipv4BitLen)),
		createIPNet("10.0.0.4", 30, int(ipv4BitLen)),
		createIPNet("10.0.0.2", 31, int(ipv4BitLen)),
		createIPNet("10.0.0.1", 32, int(ipv4BitLen)),
	}
	s.testIPNetsEqual(expectedRight, right, c)

	// exclude is not in target CIDR and is to left.
	targetCIDR = createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	excludeCIDR = createIPNet("9.0.0.255", 32, int(ipv4BitLen))
	left, exclude, right = partitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(left), Equals, 0)
	c.Assert(len(exclude), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, right, c)

	// exclude is not in target CIDR and is to right.
	targetCIDR = createIPNet("10.255.255.254", 32, int(ipv4BitLen))
	excludeCIDR = createIPNet("10.255.255.255", 32, int(ipv4BitLen))
	left, exclude, right = partitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(right), Equals, 0)
	c.Assert(len(exclude), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, left, c)

	// exclude CIDR larger than target CIDR
	targetCIDR = createIPNet("10.96.0.0", 12, int(ipv4BitLen))
	excludeCIDR = createIPNet("10.0.0.0", 8, int(ipv4BitLen))
	left, exclude, right = partitionCIDR(*targetCIDR, *excludeCIDR)
	c.Assert(len(left), Equals, 0)
	c.Assert(len(right), Equals, 0)
	s.testIPNetsEqual([]*net.IPNet{targetCIDR}, exclude, c)

	targetCIDR = createIPNet("fd44:7089:ff32:712b:ff00::", 64, int(ipv6BitLen))
	excludeCIDR = createIPNet("fd44:7089:ff32:712b::", 66, int(ipv6BitLen))

	left, exclude, right = partitionCIDR(*targetCIDR, *excludeCIDR)

	expectedCIDRs := []*net.IPNet{createIPNet("fd44:7089:ff32:712b:8000::", 65, int(ipv6BitLen)),
		createIPNet("fd44:7089:ff32:712b:4000::", 66, int(ipv6BitLen))}
	s.testIPNetsEqual(expectedCIDRs, right, c)
	s.testIPNetsEqual([]*net.IPNet{excludeCIDR}, exclude, c)
}
