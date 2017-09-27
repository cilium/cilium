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
	"reflect"
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
		c.Assert(reflect.DeepEqual((*ipNetv4_1)[k], desiredIPv4_1[k]), Equals, true)
	}
	testNetv4_2 := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	ipNetv4_2 := getNetworkPrefix(&testNetv4_2)
	for k := range *ipNetv4_2 {
		c.Assert(reflect.DeepEqual((*ipNetv4_2)[k], desiredIPv4_1[k]), Equals, true)
	}

	// Test IPv6
	desiredIPv6_1, testNetv6_1, _ := net.ParseCIDR("fd44:7089:ff32:712b::/64")

	ipNetv6_1 := getNetworkPrefix(testNetv6_1)
	for k := range *ipNetv6_1 {
		c.Assert(reflect.DeepEqual((*ipNetv6_1)[k], desiredIPv6_1[k]), Equals, true)
	}
}

func (s *IPTestSuite) testIPNetsEqual(created, expected []*net.IPNet, c *C) {
	for index := range created {
		c.Assert(created[index].String(), Equals, expected[index].String())
		c.Assert(created[index].Mask.String(), Equals, expected[index].Mask.String())
	}
}

func createIPNet(address string, maskSize int, bitLen int) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(address), Mask: net.CIDRMask(maskSize, bitLen)}
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
		c.Assert(reflect.DeepEqual(expectedBytes[k], (*newBytes)[k]), Equals, true)
	}

	newBytes = flipNthBit(&testBytes, 32)
	expectedBytes = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0}
	for k := range expectedBytes {
		c.Assert(reflect.DeepEqual(expectedBytes[k], (*newBytes)[k]), Equals, true)
	}

}
