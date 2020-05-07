// Copyright 2016-2020 Authors of Cilium
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

// +build !privileged_tests

package ipam

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type IPAMSuite struct{}

var _ = Suite(&IPAMSuite{})

func fakeIPv4AllocCIDRIP(fakeAddressing datapath.NodeAddressing) net.IP {
	// force copy so net.IP can be modified
	return net.ParseIP(fakeAddressing.IPv4().AllocationCIDR().IP.String())
}

func fakeIPv6AllocCIDRIP(fakeAddressing datapath.NodeAddressing) net.IP {
	// force copy so net.IP can be modified
	return net.ParseIP(fakeAddressing.IPv6().AllocationCIDR().IP.String())
}

type testConfiguration struct{}

func (t *testConfiguration) IPv4Enabled() bool                        { return true }
func (t *testConfiguration) IPv6Enabled() bool                        { return true }
func (t *testConfiguration) HealthCheckingEnabled() bool              { return true }
func (t *testConfiguration) IPAMMode() string                         { return ipamOption.IPAMHostScopeLegacy }
func (t *testConfiguration) BlacklistConflictingRoutesEnabled() bool  { return false }
func (t *testConfiguration) SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR) {}
func (t *testConfiguration) IPv4NativeRoutingCIDR() *cidr.CIDR        { return nil }

func (s *IPAMSuite) TestLock(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{})

	// Since the IPs we have allocated to the endpoints might or might not
	// be in the allocrange specified in cilium, we need to specify them
	// manually on the endpoint based on the alloc range.
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	nextIP(ipv4)
	epipv4, err := addressing.NewCiliumIPv4(ipv4.String())
	c.Assert(err, IsNil)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	nextIP(ipv6)
	epipv6, err := addressing.NewCiliumIPv6(ipv6.String())
	c.Assert(err, IsNil)

	// Forcefully release possible allocated IPs
	err = ipam.IPv4Allocator.Release(epipv4.IP())
	c.Assert(err, IsNil)
	err = ipam.IPv6Allocator.Release(epipv6.IP())
	c.Assert(err, IsNil)

	// Let's allocate the IP first so we can see the tests failing
	result, err := ipam.IPv4Allocator.Allocate(epipv4.IP(), "test")
	c.Assert(err, IsNil)
	c.Assert(result.IP, checker.DeepEquals, epipv4.IP())

	err = ipam.IPv4Allocator.Release(epipv4.IP())
	c.Assert(err, IsNil)
}

func (s *IPAMSuite) TestBlackList(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{})

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	nextIP(ipv4)

	ipam.BlacklistIP(ipv4, "test")
	err := ipam.AllocateIP(ipv4, "test")
	c.Assert(err, Not(IsNil))
	ipam.ReleaseIP(ipv4)

	nextIP(ipv4)
	_, ipNet, err := net.ParseCIDR(fakeAddressing.IPv4().AllocationCIDR().String())
	c.Assert(err, IsNil)
	ipam.BlacklistIPNet(*ipNet, "test")
	c.Assert(ipam.blacklist.Contains(ipv4), Equals, true)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	nextIP(ipv6)

	ipam.BlacklistIP(ipv6, "test")
	err = ipam.AllocateIP(ipv6, "test")
	c.Assert(err, Not(IsNil))
	ipam.ReleaseIP(ipv6)

	nextIP(ipv6)
	_, ipNet, err = net.ParseCIDR(fakeAddressing.IPv6().AllocationCIDR().String())
	c.Assert(err, IsNil)
	ipam.BlacklistIPNet(*ipNet, "test")
	c.Assert(ipam.blacklist.Contains(ipv6), Equals, true)
}

func (s *IPAMSuite) TestDeriveFamily(c *C) {
	c.Assert(DeriveFamily(net.ParseIP("1.1.1.1")), Equals, IPv4)
	c.Assert(DeriveFamily(net.ParseIP("f00d::1")), Equals, IPv6)
}

func (s *IPAMSuite) TestOwnerRelease(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{})

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	nextIP(ipv4)
	err := ipam.AllocateIP(ipv4, "default/test")
	c.Assert(err, IsNil)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	nextIP(ipv6)
	err = ipam.AllocateIP(ipv6, "default/test")
	c.Assert(err, IsNil)

	// unknown owner, must fail
	err = ipam.ReleaseIPString("default/test2")
	c.Assert(err, Not(IsNil))
	// 1st release by correct owner, must succeed
	err = ipam.ReleaseIPString("default/test")
	c.Assert(err, IsNil)
	// 2nd release by owner, must now fail
	err = ipam.ReleaseIPString("default/test")
	c.Assert(err, Not(IsNil))
}
