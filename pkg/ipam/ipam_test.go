// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func Test(t *testing.T) {
	TestingT(t)
}

type IPAMSuite struct{}

var _ = Suite(&IPAMSuite{})

func fakeIPv4AllocCIDRIP(fakeAddressing types.NodeAddressing) netip.Addr {
	return netip.MustParseAddr(fakeAddressing.IPv4().AllocationCIDR().IP.String())
}

func fakeIPv6AllocCIDRIP(fakeAddressing types.NodeAddressing) netip.Addr {
	return netip.MustParseAddr(fakeAddressing.IPv6().AllocationCIDR().IP.String())
}

type testConfiguration struct{}

func (t *testConfiguration) IPv4Enabled() bool                        { return true }
func (t *testConfiguration) IPv6Enabled() bool                        { return true }
func (t *testConfiguration) HealthCheckingEnabled() bool              { return true }
func (t *testConfiguration) UnreachableRoutesEnabled() bool           { return false }
func (t *testConfiguration) IPAMMode() string                         { return ipamOption.IPAMClusterPool }
func (t *testConfiguration) SetIPv4NativeRoutingCIDR(cidr *cidr.CIDR) {}
func (t *testConfiguration) GetIPv4NativeRoutingCIDR() *cidr.CIDR     { return nil }

func (s *IPAMSuite) TestLock(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

	// Since the IPs we have allocated to the endpoints might or might not
	// be in the allocrange specified in cilium, we need to specify them
	// manually on the endpoint based on the alloc range.
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	// Forcefully release possible allocated IPs
	err := ipam.IPv4Allocator.Release(ipv4.AsSlice(), PoolDefault)
	c.Assert(err, IsNil)
	err = ipam.IPv6Allocator.Release(ipv6.AsSlice(), PoolDefault)
	c.Assert(err, IsNil)

	// Let's allocate the IP first so we can see the tests failing
	result, err := ipam.IPv4Allocator.Allocate(ipv4.AsSlice(), "test", PoolDefault)
	c.Assert(err, IsNil)
	c.Assert(result.IP, checker.DeepEquals, net.IP(ipv4.AsSlice()))

	err = ipam.IPv4Allocator.Release(ipv4.AsSlice(), PoolDefault)
	c.Assert(err, IsNil)
}

func (s *IPAMSuite) TestExcludeIP(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()

	ipam.ExcludeIP(ipv4.AsSlice(), "test-foo", PoolDefault)
	err := ipam.AllocateIP(ipv4.AsSlice(), "test-bar", PoolDefault)
	c.Assert(err, Not(IsNil))
	c.Assert(err, ErrorMatches, ".* owned by test-foo")
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault)
	c.Assert(err, IsNil)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	ipam.ExcludeIP(ipv6.AsSlice(), "test-foo", PoolDefault)
	err = ipam.AllocateIP(ipv6.AsSlice(), "test-bar", PoolDefault)
	c.Assert(err, Not(IsNil))
	c.Assert(err, ErrorMatches, ".* owned by test-foo")
	ipam.ReleaseIP(ipv6.AsSlice(), PoolDefault)
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault)
	c.Assert(err, IsNil)
}

func (s *IPAMSuite) TestDeriveFamily(c *C) {
	c.Assert(DeriveFamily(net.ParseIP("1.1.1.1")), Equals, IPv4)
	c.Assert(DeriveFamily(net.ParseIP("f00d::1")), Equals, IPv6)
}

func (s *IPAMSuite) TestOwnerRelease(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	err := ipam.AllocateIP(ipv4.AsSlice(), "default/test", PoolDefault)
	c.Assert(err, IsNil)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()
	err = ipam.AllocateIP(ipv6.AsSlice(), "default/test", PoolDefault)
	c.Assert(err, IsNil)

	// unknown owner, must fail
	err = ipam.ReleaseIPString("default/test2", PoolDefault)
	c.Assert(err, Not(IsNil))
	// 1st release by correct owner, must succeed
	err = ipam.ReleaseIPString("default/test", PoolDefault)
	c.Assert(err, IsNil)
	// 2nd release by owner, must now fail
	err = ipam.ReleaseIPString("default/test", PoolDefault)
	c.Assert(err, Not(IsNil))
}
