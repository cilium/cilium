// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
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

type fakeMetadataFunc func(owner string) (pool string, err error)

func (f fakeMetadataFunc) GetIPPoolForPod(owner string) (pool string, err error) {
	return f(owner)
}

type fakePoolAllocator struct {
	pools map[string]Allocator
}

func newFakePoolAllocator(poolMap map[string]string) *fakePoolAllocator {
	pools := make(map[string]Allocator, len(poolMap))
	for name, cidr := range poolMap {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse test cidr %s for pool %s", cidr, name))
		}
		pools[name] = newHostScopeAllocator(ipnet)
	}
	return &fakePoolAllocator{pools: pools}
}

func (f *fakePoolAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	alloc, ok := f.pools[pool.String()]
	if !ok {
		return nil, fmt.Errorf("unknown pool %s", pool)
	}
	result, err := alloc.Allocate(ip, owner, pool)
	if err != nil {
		return nil, err
	}
	result.IPPoolName = pool
	return result, nil
}

func (f fakePoolAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return f.Allocate(ip, owner, pool)
}

func (f fakePoolAllocator) Release(ip net.IP, pool Pool) error {
	alloc, ok := f.pools[pool.String()]
	if !ok {
		return fmt.Errorf("unknown pool %s", pool)
	}
	return alloc.Release(ip, pool)
}

func (f fakePoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	alloc, ok := f.pools[pool.String()]
	if !ok {
		return nil, fmt.Errorf("unknown pool %s", pool)
	}
	result, err := alloc.AllocateNext(owner, pool)
	if err != nil {
		return nil, err
	}
	result.IPPoolName = pool
	return result, nil
}

func (f fakePoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return f.AllocateNext(owner, pool)
}

func (f fakePoolAllocator) Dump() (map[string]string, string) {
	result := map[string]string{}
	for name, alloc := range f.pools {
		dump, _ := alloc.Dump()
		for k, v := range dump {
			result[name+":"+k] = v
		}
	}
	return result, fmt.Sprintf("%d pools", len(f.pools))
}

func (f fakePoolAllocator) RestoreFinished() {}

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
	ipam.IPv4Allocator.Release(ipv4.AsSlice(), PoolDefault)
	ipam.IPv6Allocator.Release(ipv6.AsSlice(), PoolDefault)

	// Let's allocate the IP first so we can see the tests failing
	result, err := ipam.IPv4Allocator.Allocate(ipv4.AsSlice(), "test", PoolDefault)
	c.Assert(err, IsNil)
	c.Assert(result.IP, checker.DeepEquals, net.IP(ipv4.AsSlice()))
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

func (s *IPAMSuite) TestIPAMMetadata(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)
	ipam.IPv4Allocator = newFakePoolAllocator(map[string]string{
		"default": "10.10.0.0/16",
		"test":    "192.168.178.0/24",
		"special": "172.18.19.0/24",
	})
	ipam.IPv6Allocator = newFakePoolAllocator(map[string]string{
		"default": "fd00:100::/80",
		"test":    "fc00:100::/96",
		"special": "fe00:100::/80",
	})

	// Without metadata, should always return PoolDefault
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-pod", "")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)
	c.Assert(resIPv6.IPPoolName, Equals, PoolDefault)

	ipam.WithMetadata(fakeMetadataFunc(func(owner string) (pool string, err error) {
		// use namespace to determine pool name
		namespace, _, _ := strings.Cut(owner, "/")
		switch namespace {
		case "test":
			return "test", nil
		case "special":
			return "special", nil
		case "error":
			return "", fmt.Errorf("unable to determine pool for %s", owner)
		default:
			return PoolDefault.String(), nil
		}
	}))

	// Checks AllocateIP
	specialIP := net.ParseIP("172.18.19.20")
	_, err = ipam.AllocateIPWithoutSyncUpstream(specialIP, "special/wants-special-ip", "")
	c.Assert(err, Not(IsNil)) // pool required
	resIPv4, err = ipam.AllocateIPWithoutSyncUpstream(specialIP, "special/wants-special-ip", "special")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, Pool("special"))
	c.Assert(resIPv4.IP.Equal(specialIP), Equals, true)

	// Checks ReleaseIP
	err = ipam.ReleaseIP(specialIP, "")
	c.Assert(err, Not(IsNil)) // pool required
	err = ipam.ReleaseIP(specialIP, "special")
	c.Assert(err, IsNil)

	// Checks if pool metadata is used if pool is empty
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, Pool("test"))
	c.Assert(resIPv6.IPPoolName, Equals, Pool("test"))

	// Checks if pool can be overwritten
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/special-pod", "special")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, Pool("special"))
	c.Assert(resIPv6.IPPoolName, Equals, Pool("special"))

	// Checks if fallback to default works
	resIPv4, resIPv6, err = ipam.AllocateNext("", "other/special-pod", "")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)
	c.Assert(resIPv6.IPPoolName, Equals, PoolDefault)

	// Checks if metadata errors are propagated
	_, _, err = ipam.AllocateNext("", "error/special-value", "")
	c.Assert(err, Not(IsNil))
}

func (s *IPAMSuite) TestLegacyAllocatorIPAMMetadata(c *C) {
	// This test uses a regular hostScope allocator which does not support
	// IPAM pools. We assert that in this scenario, the pool returned in the
	// AllocationResult is always set to PoolDefault, regardless of the requested
	// pool
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)
	ipam.WithMetadata(fakeMetadataFunc(func(owner string) (pool string, err error) {
		return "some-pool", nil
	}))

	// AllocateIP requires explicit pool
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	_, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "")
	c.Assert(err, Not(IsNil))

	// AllocateIP with specific pool
	ipv4 = ipv4.Next()
	resIPv4, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "override")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)

	// AllocateIP with default pool
	ipv4 = ipv4.Next()
	resIPv4, err = ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "default")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)

	// AllocateNext with empty pool
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-pod", "")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)
	c.Assert(resIPv6.IPPoolName, Equals, PoolDefault)

	// AllocateNext with specific pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "override")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)
	c.Assert(resIPv6.IPPoolName, Equals, PoolDefault)

	// AllocateNext with default pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "default")
	c.Assert(err, IsNil)
	c.Assert(resIPv4.IPPoolName, Equals, PoolDefault)
	c.Assert(resIPv6.IPPoolName, Equals, PoolDefault)
}
