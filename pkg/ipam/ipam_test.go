// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func fakeIPv4AllocCIDRIP(fakeAddressing types.NodeAddressing) netip.Addr {
	return netip.MustParseAddr(fakeAddressing.IPv4().AllocationCIDR().IP.String())
}

func fakeIPv6AllocCIDRIP(fakeAddressing types.NodeAddressing) netip.Addr {
	return netip.MustParseAddr(fakeAddressing.IPv6().AllocationCIDR().IP.String())
}

var testConfiguration = &option.DaemonConfig{
	EnableIPv4:              true,
	EnableIPv6:              true,
	EnableHealthChecking:    true,
	EnableUnreachableRoutes: false,
	IPAM:                    ipamOption.IPAMClusterPool,
}

type fakeMetadataFunc func(owner string, family Family) (pool string, err error)

func (f fakeMetadataFunc) GetIPPoolForPod(owner string, family Family) (pool string, err error) {
	return f(owner, family)
}

type fakePoolAllocator struct {
	pools map[Pool]Allocator
}

func newFakePoolAllocator(poolMap map[string]string) *fakePoolAllocator {
	pools := make(map[Pool]Allocator, len(poolMap))
	for name, cidr := range poolMap {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse test cidr %s for pool %s", cidr, name))
		}
		pools[Pool(name)] = newHostScopeAllocator(ipnet)
	}
	return &fakePoolAllocator{pools: pools}
}

func (f *fakePoolAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	alloc, ok := f.pools[pool]
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
	alloc, ok := f.pools[pool]
	if !ok {
		return fmt.Errorf("unknown pool %s", pool)
	}
	return alloc.Release(ip, pool)
}

func (f fakePoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	alloc, ok := f.pools[pool]
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

func (f fakePoolAllocator) Dump() (map[Pool]map[string]string, string) {
	result := map[Pool]map[string]string{}
	for name, alloc := range f.pools {
		dump, _ := alloc.Dump()
		if _, ok := result[name]; !ok {
			result[name] = map[string]string{}
		}
		for k, v := range dump[name] {
			result[name][k] = v
		}
	}
	return result, fmt.Sprintf("%d pools", len(f.pools))
}

func (f fakePoolAllocator) Capacity() uint64 {
	return uint64(0)
}

func (f fakePoolAllocator) RestoreFinished() {}

func TestLock(t *testing.T) {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil)
	ipam.ConfigureAllocator()

	// Since the IPs we have allocated to the endpoints might or might not
	// be in the allocrange specified in cilium, we need to specify them
	// manually on the endpoint based on the alloc range.
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	// Forcefully release possible allocated IPs
	ipam.IPv4Allocator.Release(ipv4.AsSlice(), PoolDefault())
	ipam.IPv6Allocator.Release(ipv6.AsSlice(), PoolDefault())

	// Let's allocate the IP first so we can see the tests failing
	result, err := ipam.IPv4Allocator.Allocate(ipv4.AsSlice(), "test", PoolDefault())
	require.Nil(t, err)
	require.EqualValues(t, net.IP(ipv4.AsSlice()), result.IP)
}

func TestExcludeIP(t *testing.T) {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil)
	ipam.ConfigureAllocator()

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()

	ipam.ExcludeIP(ipv4.AsSlice(), "test-foo", PoolDefault())
	err := ipam.AllocateIP(ipv4.AsSlice(), "test-bar", PoolDefault())
	require.NotNil(t, err)
	require.ErrorContains(t, err, "owned by test-foo")
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault())
	require.Nil(t, err)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	ipam.ExcludeIP(ipv6.AsSlice(), "test-foo", PoolDefault())
	err = ipam.AllocateIP(ipv6.AsSlice(), "test-bar", PoolDefault())
	require.NotNil(t, err)
	require.ErrorContains(t, err, "owned by test-foo")
	ipam.ReleaseIP(ipv6.AsSlice(), PoolDefault())
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault())
	require.Nil(t, err)
}

func TestDeriveFamily(t *testing.T) {
	require.Equal(t, IPv4, DeriveFamily(net.ParseIP("1.1.1.1")))
	require.Equal(t, IPv6, DeriveFamily(net.ParseIP("f00d::1")))
}

func TestIPAMMetadata(t *testing.T) {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) {
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
			return PoolDefault().String(), nil
		}
	})

	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, fakeMetadata)
	ipam.ConfigureAllocator()
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

	// Checks AllocateIP
	specialIP := net.ParseIP("172.18.19.20")
	_, err := ipam.AllocateIPWithoutSyncUpstream(specialIP, "special/wants-special-ip", "")
	require.NotNil(t, err) // pool required
	resIPv4, err := ipam.AllocateIPWithoutSyncUpstream(specialIP, "special/wants-special-ip", "special")
	require.Nil(t, err)
	require.Equal(t, Pool("special"), resIPv4.IPPoolName)
	require.Equal(t, true, resIPv4.IP.Equal(specialIP))

	// Checks ReleaseIP
	err = ipam.ReleaseIP(specialIP, "")
	require.NotNil(t, err) // pool required
	err = ipam.ReleaseIP(specialIP, "special")
	require.Nil(t, err)

	// Checks if pool metadata is used if pool is empty
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-other-pod", "")
	require.Nil(t, err)
	require.Equal(t, Pool("test"), resIPv4.IPPoolName)
	require.Equal(t, Pool("test"), resIPv6.IPPoolName)

	// Checks if pool can be overwritten
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/special-pod", "special")
	require.Nil(t, err)
	require.Equal(t, Pool("special"), resIPv4.IPPoolName)
	require.Equal(t, Pool("special"), resIPv6.IPPoolName)

	// Checks if fallback to default works
	resIPv4, resIPv6, err = ipam.AllocateNext("", "other/special-pod", "")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// Checks if metadata errors are propagated
	_, _, err = ipam.AllocateNext("", "error/special-value", "")
	require.NotNil(t, err)
}

func TestLegacyAllocatorIPAMMetadata(t *testing.T) {
	// This test uses a regular hostScope allocator which does not support
	// IPAM pools. We assert that in this scenario, the pool returned in the
	// AllocationResult is always set to PoolDefault(), regardless of the requested
	// pool
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) { return "some-pool", nil })
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, fakeMetadata)
	ipam.ConfigureAllocator()

	// AllocateIP requires explicit pool
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	_, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "")
	require.NotNil(t, err)

	// AllocateIP with specific pool
	ipv4 = ipv4.Next()
	resIPv4, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "override")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)

	// AllocateIP with default pool
	ipv4 = ipv4.Next()
	resIPv4, err = ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "default")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)

	// AllocateNext with empty pool
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-pod", "")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// AllocateNext with specific pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "override")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// AllocateNext with default pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "default")
	require.Nil(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)
}
