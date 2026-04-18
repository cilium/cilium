// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
)

func fakeIPv4AllocCIDRIP(fakeAddressing node.Addressing) netip.Addr {
	return netip.MustParseAddr(fakeAddressing.IPv4().AllocationCIDR().IP.String())
}

func fakeIPv6AllocCIDRIP(fakeAddressing node.Addressing) netip.Addr {
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
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse test cidr %s for pool %s", cidr, name))
		}
		pools[Pool(name)] = newHostScopeAllocator(prefix)
	}
	return &fakePoolAllocator{pools: pools}
}

func (f *fakePoolAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	alloc, ok := f.pools[pool]
	if !ok {
		return nil, fmt.Errorf("unknown pool %s", pool)
	}
	result, err := alloc.Allocate(addr, owner, pool)
	if err != nil {
		return nil, err
	}
	result.IPPoolName = pool
	return result, nil
}

func (f fakePoolAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return f.Allocate(addr, owner, pool)
}

func (f fakePoolAllocator) Release(addr netip.Addr, pool Pool) error {
	alloc, ok := f.pools[pool]
	if !ok {
		return fmt.Errorf("unknown pool %s", pool)
	}
	return alloc.Release(addr, pool)
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
		maps.Copy(result[name], dump[name])
	}
	return result, fmt.Sprintf("%d pools", len(f.pools))
}

func (f fakePoolAllocator) Capacity() uint64 {
	return uint64(0)
}

func (f fakePoolAllocator) RestoreFinished() {}

func TestLock(t *testing.T) {
	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	ipam.ConfigureAllocator()

	// Since the IPs we have allocated to the endpoints might or might not
	// be in the allocrange specified in cilium, we need to specify them
	// manually on the endpoint based on the alloc range.
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	// Forcefully release possible allocated IPs
	ipam.ipv4Allocator.Release(ipv4, PoolDefault())
	ipam.ipv6Allocator.Release(ipv6, PoolDefault())

	// Let's allocate the IP first so we can see the tests failing
	result, err := ipam.ipv4Allocator.Allocate(ipv4, "test", PoolDefault())
	require.NoError(t, err)
	require.Equal(t, ipv4, result.IP)
}

func TestExcludeIP(t *testing.T) {
	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	ipam.ConfigureAllocator()

	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()

	ipam.ExcludeIP(ipv4.AsSlice(), "test-foo", PoolDefault())
	err := ipam.AllocateIP(ipv4.AsSlice(), "test-bar", PoolDefault())
	require.Error(t, err)
	require.ErrorContains(t, err, "owned by test-foo")
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault())
	require.NoError(t, err)

	ipv6 := fakeIPv6AllocCIDRIP(fakeAddressing)
	ipv6 = ipv6.Next()

	ipam.ExcludeIP(ipv6.AsSlice(), "test-foo", PoolDefault())
	err = ipam.AllocateIP(ipv6.AsSlice(), "test-bar", PoolDefault())
	require.Error(t, err)
	require.ErrorContains(t, err, "owned by test-foo")
	ipam.ReleaseIP(ipv6.AsSlice(), PoolDefault())
	err = ipam.ReleaseIP(ipv4.AsSlice(), PoolDefault())
	require.NoError(t, err)
}

func TestDeriveFamily(t *testing.T) {
	require.Equal(t, IPv4, DeriveFamily(netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, IPv6, DeriveFamily(netip.MustParseAddr("f00d::1")))
}

func TestIPAMMetadata(t *testing.T) {
	fakeAddressing := fakenode.NewAddressing()
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

	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
		Metadata:       fakeMetadata,
	})
	ipam.ConfigureAllocator()
	ipam.ipv4Allocator = newFakePoolAllocator(map[string]string{
		"default": "10.10.0.0/16",
		"test":    "192.168.178.0/24",
		"special": "172.18.19.0/24",
	})
	ipam.ipv6Allocator = newFakePoolAllocator(map[string]string{
		"default": "fd00:100::/80",
		"test":    "fc00:100::/96",
		"special": "fe00:100::/80",
	})

	// Checks AllocateIP
	specialIP := netip.MustParseAddr("172.18.19.20")
	_, err := ipam.AllocateIPWithoutSyncUpstream(specialIP.AsSlice(), "special/wants-special-ip", "")
	require.Error(t, err) // pool required
	resIPv4, err := ipam.AllocateIPWithoutSyncUpstream(specialIP.AsSlice(), "special/wants-special-ip", "special")
	require.NoError(t, err)
	require.Equal(t, Pool("special"), resIPv4.IPPoolName)
	require.Equal(t, specialIP, resIPv4.IP)

	// Checks ReleaseIP
	err = ipam.ReleaseIP(specialIP.AsSlice(), "")
	require.Error(t, err) // pool required
	err = ipam.ReleaseIP(specialIP.AsSlice(), "special")
	require.NoError(t, err)

	// Checks if pool metadata is used if pool is empty
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-other-pod", "")
	require.NoError(t, err)
	require.Equal(t, Pool("test"), resIPv4.IPPoolName)
	require.Equal(t, Pool("test"), resIPv6.IPPoolName)

	// Checks if pool can be overwritten
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/special-pod", "special")
	require.NoError(t, err)
	require.Equal(t, Pool("special"), resIPv4.IPPoolName)
	require.Equal(t, Pool("special"), resIPv6.IPPoolName)

	// Checks if fallback to default works
	resIPv4, resIPv6, err = ipam.AllocateNext("", "other/special-pod", "")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// Checks if metadata errors are propagated
	_, _, err = ipam.AllocateNext("", "error/special-value", "")
	require.Error(t, err)
}

func TestLegacyAllocatorIPAMMetadata(t *testing.T) {
	// This test uses a regular hostScope allocator which does not support
	// IPAM pools. We assert that in this scenario, the pool returned in the
	// AllocationResult is always set to PoolDefault(), regardless of the requested
	// pool
	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) { return "some-pool", nil })
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
		Metadata:       fakeMetadata,
	})
	ipam.ConfigureAllocator()

	// AllocateIP requires explicit pool
	ipv4 := fakeIPv4AllocCIDRIP(fakeAddressing)
	ipv4 = ipv4.Next()
	_, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "")
	require.Error(t, err)

	// AllocateIP with specific pool
	ipv4 = ipv4.Next()
	resIPv4, err := ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "override")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)

	// AllocateIP with default pool
	ipv4 = ipv4.Next()
	resIPv4, err = ipam.AllocateIPWithoutSyncUpstream(ipv4.AsSlice(), "default/specific-ip", "default")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)

	// AllocateNext with empty pool
	resIPv4, resIPv6, err := ipam.AllocateNext("", "test/some-pod", "")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// AllocateNext with specific pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "override")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)

	// AllocateNext with default pool
	resIPv4, resIPv6, err = ipam.AllocateNext("", "test/some-other-pod", "default")
	require.NoError(t, err)
	require.Equal(t, PoolDefault(), resIPv4.IPPoolName)
	require.Equal(t, PoolDefault(), resIPv6.IPPoolName)
}
