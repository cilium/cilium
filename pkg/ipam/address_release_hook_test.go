// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
)

type testAddressReleaseHook struct {
	initialize    func(context.Context) error
	beforeRelease func(netip.Addr, Pool) error
}

func (h testAddressReleaseHook) Initialize(ctx context.Context) error {
	return h.initialize(ctx)
}

func (h testAddressReleaseHook) BeforeRelease(ip netip.Addr, pool Pool) error {
	return h.beforeRelease(ip, pool)
}

func newHookTestIPAM(t *testing.T) *IPAM {
	t.Helper()
	return NewIPAM(NewIPAMParams{
		Logger: hivetest.Logger(t), NodeAddressing: fakenode.NewAddressing(),
		AgentConfig: testConfiguration, NodeDiscovery: &ownerMock{},
		LocalNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		K8sEventReg:    &ownerMock{}, NodeResource: &resourceMock{}, MTUConfig: &mtuMock,
	})
}

func TestAddressReleaseHookInitialization(t *testing.T) {
	ipam := newHookTestIPAM(t)
	cleanupErr := errors.New("stale hardware state")
	ipam.SetAddressReleaseHook(testAddressReleaseHook{initialize: func(context.Context) error {
		require.Nil(t, ipam.ipv4Allocator)
		require.Nil(t, ipam.ipv6Allocator)
		return cleanupErr
	}})
	require.ErrorIs(t, ipam.ConfigureAllocator(t.Context()), cleanupErr)
	require.Nil(t, ipam.ipv4Allocator)
	require.Nil(t, ipam.ipv6Allocator)
}

func TestAddressReleaseHookRetainsAllocation(t *testing.T) {
	for _, family := range []Family{IPv4, IPv6} {
		t.Run(string(family), func(t *testing.T) {
			ipam := newHookTestIPAM(t)
			cleanupErr := errors.New("hardware cleanup failed")
			calls := 0
			var address netip.Addr
			ipam.SetAddressReleaseHook(testAddressReleaseHook{
				initialize: func(context.Context) error { return nil },
				beforeRelease: func(ip netip.Addr, pool Pool) error {
					calls++
					require.Equal(t, address, ip)
					require.Equal(t, PoolDefault(), pool)
					require.Equal(t, "old-pod", ipam.getIPOwner(ip, pool))
					return cleanupErr
				},
			})
			require.NoError(t, ipam.ConfigureAllocator(t.Context()))
			result, err := ipam.AllocateNextFamily(family, "old-pod", PoolDefault())
			require.NoError(t, err)
			address = result.IP
			require.ErrorIs(t, ipam.ReleaseIP(address, PoolDefault()), cleanupErr)
			require.True(t, ipam.IsAllocatedIP(address))
			require.Error(t, ipam.AllocateIP(address, "new-pod", PoolDefault()))
			cleanupErr = nil
			require.NoError(t, ipam.ReleaseIP(address, PoolDefault()))
			require.Equal(t, 2, calls)
			require.False(t, ipam.IsAllocatedIP(address))
			require.NoError(t, ipam.AllocateIP(address, "new-pod", PoolDefault()))
		})
	}
}

func TestAddressReleaseHookProtectsExpiration(t *testing.T) {
	ipam := newHookTestIPAM(t)
	called := make(chan struct{}, 1)
	ipam.SetAddressReleaseHook(testAddressReleaseHook{
		initialize: func(context.Context) error { return nil },
		beforeRelease: func(netip.Addr, Pool) error {
			called <- struct{}{}
			return errors.New("hardware cleanup failed")
		},
	})
	require.NoError(t, ipam.ConfigureAllocator(t.Context()))
	result, err := ipam.AllocateNextFamily(IPv4, "old-pod", PoolDefault())
	require.NoError(t, err)
	_, err = ipam.StartExpirationTimer(result.IP, PoolDefault(), time.Millisecond)
	require.NoError(t, err)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("expiration did not invoke the release hook")
	}
	require.True(t, ipam.IsAllocatedIP(result.IP))
	require.Error(t, ipam.AllocateIP(result.IP, "new-pod", PoolDefault()))
}
