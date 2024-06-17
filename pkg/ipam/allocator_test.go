// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
)

type ownerMock struct{}

func (o *ownerMock) K8sEventReceived(resourceApiGroup, scope string, action string, valid, equal bool) {
}

func (o *ownerMock) K8sEventProcessed(scope string, action string, status bool) {}

func (o *ownerMock) UpdateCiliumNodeResource() {}

type resourceMock struct{}

func (rm *resourceMock) Observe(ctx context.Context, next func(resource.Event[*ciliumv2.CiliumNode]), complete func(error)) {
}

func (rm *resourceMock) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*ciliumv2.CiliumNode] {
	return nil
}

func (rm *resourceMock) Store(context.Context) (resource.Store[*ciliumv2.CiliumNode], error) {
	return nil, errors.New("unimplemented")
}

var mtuMock = mtu.NewConfiguration(0, false, false, false, false, 1500, nil)

func TestAllocatedIPDump(t *testing.T) {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil)
	ipam.ConfigureAllocator()

	allocv4, allocv6, status := ipam.Dump()
	require.NotEqual(t, "", status)

	// Test the format of the dumped ip addresses
	for ip := range allocv4 {
		require.NotNil(t, net.ParseIP(ip))
	}
	for ip := range allocv6 {
		require.NotNil(t, net.ParseIP(ip))
	}
}

func TestExpirationTimer(t *testing.T) {
	ip := net.ParseIP("1.1.1.1")
	timeout := 50 * time.Millisecond

	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil)
	ipam.ConfigureAllocator()

	err := ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Nil(t, err)

	uuid, err := ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Nil(t, err)
	require.NotEqual(t, "", uuid)
	// must fail, already registered
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NotNil(t, err)
	require.Equal(t, "", uuid)
	// must fail, already in use
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NotNil(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// Must succeed, IP must be released again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Nil(t, err)
	// register new expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Nil(t, err)
	require.NotEqual(t, "", uuid)
	// attempt to stop with an invalid uuid, must fail
	err = ipam.StopExpirationTimer(ip, PoolDefault(), "unknown-uuid")
	require.NotNil(t, err)
	// stop expiration with valid uuid
	err = ipam.StopExpirationTimer(ip, PoolDefault(), uuid)
	require.Nil(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// must fail as IP is properly in use now
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NotNil(t, err)
	// release IP for real
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.Nil(t, err)

	// allocate IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Nil(t, err)
	// register expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Nil(t, err)
	require.NotEqual(t, "", uuid)
	// release IP, must also stop expiration timer
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.Nil(t, err)
	// allocate same IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Nil(t, err)
	// register expiration timer must succeed even though stop was never called
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Nil(t, err)
	require.NotEqual(t, "", uuid)
	// release IP
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.Nil(t, err)
}

func TestAllocateNextWithExpiration(t *testing.T) {
	timeout := 50 * time.Millisecond

	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) { return "some-pool", nil })
	ipam := NewIPAM(fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, fakeMetadata)
	ipam.ConfigureAllocator()

	// Allocate IPs and test expiration timer. 'pool' is empty in order to test
	// that the allocated pool is passed to StartExpirationTimer
	ipv4, ipv6, err := ipam.AllocateNextWithExpiration("", "foo", "", timeout)
	require.Nil(t, err)

	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.NotNil(t, err)
	// IPv6 address must be in use
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.NotNil(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be available again
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.Nil(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.Nil(t, err)
	// Release IPs
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.Nil(t, err)
	err = ipam.ReleaseIP(ipv6.IP, PoolDefault())
	require.Nil(t, err)

	// Allocate IPs again and test stopping the expiration timer
	ipv4, ipv6, err = ipam.AllocateNextWithExpiration("", "foo", PoolDefault(), timeout)
	require.Nil(t, err)

	// Stop expiration timer for IPv4 address
	err = ipam.StopExpirationTimer(ipv4.IP, PoolDefault(), ipv4.ExpirationUUID)
	require.Nil(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.NotNil(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.Nil(t, err)
	// Release IPv4 address
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.Nil(t, err)
}
