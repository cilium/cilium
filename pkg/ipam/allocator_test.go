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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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

type fakeMTU struct{}

func (f *fakeMTU) GetDeviceMTU() int {
	return 1500
}

func (f *fakeMTU) GetRouteMTU() int {
	return 1500
}

func (f *fakeMTU) GetRoutePostEncryptMTU() int {
	return 1500
}

var mtuMock = fakeMTU{}

func TestAllocatedIPDump(t *testing.T) {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(hivetest.Logger(t), fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil, nil, nil, nil, nil, false)
	ipam.ConfigureAllocator()

	allocv4, allocv6, status := ipam.Dump()
	require.NotEmpty(t, status)

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
	ipam := NewIPAM(hivetest.Logger(t), fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, nil, nil, nil, nil, nil, false)
	ipam.ConfigureAllocator()

	err := ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)

	uuid, err := ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// must fail, already registered
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Error(t, err)
	require.Empty(t, uuid)
	// must fail, already in use
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Error(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// Must succeed, IP must be released again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register new expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// attempt to stop with an invalid uuid, must fail
	err = ipam.StopExpirationTimer(ip, PoolDefault(), "unknown-uuid")
	require.Error(t, err)
	// stop expiration with valid uuid
	err = ipam.StopExpirationTimer(ip, PoolDefault(), uuid)
	require.NoError(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// must fail as IP is properly in use now
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Error(t, err)
	// release IP for real
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)

	// allocate IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// release IP, must also stop expiration timer
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)
	// allocate same IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register expiration timer must succeed even though stop was never called
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// release IP
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)
}

func TestAllocateNextWithExpiration(t *testing.T) {
	timeout := 50 * time.Millisecond

	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) { return "some-pool", nil })
	ipam := NewIPAM(hivetest.Logger(t), fakeAddressing, testConfiguration, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil, fakeMetadata, nil, nil, nil, nil, false)
	ipam.ConfigureAllocator()

	// Allocate IPs and test expiration timer. 'pool' is empty in order to test
	// that the allocated pool is passed to StartExpirationTimer
	ipv4, ipv6, err := ipam.AllocateNextWithExpiration("", "foo", "", timeout)
	require.NoError(t, err)

	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.Error(t, err)
	// IPv6 address must be in use
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.Error(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be available again
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// Release IPs
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.NoError(t, err)
	err = ipam.ReleaseIP(ipv6.IP, PoolDefault())
	require.NoError(t, err)

	// Allocate IPs again and test stopping the expiration timer
	ipv4, ipv6, err = ipam.AllocateNextWithExpiration("", "foo", PoolDefault(), timeout)
	require.NoError(t, err)

	// Stop expiration timer for IPv4 address
	err = ipam.StopExpirationTimer(ipv4.IP, PoolDefault(), ipv4.ExpirationUUID)
	require.NoError(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.Error(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// Release IPv4 address
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.NoError(t, err)
}

// insertPool writes a LocalPodIPPool object into StateDB.
func insertPool(t *testing.T, db *statedb.DB, tbl statedb.RWTable[k8s.LocalPodIPPool], name string, skipMasq bool) {
	t.Helper()
	ann := map[string]string{}
	if skipMasq {
		ann[annotation.IPAMSkipMasquerade] = "true"
	}

	poolObj := k8s.LocalPodIPPool{
		CiliumPodIPPool: &k8sv2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Annotations: ann,
			},
		},
		UpdatedAt: time.Now(),
	}

	w := db.WriteTxn(tbl)
	tbl.Insert(w, poolObj)
	w.Commit()
}

func createTestIPAM(t *testing.T, db *statedb.DB, pools statedb.Table[k8s.LocalPodIPPool], onlyMasqDefault bool) *IPAM {
	fakeAddressing := fakeTypes.NewNodeAddressing()
	cfg := &option.DaemonConfig{
		EnableIPv4:              true,
		EnableIPv6:              false,
		IPAM:                    ipamOption.IPAMMultiPool,
		RoutingMode:             option.RoutingModeTunnel,
		EnableHealthChecking:    true,
		EnableUnreachableRoutes: false,
	}

	ipam := NewIPAM(hivetest.Logger(t), fakeAddressing, cfg, &ownerMock{}, node.NewTestLocalNodeStore(node.LocalNode{}), &ownerMock{}, &resourceMock{}, &fakeMTU{}, nil, nil, nil, nil, db, pools, onlyMasqDefault)

	// Use a small fake allocator that supports pools
	ipam.IPv4Allocator = newFakePoolAllocator(map[string]string{
		"default": "10.0.0.0/24",
		"blue":    "10.0.1.0/24",
		"red":     "10.0.2.0/24",
		"green":   "10.0.3.0/24",
	})

	return ipam
}

func TestAllocateNextFamily_SkipMasquerade(t *testing.T) {
	db := statedb.New()
	poolsTbl, err := k8s.NewPodIPPoolTable(db)
	require.NoError(t, err)

	// onlyMasqueradeDefaultPool = true
	ipam := createTestIPAM(t, db, poolsTbl, true)
	res, err := ipam.AllocateNextFamily(IPv4, "ns/pod", "blue")
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true for non-default pools when onlyMasqueradeDefaultPool is set")
	res, err = ipam.AllocateNextFamily(IPv4, "ns/pod", "default")
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "default pool should always be masqueraded even if global flag set")
	// onlyMasqueradeDefaultPool = false but pool annotated with skip-masquerade
	insertPool(t, db, poolsTbl, "red", true)
	ipam = createTestIPAM(t, db, poolsTbl, false)
	res, err = ipam.AllocateNextFamily(IPv4, "ns/pod", "red")
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true based on pool annotation")
	// ignore annotation on default pool
	insertPool(t, db, poolsTbl, "default", true)
	ipam = createTestIPAM(t, db, poolsTbl, false)
	res, err = ipam.AllocateNextFamily(IPv4, "ns/pod", "default")
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "default pool should always be masqueraded even if annotation set")
	// neither flag nor annotation set
	insertPool(t, db, poolsTbl, "green", false)
	ipam = createTestIPAM(t, db, poolsTbl, false)
	res, err = ipam.AllocateNextFamily(IPv4, "ns/pod", "green")
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "SkipMasquerade should default to false")
}
