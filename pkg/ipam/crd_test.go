// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

func testDaemonConfig() *option.DaemonConfig {
	return &option.DaemonConfig{
		EnableIPv4:              true,
		EnableIPv6:              false,
		EnableHealthChecking:    true,
		EnableUnreachableRoutes: false,
		IPAM:                    ipamOption.IPAMCRD,
	}
}

func newFakeNodeStore(conf *option.DaemonConfig, t *testing.T) *nodeStore {
	tr, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "fake-crd-allocator-node-refresher",
		MinInterval: 3 * time.Second,
		TriggerFunc: func(reasons []string) {},
	})
	if err != nil {
		logging.Fatal(hivetest.Logger(t), "Unable to initialize CiliumNode synchronization trigger", logfields.Error, err)
	}
	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
		refreshTrigger:     tr,
	}
	return store
}

func TestMarkForReleaseNoAllocate(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "foo"}
	for i := 1; i <= 4; i++ {
		cn.Spec.IPAM.Pool[iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i)))] = dummyResource
	}

	fakeAddressing := fakenode.NewAddressing()
	conf := testDaemonConfig()
	initNodeStore.Do(func() {}) // Ensure the real initNodeStore is not called
	sharedNodeStore = newFakeNodeStore(conf, t)
	sharedNodeStore.ownNode = cn

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    conf,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	require.NoError(t, ipam.ConfigureAllocator(t.Context()))
	sharedNodeStore.updateLocalNodeResource(cn)

	// Allocate the first 3 IPs
	for i := 1; i <= 3; i++ {
		epipv4 := netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))
		_, err := ipam.ipv4Allocator.Allocate(epipv4, fmt.Sprintf("test%d", i), PoolDefault())
		require.NoError(t, err)
	}

	// Update 1.1.1.4 as marked for release like operator would.
	cn.Status.IPAM.ReleaseIPs[iputil.AddrFrom(netip.MustParseAddr("1.1.1.4"))] = ipamOption.IPAMMarkForRelease
	// Attempts to allocate 1.1.1.4 should fail, since it's already marked for release
	epipv4 := netip.MustParseAddr("1.1.1.4")
	_, err := ipam.ipv4Allocator.Allocate(epipv4, "test", PoolDefault())
	require.Error(t, err)
	// Call agent's CRD update function. status for 1.1.1.4 should change from marked for release to ready for release
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMReadyForRelease, string(cn.Status.IPAM.ReleaseIPs[iputil.AddrFrom(netip.MustParseAddr("1.1.1.4"))]))

	// Verify that 1.1.1.3 is denied for release, since it's already in use
	cn.Status.IPAM.ReleaseIPs[iputil.AddrFrom(netip.MustParseAddr("1.1.1.3"))] = ipamOption.IPAMMarkForRelease
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMDoNotRelease, string(cn.Status.IPAM.ReleaseIPs[iputil.AddrFrom(netip.MustParseAddr("1.1.1.3"))]))
}

func TestNodeStoreStaticIPStatus(t *testing.T) {
	newNode := func(tags map[string]string, assigned netip.Addr) *ciliumv2.CiliumNode {
		cn := newCiliumNode("node1", 0, 0, 0)
		cn.Spec.IPAM.StaticIPTags = tags
		cn.Status.IPAM.AssignedStaticIP = iputil.AddrFrom(assigned)
		return cn
	}

	tests := []struct {
		name                  string
		ownNode               *ciliumv2.CiliumNode
		wantRequestedStaticIP bool
		wantAssignedStaticIP  netip.Addr
	}{
		{
			name:                  "nil node",
			ownNode:               nil,
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "no static IP requested",
			ownNode:               newNode(nil, netip.Addr{}),
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "static IP requested but not yet assigned",
			ownNode:               newNode(map[string]string{"env": "prod"}, netip.Addr{}),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "static IP requested and assigned",
			ownNode:               newNode(map[string]string{"env": "prod"}, netip.MustParseAddr("1.2.3.4")),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  netip.MustParseAddr("1.2.3.4"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &nodeStore{ownNode: tt.ownNode}
			requested, assigned := store.staticIPStatus()
			assert.Equal(t, tt.wantRequestedStaticIP, requested)
			assert.Equal(t, tt.wantAssignedStaticIP, assigned)
		})
	}
}
