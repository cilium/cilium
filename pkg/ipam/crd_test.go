// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

func TestIPNotAvailableInPoolError(t *testing.T) {
	err := NewIPNotAvailableInPoolError(netip.MustParseAddr("1.1.1.1"))
	err2 := NewIPNotAvailableInPoolError(netip.MustParseAddr("1.1.1.1"))
	assert.Equal(t, err, err2)
	assert.ErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(netip.MustParseAddr("2.1.1.1"))
	err2 = NewIPNotAvailableInPoolError(netip.MustParseAddr("1.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(netip.MustParseAddr("2.1.1.1"))
	err2 = errors.New("another error")
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = errors.New("another error")
	err2 = NewIPNotAvailableInPoolError(netip.MustParseAddr("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(netip.MustParseAddr("1.1.1.1"))
	err2 = nil
	assert.NotErrorIs(t, err, err2)

	err = nil
	err2 = NewIPNotAvailableInPoolError(netip.MustParseAddr("1.1.1.1"))
	assert.NotErrorIs(t, err, err2)

	// We don't match against strings. It must be the sentinel value.
	err = errors.New("IP 2.1.1.1 is not available")
	err2 = NewIPNotAvailableInPoolError(netip.MustParseAddr("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)
}

var testConfigurationCRD = &option.DaemonConfig{
	EnableIPv4:              true,
	EnableIPv6:              false,
	EnableHealthChecking:    true,
	EnableUnreachableRoutes: false,
	IPAM:                    ipamOption.IPAMCRD,
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
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = dummyResource
	}

	fakeAddressing := fakenode.NewAddressing()
	conf := testConfigurationCRD
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
	ipam.ConfigureAllocator()
	sharedNodeStore.updateLocalNodeResource(cn)

	// Allocate the first 3 IPs
	for i := 1; i <= 3; i++ {
		epipv4 := netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))
		_, err := ipam.ipv4Allocator.Allocate(epipv4, fmt.Sprintf("test%d", i), PoolDefault())
		require.NoError(t, err)
	}

	// Update 1.1.1.4 as marked for release like operator would.
	cn.Status.IPAM.ReleaseIPs["1.1.1.4"] = ipamOption.IPAMMarkForRelease
	// Attempts to allocate 1.1.1.4 should fail, since it's already marked for release
	epipv4 := netip.MustParseAddr("1.1.1.4")
	_, err := ipam.ipv4Allocator.Allocate(epipv4, "test", PoolDefault())
	require.Error(t, err)
	// Call agent's CRD update function. status for 1.1.1.4 should change from marked for release to ready for release
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMReadyForRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.4"]))

	// Verify that 1.1.1.3 is denied for release, since it's already in use
	cn.Status.IPAM.ReleaseIPs["1.1.1.3"] = ipamOption.IPAMMarkForRelease
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMDoNotRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.3"]))
}

type ipMasqMapDummy struct{}

func (m ipMasqMapDummy) Update(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Delete(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Dump() ([]netip.Prefix, error) { return []netip.Prefix{}, nil }

func TestAzureIPMasq(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "azure-interface-1"}
	cn.Spec.IPAM.Pool["10.10.1.5"] = dummyResource
	cn.Status.Azure.Interfaces = []azureTypes.AzureInterface{
		{
			ID:      "azure-interface-1",
			Name:    "eth0",
			MAC:     "00:00:5e:00:53:01",
			Gateway: "10.10.1.1",
			CIDR:    "10.10.1.0/24",
			Addresses: []azureTypes.AzureAddress{
				{IP: "10.10.1.5", Subnet: "subnet-1", State: azureTypes.StateSucceeded},
			},
		},
	}

	fakeAddressing := fakenode.NewAddressing()
	conf := testConfigurationCRD
	conf.IPAM = ipamOption.IPAMAzure
	conf.EnableIPMasqAgent = true
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), "", ipMasqMapDummy{})
	err := ipMasqAgent.Start()
	require.NoError(t, err)

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
		IPMasqAgent:    ipMasqAgent,
	})
	ipam.ConfigureAllocator()

	epipv4 := netip.MustParseAddr("10.10.1.5")
	result, err := ipam.ipv4Allocator.Allocate(epipv4, "test1", PoolDefault())
	require.NoError(t, err)
	// The resulting CIDRs should contain the Azure interface CIDR and the default ip-masq-agent CIDRs
	require.ElementsMatch(
		t,
		[]netip.Prefix{
			// Azure interface CIDR
			netip.MustParsePrefix("10.10.1.0/24"),
			// Default ip-masq-agent CIDRs
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("192.0.0.0/24"),
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("192.88.99.0/24"),
			netip.MustParsePrefix("198.18.0.0/15"),
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("240.0.0.0/4"),
			netip.MustParsePrefix("169.254.0.0/16"),
		},
		result.CIDRs,
	)

	ipMasqAgent.Stop()
}
