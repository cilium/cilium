// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

func TestIPNotAvailableInPoolError(t *testing.T) {
	err := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.Equal(t, err, err2)
	assert.ErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = errors.New("another error")
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = errors.New("another error")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.NotErrorIs(t, err, err2)

	err = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 = nil
	assert.NotErrorIs(t, err, err2)

	err = nil
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.NotErrorIs(t, err, err2)

	// We don't match against strings. It must be the sentinel value.
	err = errors.New("IP 2.1.1.1 is not available")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
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

	fakeAddressing := fakeTypes.NewNodeAddressing()
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
		_, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), fmt.Sprintf("test%d", i), PoolDefault())
		require.NoError(t, err)
	}

	// Update 1.1.1.4 as marked for release like operator would.
	cn.Status.IPAM.ReleaseIPs["1.1.1.4"] = ipamOption.IPAMMarkForRelease
	// Attempts to allocate 1.1.1.4 should fail, since it's already marked for release
	epipv4 := netip.MustParseAddr("1.1.1.4")
	_, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test", PoolDefault())
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

func TestIPMasq(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "eni-1"}
	cn.Spec.IPAM.Pool["10.1.1.226"] = dummyResource
	cn.Status.ENI.ENIs = map[string]eniTypes.ENI{
		"eni-1": {
			ID: "eni-1",
			Addresses: []string{
				"10.1.1.226",
				"10.1.1.229",
			},
			VPC: eniTypes.AwsVPC{
				ID:          "vpc-1",
				PrimaryCIDR: "10.1.0.0/16",
				CIDRs: []string{
					"10.2.0.0/16",
				},
			},
		},
	}

	fakeAddressing := fakeTypes.NewNodeAddressing()
	conf := testConfigurationCRD
	conf.IPAM = ipamOption.IPAMENI
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

	epipv4 := netip.MustParseAddr("10.1.1.226")
	result, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test1", PoolDefault())
	require.NoError(t, err)
	// The resulting CIDRs should contain the VPC CIDRs and the default ip-masq-agent CIDRs from pkg/ipmasq/ipmasq.go
	require.ElementsMatch(
		t,
		[]string{
			// VPC CIDRs
			"10.1.0.0/16",
			"10.2.0.0/16",
			// Default ip-masq-agent CIDRs
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4",
			"169.254.0.0/16",
		},
		result.CIDRs,
	)

	ipMasqAgent.Stop()
}

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

	fakeAddressing := fakeTypes.NewNodeAddressing()
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
	result, err := ipam.ipv4Allocator.Allocate(epipv4.AsSlice(), "test1", PoolDefault())
	require.NoError(t, err)
	// The resulting CIDRs should contain the Azure interface CIDR and the default ip-masq-agent CIDRs
	require.ElementsMatch(
		t,
		[]string{
			// Azure interface CIDR
			"10.10.1.0/24",
			// Default ip-masq-agent CIDRs
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4",
			"169.254.0.0/16",
		},
		result.CIDRs,
	)

	ipMasqAgent.Stop()
}

func Test_validateENIConfig(t *testing.T) {
	type args struct {
		node *ciliumv2.CiliumNode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    string
	}{
		{
			name: "Consistent ENI config",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Missing VPC Primary CIDR",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID: "vpc-1",
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC Primary CIDR not set for ENI eni-1",
		},
		{
			name: "VPC CIDRs contain invalid value",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "VPC CIDR not set for ENI eni-1",
		},
		{
			name: "ENI not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.226": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-2": {
									ID: "eni-2",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 not found in status",
		},
		{
			name: "ENI IP not found in status",
			args: args{
				node: &ciliumv2.CiliumNode{
					Spec: ciliumv2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							Pool: ipamTypes.AllocationMap{
								"10.1.1.227": ipamTypes.AllocationIP{
									Resource: "eni-1",
								},
							},
						},
					},
					Status: ciliumv2.NodeStatus{
						ENI: eniTypes.ENIStatus{
							ENIs: map[string]eniTypes.ENI{
								"eni-1": {
									ID: "eni-1",
									Addresses: []string{
										"10.1.1.226",
										"10.1.1.229",
									},
									VPC: eniTypes.AwsVPC{
										ID:          "vpc-1",
										PrimaryCIDR: "10.1.0.0/16",
										CIDRs: []string{
											"10.1.0.0/16",
											"10.2.0.0/16",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			want:    "ENI eni-1 does not have address 10.1.1.227",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateENIConfig(tt.args.node)
			require.Equal(t, tt.wantErr, got != nil, "error: %v", got)
			if tt.wantErr {
				require.Equal(t, tt.want, got.Error())
			}
		})
	}
}
