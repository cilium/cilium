// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	"github.com/cilium/cilium/pkg/aws/eni/types"
	metadataMock "github.com/cilium/cilium/pkg/aws/metadata/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	api := ec2mock.NewAPI(nil, nil, nil, nil)
	metadataMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
	require.NoError(t, err)
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
	}
	n.logger.Store(n.rootLogger)

	// With no k8sObj defined, it should return 0
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	require.Equal(t, 27, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	require.Equal(t, 18, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())
}

func Test_findSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
				"subnet-3": {},
			},
		},
		"rt-2": &ipamTypes.RouteTable{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-2",
			Subnets: map[string]struct{}{
				"subnet-4": {},
			},
		},
	}

	node := &Node{
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				ENI: types.ENISpec{
					VpcID:            "vpc-1",
					NodeSubnetID:     "subnet-1",
					AvailabilityZone: "us-east-1a",
				},
			},
		},
		manager: &InstancesManager{
			subnets: map[string]*ipamTypes.Subnet{
				"subnet-1": {
					ID:                 "subnet-1",
					AvailableAddresses: 10,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-2": {
					ID:                 "subnet-2",
					AvailableAddresses: 20,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-3": {
					ID:                 "subnet-3",
					AvailableAddresses: 25,
					AvailabilityZone:   "us-east-1b",
				},
				"subnet-4": {
					ID:                 "subnet-4",
					AvailableAddresses: 15,
					AvailabilityZone:   "us-east-1a",
				},
			},
			routeTables: routeTableMap,
		},
	}

	got := node.findSubnetInSameRouteTableWithNodeSubnet()
	require.NotNil(t, got)
	require.Equal(t, "subnet-2", got.ID)
	require.Equal(t, 20, got.AvailableAddresses)

	node.k8sObj.Spec.ENI.VpcID = "vpc-2"
	got = node.findSubnetInSameRouteTableWithNodeSubnet()
	require.Nil(t, got)

}

func Test_findSubnetInSameRouteTableWithNodeSubnet_UntrackedSubnets(t *testing.T) {
	// This test ensures that the function handles the case where the route table
	// references subnets that are not tracked by the manager because they were filtered
	// out by the subnetsFilters parameter
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {}, // node subnet
				"subnet-2": {}, // tracked subnet
				"subnet-3": {}, // untracked subnet (not in manager.subnets)
				"subnet-4": {}, // another tracked subnet
			},
		},
	}

	node := &Node{
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				ENI: types.ENISpec{
					VpcID:            "vpc-1",
					NodeSubnetID:     "subnet-1",
					AvailabilityZone: "us-east-1a",
				},
			},
		},
		manager: &InstancesManager{
			subnets: map[string]*ipamTypes.Subnet{
				"subnet-1": {
					ID:                 "subnet-1",
					AvailableAddresses: 10,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-2": {
					ID:                 "subnet-2",
					AvailableAddresses: 20,
					AvailabilityZone:   "us-east-1a",
				},
				// subnet-3 is intentionally missing to simulate an untracked subnet
				"subnet-4": {
					ID:                 "subnet-4",
					AvailableAddresses: 30,
					AvailabilityZone:   "us-east-1a",
				},
			},
			routeTables: routeTableMap,
		},
	}

	// This should not panic and should return subnet-4 (highest available addresses)
	got := node.findSubnetInSameRouteTableWithNodeSubnet()
	require.NotNil(t, got)
	require.Equal(t, "subnet-4", got.ID)
	require.Equal(t, 30, got.AvailableAddresses)
}

func Test_checkSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
			},
		},
		"rt-2": &ipamTypes.RouteTable{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-2",
			Subnets: map[string]struct{}{
				"subnet-3": {},
			},
		},
	}

	tests := []struct {
		name     string
		nodeSpec *v2.CiliumNode
		subnet   *ipamTypes.Subnet
		want     bool
	}{
		{
			name: "same route table",
			nodeSpec: &v2.CiliumNode{
				Spec: v2.NodeSpec{
					ENI: types.ENISpec{
						VpcID:        "vpc-1",
						NodeSubnetID: "subnet-1",
					},
				},
			},
			subnet: &ipamTypes.Subnet{
				ID: "subnet-2",
			},
			want: true,
		},
		{
			name: "different route table",
			nodeSpec: &v2.CiliumNode{
				Spec: v2.NodeSpec{
					ENI: types.ENISpec{
						VpcID:        "vpc-1",
						NodeSubnetID: "subnet-1",
					},
				},
			},
			subnet: &ipamTypes.Subnet{
				ID: "subnet-3",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{
				k8sObj: tt.nodeSpec,
				manager: &InstancesManager{
					routeTables: routeTableMap,
				},
			}
			got := node.checkSubnetInSameRouteTableWithNodeSubnet(tt.subnet)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsPrefixDelegated(t *testing.T) {
	tests := []struct {
		name            string
		instanceType    string
		expectDelegated bool
	}{
		{
			name:            "xen instance",
			instanceType:    "m4.large",
			expectDelegated: false,
		},
		{
			name:            "metal instance",
			instanceType:    "m5.metal",
			expectDelegated: true,
		},
		{
			name:            "nitro instance",
			instanceType:    "m5.large",
			expectDelegated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := ec2mock.NewAPI(nil, nil, nil, nil)
			metadataMock, _ := metadataMock.NewMetadataMock()
			instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
			require.NoError(t, err)
			n := &Node{
				rootLogger: hivetest.Logger(t),
				manager:    instances,
				k8sObj:     newCiliumNode("node1", withInstanceType(tt.instanceType)),
				node: &mockIPAMNode{
					prefixDelegation: true,
				},
			}
			n.logger.Store(n.rootLogger)

			require.Equal(t, tt.expectDelegated, n.IsPrefixDelegated())
		})
	}
}
