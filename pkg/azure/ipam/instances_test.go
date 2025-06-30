// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-3",
			CIDR:             netip.MustParsePrefix("3.3.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		},
	}

	vnets = []*ipamTypes.VirtualNetwork{
		{ID: "vpc-0"},
		{ID: "vpc-1"},
	}
)

func iteration1(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-1")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.3.3",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-3")
	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	api.UpdateInstances(instances)
	mngr.Resync(t.Context())
}

func iteration2(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)

	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-1")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg2",
		Addresses: []types.AzureAddress{
			{
				IP:     "3.3.3.3",
				Subnet: "subnet-3",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-2")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.3.3",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-3")
	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	api.UpdateInstances(instances)
	mngr.Resync(t.Context())
}

func TestGetVpcsAndSubnets(t *testing.T) {
	api := apimock.NewAPI(subnets, vnets)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	require.Nil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"])
	require.Nil(t, mngr.subnets["subnet-3"])

	iteration1(t, api, mngr)

	require.NotNil(t, mngr.subnets["subnet-1"])
	require.NotNil(t, mngr.subnets["subnet-2"])
	require.Nil(t, mngr.subnets["subnet-3"])

	iteration2(t, api, mngr)

	require.NotNil(t, mngr.subnets["subnet-1"])
	require.NotNil(t, mngr.subnets["subnet-2"])
	require.NotNil(t, mngr.subnets["subnet-3"])
}
