// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"

	check "github.com/cilium/checkmate"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             cidr.MustParseCIDR("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             cidr.MustParseCIDR("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             cidr.MustParseCIDR("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             cidr.MustParseCIDR("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-3",
			CIDR:             cidr.MustParseCIDR("3.3.0.0/16"),
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

func iteration1(api *apimock.API, mngr *InstancesManager) {
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
	mngr.Resync(context.Background())
}

func iteration2(api *apimock.API, mngr *InstancesManager) {
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
	mngr.Resync(context.TODO())
}

func (e *IPAMSuite) TestGetVpcsAndSubnets(c *check.C) {
	api := apimock.NewAPI(subnets, vnets)
	c.Assert(api, check.Not(check.IsNil))

	mngr := NewInstancesManager(api)
	c.Assert(mngr, check.Not(check.IsNil))

	c.Assert(mngr.subnets["subnet-1"], check.IsNil)
	c.Assert(mngr.subnets["subnet-2"], check.IsNil)
	c.Assert(mngr.subnets["subnet-3"], check.IsNil)

	iteration1(api, mngr)

	c.Assert(mngr.subnets["subnet-1"], check.Not(check.IsNil))
	c.Assert(mngr.subnets["subnet-2"], check.Not(check.IsNil))
	c.Assert(mngr.subnets["subnet-3"], check.IsNil)

	iteration2(api, mngr)

	c.Assert(mngr.subnets["subnet-1"], check.Not(check.IsNil))
	c.Assert(mngr.subnets["subnet-2"], check.Not(check.IsNil))
	c.Assert(mngr.subnets["subnet-3"], check.Not(check.IsNil))
}
