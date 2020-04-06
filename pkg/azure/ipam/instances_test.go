// Copyright 2019-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package ipam

import (
	"context"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
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
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{
			ID:            "intf-1",
			SecurityGroup: "sg1",
			Addresses: []types.AzureAddress{
				{
					IP:     "1.1.1.1",
					Subnet: "subnet-1",
					State:  types.StateSucceeded,
				},
			},
			State: types.StateSucceeded,
		},
	})

	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{
			ID:            "intf-3",
			SecurityGroup: "sg3",
			Addresses: []types.AzureAddress{
				{
					IP:     "1.1.3.3",
					Subnet: "subnet-1",
					State:  types.StateSucceeded,
				},
			},
			State: types.StateSucceeded,
		},
	})
	api.UpdateInstances(instances)

	mngr.Resync(context.Background())
}

func iteration2(api *apimock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)

	instances := ipamTypes.NewInstanceMap()
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{
			ID:            "intf-1",
			SecurityGroup: "sg1",
			Addresses: []types.AzureAddress{
				{
					IP:     "1.1.1.1",
					Subnet: "subnet-1",
					State:  types.StateSucceeded,
				},
			},
			State: types.StateSucceeded,
		},
	})
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{
			ID:            "intf-2",
			SecurityGroup: "sg2",
			Addresses: []types.AzureAddress{
				{
					IP:     "3.3.3.3",
					Subnet: "subnet-3",
					State:  types.StateSucceeded,
				},
			},
			State: types.StateSucceeded,
		},
	})
	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{
			ID:            "intf-3",
			SecurityGroup: "sg3",
			Addresses: []types.AzureAddress{
				{
					IP:     "1.1.3.3",
					Subnet: "subnet-1",
					State:  types.StateSucceeded,
				},
			},
			State: types.StateSucceeded,
		},
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
