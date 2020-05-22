// Copyright 2019 Authors of Cilium
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

package mock

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	c.Assert(api, check.Not(check.IsNil))

	instances, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 0)

	vnets, subnets, err := api.GetVpcsAndSubnets(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(len(vnets), check.Equals, 1)
	c.Assert(vnets["v-1"], checker.DeepEquals, &ipamTypes.VirtualNetwork{ID: "v-1"})
	c.Assert(len(subnets), check.Equals, 1)
	c.Assert(subnets["s-1"], checker.DeepEquals, subnet)

	ifaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	instances = ipamTypes.NewInstanceMap()
	instances.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{ID: ifaceID, Name: "eth0"},
	})
	api.UpdateInstances(instances)
	instances, err = api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 1)
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		c.Assert(instanceID, check.Equals, "vm1")
		c.Assert(interfaceID, check.Equals, ifaceID)
		return nil
	})

	err = api.AssignPrivateIpAddressesVMSS(context.Background(), "vm1", "vmss1", "s-1", "eth0", 2)
	c.Assert(err, check.IsNil)
	instances, err = api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 1)
	instances.ForeachInterface("", func(instanceID, interfaceID string, revision ipamTypes.InterfaceRevision) error {
		c.Assert(instanceID, check.Equals, "vm1")
		c.Assert(interfaceID, check.Equals, ifaceID)

		iface, ok := revision.Resource.(*types.AzureInterface)
		c.Assert(ok, check.Equals, true)
		c.Assert(len(iface.Addresses), check.Equals, 2)
		return nil
	})

	vmIfaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm22-if"
	vmInstances := ipamTypes.NewInstanceMap()
	vmInstances.Update("vm2", ipamTypes.InterfaceRevision{
		Resource: &types.AzureInterface{ID: vmIfaceID, Name: "eth0"},
	})
	c.Assert(err, check.IsNil)
	c.Assert(vmInstances.NumInstances(), check.Equals, 1)
	vmInstances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		c.Assert(instanceID, check.Equals, "vm2")
		c.Assert(interfaceID, check.Equals, vmIfaceID)
		return nil
	})

}

func (e *MockSuite) TestSetMockError(c *check.C) {
	api := NewAPI([]*ipamTypes.Subnet{}, []*ipamTypes.VirtualNetwork{})
	c.Assert(api, check.Not(check.IsNil))

	mockError := errors.New("error")

	api.SetMockError(GetInstances, mockError)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(GetVpcsAndSubnets, mockError)
	_, _, err = api.GetVpcsAndSubnets(context.Background())
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AssignPrivateIpAddressesVMSS, mockError)
	err = api.AssignPrivateIpAddressesVMSS(context.Background(), "vmss1", "i-1", "s-1", "eth0", 0)
	c.Assert(err, check.Equals, mockError)
}

func (e *MockSuite) TestSetLimiter(c *check.C) {
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 100}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	c.Assert(api, check.Not(check.IsNil))

	api.SetLimiter(10.0, 2)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	c.Assert(err, check.IsNil)
}
