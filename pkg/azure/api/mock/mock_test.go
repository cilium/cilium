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
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/checker"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type MockSuite struct{}

var _ = check.Suite(&MockSuite{})

func (e *MockSuite) TestMock(c *check.C) {
	api := NewAPI([]*ipamTypes.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	c.Assert(api, check.Not(check.IsNil))

	instances, err := api.GetInstances(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 0)

	vnets, subnets, err := api.GetVpcsAndSubnets(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(len(vnets), check.Equals, 1)
	c.Assert(vnets["v-1"], checker.DeepEquals, &ipamTypes.VirtualNetwork{ID: "v-1"})
	c.Assert(len(subnets), check.Equals, 1)
	c.Assert(subnets["s-1"], checker.DeepEquals, &ipamTypes.Subnet{ID: "s-1", AvailableAddresses: 100})

	instances = ipamTypes.NewInstanceMap()
	instances.Update("i-1", ipamTypes.InterfaceRevision{Resource: &types.AzureInterface{ID: "intf-1"}})
	api.UpdateInstances(instances)
	instances, err = api.GetInstances(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 1)
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		c.Assert(instanceID, check.Equals, "i-1")
		c.Assert(interfaceID, check.Equals, "intf-1")
		return nil
	})

	err = api.AssignPrivateIpAddresses(context.Background(), "s-1", "intf-1", []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")})
	c.Assert(err, check.IsNil)
	instances, err = api.GetInstances(context.Background())
	c.Assert(err, check.IsNil)
	c.Assert(instances.NumInstances(), check.Equals, 1)
	instances.ForeachInterface("", func(instanceID, interfaceID string, revision ipamTypes.InterfaceRevision) error {
		c.Assert(instanceID, check.Equals, "i-1")
		c.Assert(interfaceID, check.Equals, "intf-1")

		iface, ok := revision.Resource.(*types.AzureInterface)
		c.Assert(ok, check.Equals, true)
		c.Assert(iface, checker.DeepEquals, &types.AzureInterface{
			ID: "intf-1",
			Addresses: []types.AzureAddress{
				{IP: "1.1.1.1", Subnet: "s-1", State: types.StateSucceeded},
				{IP: "2.2.2.2", Subnet: "s-1", State: types.StateSucceeded},
			}})
		return nil
	})
}

func (e *MockSuite) TestSetMockError(c *check.C) {
	api := NewAPI([]*ipamTypes.Subnet{}, []*ipamTypes.VirtualNetwork{})
	c.Assert(api, check.Not(check.IsNil))

	mockError := errors.New("error")

	api.SetMockError(GetInstances, mockError)
	_, err := api.GetInstances(context.Background())
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(GetVpcsAndSubnets, mockError)
	_, _, err = api.GetVpcsAndSubnets(context.Background())
	c.Assert(err, check.Equals, mockError)

	api.SetMockError(AssignPrivateIpAddresses, mockError)
	err = api.AssignPrivateIpAddresses(context.Background(), "s-1", "i-1", []net.IP{})
	c.Assert(err, check.Equals, mockError)
}

func (e *MockSuite) TestSetLimiter(c *check.C) {
	api := NewAPI([]*ipamTypes.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	c.Assert(api, check.Not(check.IsNil))

	api.SetLimiter(10.0, 2)
	_, err := api.GetInstances(context.Background())
	c.Assert(err, check.IsNil)
}
