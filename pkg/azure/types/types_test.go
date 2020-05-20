// Copyright 2020 Authors of Cilium
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

package types

import (
	"testing"

	"github.com/cilium/cilium/pkg/ipam/types"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func (e *TypesSuite) TestForeachAddresses(c *check.C) {
	m := types.NewInstanceMap()
	m.Update("i-1", types.InterfaceRevision{
		Resource: &AzureInterface{ID: "1", Addresses: []AzureAddress{
			{IP: "1.1.1.1"},
			{IP: "2.2.2.2"},
		},
		}})
	m.Update("i-2", types.InterfaceRevision{
		Resource: &AzureInterface{ID: "1", Addresses: []AzureAddress{
			{IP: "3.3.3.3"},
			{IP: "4.4.4.4"},
		},
		}})

	// Iterate over all instances
	addresses := 0
	m.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, address types.Address) error {
		addresses++
		return nil
	})
	c.Assert(addresses, check.Equals, 4)

	// Iterate over "i-1"
	addresses = 0
	m.ForeachAddress("i-1", func(instanceID, interfaceID, ip, poolID string, address types.Address) error {
		addresses++
		return nil
	})
	c.Assert(addresses, check.Equals, 2)

	// Iterate over all interfaces
	interfaces := 0
	m.ForeachInterface("", func(instanceID, interfaceID string, interfaceObj types.InterfaceRevision) error {
		interfaces++
		return nil
	})
	c.Assert(interfaces, check.Equals, 2)
}

func (e *TypesSuite) TestExtractIDs(c *check.C) {
	vmssIntf := AzureInterface{
		ID: "/subscriptions/xxx/resourceGroups/MC_aks-test_aks-test_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-nodepool1-10706209-vmss/virtualMachines/3/networkInterfaces/aks-nodepool1-10706209-vmss",
	}
	vmIntf := AzureInterface{
		ID: "/subscriptions/xxx/resourceGroups/az-test-rg/providers/Microsoft.Network/networkInterfaces/pods-interface",
	}

	c.Assert(vmssIntf.GetResourceGroup(), check.Equals, "MC_aks-test_aks-test_westeurope")
	c.Assert(vmssIntf.GetVMID(), check.Equals, "3")
	c.Assert(vmssIntf.GetVMScaleSetName(), check.Equals, "aks-nodepool1-10706209-vmss")
	c.Assert(vmIntf.GetResourceGroup(), check.Equals, "az-test-rg")
}
