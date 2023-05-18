// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/ipam/types"
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
	vmssIntf := AzureInterface{}
	vmssIntf.SetID("/subscriptions/xxx/resourceGroups/MC_aks-test_aks-test_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-nodepool1-10706209-vmss/virtualMachines/3/networkInterfaces/aks-nodepool1-10706209-vmss")

	vmIntf := AzureInterface{}
	vmIntf.SetID("/subscriptions/xxx/resourceGroups/az-test-rg/providers/Microsoft.Network/networkInterfaces/pods-interface")

	c.Assert(vmssIntf.GetResourceGroup(), check.Equals, "MC_aks-test_aks-test_westeurope")
	c.Assert(vmssIntf.GetVMID(), check.Equals, "3")
	c.Assert(vmssIntf.GetVMScaleSetName(), check.Equals, "aks-nodepool1-10706209-vmss")
	c.Assert(vmIntf.GetResourceGroup(), check.Equals, "az-test-rg")
}
