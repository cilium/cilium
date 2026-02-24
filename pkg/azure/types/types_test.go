// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ipam/types"
)

func TestForeachAddresses(t *testing.T) {
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
	require.Equal(t, 4, addresses)

	// Iterate over "i-1"
	addresses = 0
	m.ForeachAddress("i-1", func(instanceID, interfaceID, ip, poolID string, address types.Address) error {
		addresses++
		return nil
	})
	require.Equal(t, 2, addresses)

	// Iterate over all interfaces
	interfaces := 0
	m.ForeachInterface("", func(instanceID, interfaceID string, interfaceObj types.InterfaceRevision) error {
		interfaces++
		return nil
	})
	require.Equal(t, 2, interfaces)
}

func TestExtractIDs(t *testing.T) {
	vmssIntf := AzureInterface{}
	vmssIntf.SetID("/subscriptions/xxx/resourceGroups/MC_aks-test_aks-test_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-nodepool1-10706209-vmss/virtualMachines/3/networkInterfaces/aks-nodepool1-10706209-vmss")

	vmIntf := AzureInterface{}
	vmIntf.SetID("/subscriptions/xxx/resourceGroups/az-test-rg/providers/Microsoft.Network/networkInterfaces/pods-interface")

	require.Equal(t, "MC_aks-test_aks-test_westeurope", vmssIntf.GetResourceGroup())
	require.Equal(t, "3", vmssIntf.GetVMID())
	require.Equal(t, "aks-nodepool1-10706209-vmss", vmssIntf.GetVMScaleSetName())
	require.Equal(t, "az-test-rg", vmIntf.GetResourceGroup())
}
