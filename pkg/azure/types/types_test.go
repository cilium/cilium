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
	tests := []struct {
		name             string
		resourceID       string
		expectedRG       string
		expectedVMID     string
		expectedVMSSName string
	}{
		{
			name:             "VMSS network interface",
			resourceID:       "/subscriptions/xxx/resourceGroups/MC_aks-test_aks-test_westeurope/providers/Microsoft.Compute/virtualMachineScaleSets/aks-nodepool1-10706209-vmss/virtualMachines/3/networkInterfaces/aks-nodepool1-10706209-vmss",
			expectedRG:       "MC_aks-test_aks-test_westeurope",
			expectedVMID:     "3",
			expectedVMSSName: "aks-nodepool1-10706209-vmss",
		},
		{
			name:             "Standalone VM network interface",
			resourceID:       "/subscriptions/xxx/resourceGroups/az-test-rg/providers/Microsoft.Network/networkInterfaces/pods-interface",
			expectedRG:       "az-test-rg",
			expectedVMID:     "",
			expectedVMSSName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intf := AzureInterface{}
			intf.SetID(tt.resourceID)

			require.Equal(t, tt.expectedRG, intf.GetResourceGroup())
			require.Equal(t, tt.expectedVMID, intf.GetVMID())
			require.Equal(t, tt.expectedVMSSName, intf.GetVMScaleSetName())
		})
	}
}
