// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	azuretypes "github.com/cilium/cilium/pkg/azure/types"
	// Register the Azure resource-ID parser so SetID()/extractIDs() populate
	// the VMSS/VM/RG fields exercised by TestExtractIDs.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
)

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
			intf := azuretypes.AzureInterface{}
			intf.SetID(tt.resourceID)

			require.Equal(t, tt.expectedRG, intf.GetResourceGroup())
			require.Equal(t, tt.expectedVMID, intf.GetVMID())
			require.Equal(t, tt.expectedVMSSName, intf.GetVMScaleSetName())
		})
	}
}
