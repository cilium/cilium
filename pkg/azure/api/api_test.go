// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSubnetID(t *testing.T) {
	tests := []struct {
		name           string
		subnetID       string
		expectedRG     string
		expectedVNet   string
		expectedSubnet string
		shouldError    bool
	}{
		{
			name:           "valid subnet ID",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/my-subnet",
			expectedRG:     "my-rg",
			expectedVNet:   "my-vnet",
			expectedSubnet: "my-subnet",
			shouldError:    false,
		},
		{
			name:           "valid subnet ID with hyphens in names",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/test-rg-name/providers/Microsoft.Network/virtualNetworks/test-vnet-name/subnets/test-subnet-name",
			expectedRG:     "test-rg-name",
			expectedVNet:   "test-vnet-name",
			expectedSubnet: "test-subnet-name",
			shouldError:    false,
		},
		{
			name:           "invalid format - too few parts",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
		{
			name:           "invalid format - too many parts",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/my-subnet/extra",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
		{
			name:           "invalid format - wrong structure",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/badstructure/my-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/my-subnet",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
		{
			name:           "invalid format - empty vnet name",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg/providers/Microsoft.Network/virtualNetworks//subnets/my-subnet",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
		{
			name:           "invalid format - empty subnet name",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
		{
			name:           "empty subnet ID",
			subnetID:       "",
			expectedRG:     "",
			expectedVNet:   "",
			expectedSubnet: "",
			shouldError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resourceGroup, vnetName, subnetName, err := parseSubnetID(tt.subnetID)

			if tt.shouldError {
				require.Error(t, err, "expected error for test case: %s", tt.name)
			} else {
				require.NoError(t, err, "unexpected error for test case: %s", tt.name)
				require.Equal(t, tt.expectedRG, resourceGroup, "resource group name mismatch")
				require.Equal(t, tt.expectedVNet, vnetName, "vnet name mismatch")
				require.Equal(t, tt.expectedSubnet, subnetName, "subnet name mismatch")
			}
		})
	}
}
