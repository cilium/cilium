// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types_test

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	// Register the Azure resource-ID parser used by TestExtractIDs.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
	iputil "github.com/cilium/cilium/pkg/ip"
)

// State that does not serialize forces a /status write on every IPAM sync.
func TestAzureStatusHasNoUnserializedState(t *testing.T) {
	status := reflect.TypeFor[types.AzureStatus]()

	queue := []reflect.Type{status}
	for len(queue) > 0 {
		ty := queue[0]
		queue = queue[1:]

		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		// iputil's wrappers serialize through MarshalText, so the unexported
		// state they keep is legitimate.
		if ty.Kind() != reflect.Struct || ty.PkgPath() != status.PkgPath() {
			continue
		}
		for field := range ty.Fields() {
			require.True(t, field.IsExported(), "%s.%s is unexported", ty.Name(), field.Name)
			require.NotEqual(t, "-", field.Tag.Get("json"), "%s.%s is excluded from JSON", ty.Name(), field.Name)
			queue = append(queue, field.Type)
		}
	}
}

// A round trip must not perturb the interface, or the write-skip gate breaks.
func TestAzureInterfaceJSONRoundTrip(t *testing.T) {
	base := &types.AzureInterface{
		ID:            "/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0/networkInterfaces/vmss1",
		IP:            iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		Name:          "eth0",
		MAC:           "aa:bb:cc:dd:ee:ff",
		State:         "succeeded",
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")), State: "succeeded"},
			{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), State: "succeeded"},
		},
		Subnet:  types.AzureSubnet{ID: "s-1", CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24"))},
		Gateway: iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
	}

	marshalled, err := json.Marshal(base)
	require.NoError(t, err)
	var roundTripped types.AzureInterface
	require.NoError(t, json.Unmarshal(marshalled, &roundTripped))

	require.Equal(t, *base, roundTripped)
	require.True(t, base.DeepEqual(&roundTripped))

	// Reordering must be visible to DeepEqual, or sorting the addresses in
	// PopulateStatusFields would be pointless.
	reordered := roundTripped.DeepCopy()
	reordered.Addresses[0], reordered.Addresses[1] = reordered.Addresses[1], reordered.Addresses[0]
	require.False(t, base.DeepEqual(reordered))
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
		{
			name:       "Unparseable resource ID",
			resourceID: "intf-1",
		},
		{
			name: "Empty resource ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intf := types.AzureInterface{ID: tt.resourceID}

			require.Equal(t, tt.expectedRG, intf.GetResourceGroup())
			require.Equal(t, tt.expectedVMID, intf.GetVMID())
			require.Equal(t, tt.expectedVMSSName, intf.GetVMScaleSetName())
		})
	}
}
