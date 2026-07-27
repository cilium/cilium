// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package azureid provides the Azure resource ID parser used by
// pkg/azure/types. It lives in its own package so that the Azure SDK
// (github.com/Azure/azure-sdk-for-go) is only linked into binaries that
// explicitly import this package, keeping the SDK out of non-Azure builds
// (in particular cilium-operator-generic, which transitively imports
// pkg/azure/types via CiliumNode's AzureSpec).
//
// On import, this package registers Parse with pkg/azure/types so that
// AzureInterface.SetID() can extract the resource group, VMSS name, and VM ID
// from a network interface resource ID.
package azureid

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

	"github.com/cilium/cilium/pkg/azure/types"
)

const (
	resourceTypeVirtualMachines         = "virtualMachines"
	resourceTypeVirtualMachineScaleSets = "virtualMachineScaleSets"
)

func init() {
	types.RegisterResourceIDParser(Parse)
}

// Parse parses a network interface Azure resource ID and returns the
// resource group name, VMSS name (if any), and VM ID (if any). On parse
// failure or missing fields, empty strings are returned.
func Parse(id string) (resourceGroup, vmssName, vmID string) {
	resourceID, err := arm.ParseResourceID(id)
	if err != nil {
		return "", "", ""
	}

	resourceGroup = resourceID.ResourceGroupName

	// For VMSS instances, walk up the parent chain to extract VMSS name and VM ID.
	// Resource ID structure for VMSS VM interfaces:
	// /subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.Compute/virtualMachineScaleSets/ssss/virtualMachines/vvv/networkInterfaces/iii
	current := resourceID
	for current != nil {
		resourceType := current.ResourceType
		if len(resourceType.Types) == 0 {
			current = current.Parent
			continue
		}

		lastType := resourceType.Types[len(resourceType.Types)-1]

		if strings.EqualFold(lastType, resourceTypeVirtualMachines) {
			vmID = current.Name
		}

		if strings.EqualFold(lastType, resourceTypeVirtualMachineScaleSets) {
			vmssName = current.Name
		}

		current = current.Parent
	}

	return resourceGroup, vmssName, vmID
}
