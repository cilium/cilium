// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// resourceIDParser parses an Azure network interface resource ID and returns
// (resourceGroup, vmssName, vmID). It is overridden via RegisterResourceIDParser
// from pkg/azure/types/azureid (which uses the Azure SDK) so that pkg/azure/types
// itself does not transitively pull the Azure SDK into every consumer of
// CiliumNode (which embeds AzureSpec). Non-Azure binaries leave this stub in
// place; they never call extractIDs() on real Azure resource IDs.
var resourceIDParser = func(_ string) (resourceGroup, vmssName, vmID string) {
	return "", "", ""
}

// RegisterResourceIDParser installs the function used to parse Azure network
// interface resource IDs into resource group, VMSS, and VM ID components.
//
// This indirection exists so that the Azure SDK (which provides the actual
// parser implementation) is only linked into binaries that import
// pkg/azure/types/azureid, keeping it out of non-Azure builds without
// requiring build tags.
func RegisterResourceIDParser(fn func(id string) (resourceGroup, vmssName, vmID string)) {
	if fn == nil {
		return
	}
	resourceIDParser = fn
}

func parseAzureResourceID(id string) (resourceGroup, vmssName, vmID string) {
	return resourceIDParser(id)
}
