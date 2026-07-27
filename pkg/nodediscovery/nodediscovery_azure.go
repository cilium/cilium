// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"fmt"
	"strings"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
)

// mutateAzureNodeResource fills in the Azure-specific fields of the
// CiliumNode resource. It is kept in a separate file so that the
// Azure-specific imports are not pulled in via the main nodediscovery.go.
func (n *NodeDiscovery) mutateAzureNodeResource(_ context.Context, nodeResource *ciliumv2.CiliumNode, ln *node.LocalNode) error {
	if ln.Local.ProviderID == "" {
		logging.Fatal(n.logger, "Spec.ProviderID in k8s node resource must be set for Azure IPAM")
	}
	if !strings.HasPrefix(ln.Local.ProviderID, azureTypes.ProviderPrefix) {
		logging.Fatal(n.logger, fmt.Sprintf("Spec.ProviderID in k8s node resource must have prefix %s", azureTypes.ProviderPrefix))
	}
	// The Azure controller in Kubernetes creates a mix of upper and lower
	// case when filling in the ProviderID and is therefore not providing the
	// exact representation of what is returned by the Azure API. Convert it
	// to lower case for consistent results.
	nodeResource.Spec.InstanceID = strings.ToLower(strings.TrimPrefix(ln.Local.ProviderID, azureTypes.ProviderPrefix))

	nodeResource.Spec.IPAM.MinAllocate = n.config.IPAMMinAllocate
	nodeResource.Spec.IPAM.PreAllocate = n.config.IPAMPreAllocate
	nodeResource.Spec.IPAM.MaxAllocate = n.config.IPAMMaxAllocate
	nodeResource.Spec.Azure.InterfaceName = n.config.AzureInterfaceName

	if c := n.cniConfigManager.GetCustomNetConf(); c != nil {
		if c.IPAM.MinAllocate != 0 {
			nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
		}
		if c.IPAM.PreAllocate != 0 {
			nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
		}
		if c.Azure.InterfaceName != "" {
			nodeResource.Spec.Azure.InterfaceName = c.Azure.InterfaceName
		}
	}

	return nil
}
