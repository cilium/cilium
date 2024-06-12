// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamcell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/k8s"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides access to the IP address management
var Cell = cell.Module(
	"ipam",
	"IP Address Management",

	cell.Provide(newIPAddressManager),
)

type ipamParams struct {
	cell.In

	AgentConfig *option.DaemonConfig

	NodeAddressing      datapathTypes.NodeAddressing
	LocalNodeStore      *node.LocalNodeStore
	K8sEventReporter    *watchers.K8sEventReporter
	NodeResource        k8s.LocalCiliumNodeResource
	MTU                 mtu.MTU
	Clientset           k8sClient.Clientset
	IPAMMetadataManager *ipamMetadata.Manager
	NodeDiscovery       *nodediscovery.NodeDiscovery
}

func newIPAddressManager(params ipamParams) *ipam.IPAM {
	ipam := ipam.NewIPAM(params.NodeAddressing, params.AgentConfig, params.NodeDiscovery, params.LocalNodeStore, params.K8sEventReporter, params.NodeResource, params.MTU, params.Clientset)

	if params.IPAMMetadataManager != nil {
		ipam.WithMetadata(params.IPAMMetadataManager)
	}

	return ipam
}
