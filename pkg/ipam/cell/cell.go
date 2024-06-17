// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamcell

import (
	"github.com/cilium/hive/cell"

	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/daemon/k8s"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamapi "github.com/cilium/cilium/pkg/ipam/api"
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
	cell.Provide(newIPAMAPIHandler),

	// IPAM metadata manager, determines which IPAM pool a pod should allocate from
	ipamMetadata.Cell,
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
	IPAMMetadataManager ipamMetadata.Manager
	NodeDiscovery       *nodediscovery.NodeDiscovery
}

func newIPAddressManager(params ipamParams) *ipam.IPAM {
	return ipam.NewIPAM(params.NodeAddressing, params.AgentConfig, params.NodeDiscovery, params.LocalNodeStore, params.K8sEventReporter, params.NodeResource, params.MTU, params.Clientset, params.IPAMMetadataManager)
}

type ipamAPIHandlerParams struct {
	cell.In

	IPAM            *ipam.IPAM
	EndpointManager endpointmanager.EndpointManager
}

type ipamAPIHandlerOut struct {
	cell.Out

	IpamDeleteIpamIPHandler ipamrestapi.DeleteIpamIPHandler
	IpamPostIpamHandler     ipamrestapi.PostIpamHandler
	IpamPostIpamIPHandler   ipamrestapi.PostIpamIPHandler
}

func newIPAMAPIHandler(params ipamAPIHandlerParams) ipamAPIHandlerOut {
	if option.Config.DatapathMode == datapathOption.DatapathModeLBOnly {
		return ipamAPIHandlerOut{}
	}

	return ipamAPIHandlerOut{
		IpamDeleteIpamIPHandler: &ipamapi.IpamDeleteIpamIPHandler{
			IPAM:            params.IPAM,
			EndpointManager: params.EndpointManager,
		},
		IpamPostIpamHandler: &ipamapi.IpamPostIpamHandler{
			IPAM: params.IPAM,
		},
		IpamPostIpamIPHandler: &ipamapi.IpamPostIpamIPHandler{
			IPAM: params.IPAM,
		},
	}
}
