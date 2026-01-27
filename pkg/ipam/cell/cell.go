// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamcell

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamapi "github.com/cilium/cilium/pkg/ipam/api"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	"github.com/cilium/cilium/pkg/ipmasq"
	k8sResources "github.com/cilium/cilium/pkg/k8s"
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

	cell.Config(defaultIPAMConfig),

	cell.Provide(newIPAddressManager),
	cell.Provide(newIPAMAPIHandler),
	cell.Provide(k8sResources.CiliumPodIPPoolResource),
	podippool.TableCell,

	// IPAM metadata manager, determines which IPAM pool a pod should allocate from
	ipamMetadata.Cell,
)

type ipamConfig struct {
	OnlyMasqueradeDefaultPool bool
}

var defaultIPAMConfig = ipamConfig{
	OnlyMasqueradeDefaultPool: false,
}

func (def ipamConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("only-masquerade-default-pool",
		defaultIPAMConfig.OnlyMasqueradeDefaultPool,
		"When using multi-pool IPAM, only masquerade flows from the default IP pool. "+
			"This will preserve source IPs for pods from non-default IP pools. "+
			"Useful when combining multi-pool IPAM with BGP control plane. "+
			"This option must be combined with enable-bpf-masquerade.")
}

type ipamParams struct {
	cell.In

	Logger *slog.Logger

	AgentConfig *option.DaemonConfig

	NodeAddressing      datapathTypes.NodeAddressing
	LocalNodeStore      *node.LocalNodeStore
	K8sEventReporter    *watchers.K8sEventReporter
	NodeResource        k8s.LocalCiliumNodeResource
	MTU                 mtu.MTU
	Clientset           k8sClient.Clientset
	IPAMMetadataManager ipamMetadata.Manager
	NodeDiscovery       *nodediscovery.NodeDiscovery
	Sysctl              sysctl.Sysctl
	EndpointManager     endpointmanager.EndpointManager
	IPMasqAgent         *ipmasq.IPMasqAgent

	JobGroup   job.Group
	DB         *statedb.DB
	PodIPPools statedb.Table[podippool.LocalPodIPPool]
}

func newIPAddressManager(params ipamParams, c ipamConfig) (*ipam.IPAM, error) {
	if c.OnlyMasqueradeDefaultPool && !params.AgentConfig.EnableBPFMasquerade {
		return nil, fmt.Errorf("--only-masquerade-default-pool requires --enable-bpf-masquerade to be enabled")
	}
	ipam := ipam.NewIPAM(ipam.NewIPAMParams{
		Logger:                    params.Logger,
		NodeAddressing:            params.NodeAddressing,
		AgentConfig:               params.AgentConfig,
		NodeDiscovery:             params.NodeDiscovery,
		LocalNodeStore:            params.LocalNodeStore,
		K8sEventReg:               params.K8sEventReporter,
		NodeResource:              params.NodeResource,
		MTUConfig:                 params.MTU,
		Clientset:                 params.Clientset,
		Metadata:                  params.IPAMMetadataManager,
		Sysctl:                    params.Sysctl,
		IPMasqAgent:               params.IPMasqAgent,
		DB:                        params.DB,
		JobGroup:                  params.JobGroup,
		PodIPPools:                params.PodIPPools,
		OnlyMasqueradeDefaultPool: c.OnlyMasqueradeDefaultPool,
	})

	debug.RegisterStatusObject("ipam", ipam)

	params.EndpointManager.Subscribe(ipam)

	return ipam, nil
}

type ipamAPIHandlerParams struct {
	cell.In

	Logger          *slog.Logger
	DaemonConfig    *option.DaemonConfig
	IPAM            *ipam.IPAM
	LocalNodeStore  *node.LocalNodeStore
	EndpointManager endpointmanager.EndpointManager
}

type ipamAPIHandlerOut struct {
	cell.Out

	IpamDeleteIpamIPHandler ipamrestapi.DeleteIpamIPHandler
	IpamPostIpamHandler     ipamrestapi.PostIpamHandler
	IpamPostIpamIPHandler   ipamrestapi.PostIpamIPHandler
}

func newIPAMAPIHandler(params ipamAPIHandlerParams) ipamAPIHandlerOut {
	return ipamAPIHandlerOut{
		IpamDeleteIpamIPHandler: &ipamapi.IpamDeleteIpamIPHandler{
			IPAM:            params.IPAM,
			EndpointManager: params.EndpointManager,
		},
		IpamPostIpamHandler: &ipamapi.IpamPostIpamHandler{
			DaemonConfig:   params.DaemonConfig,
			Logger:         params.Logger,
			IPAM:           params.IPAM,
			LocalNodeStore: params.LocalNodeStore,
		},
		IpamPostIpamIPHandler: &ipamapi.IpamPostIpamIPHandler{
			IPAM: params.IPAM,
		},
	}
}
