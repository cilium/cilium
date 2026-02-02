// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// AddrAddRetryInterval is the initial interval for the exponential backoff between
	// subsequent "address add request" retries to the IPAM manager.
	// This is needed when requesting an IP address from a not yet ready pool, in order
	// to let the operator handle the new request and reserve a CIDR for the node.
	AddrAddRetryInterval = time.Second

	// AddrAddMaxRetries is the maximum number of "address add request" retries before
	// failing the operation.
	AddrAddMaxRetries = 25

	// ResourceIPAMMultiPoolPreAllocation defines the pre-allocation value for each resource
	// IPAM pool.
	ResourceIPAMMultiPoolPreAllocation = "resource-ipam-multi-pool-pre-allocation"
)

type ipamAction string

const (
	addrAdd ipamAction = "add"
	addrDel ipamAction = "del"
)

var resourceIPAM = cell.Group(
	cell.Config(defaultIPAMConfig),

	cell.ProvidePrivate(newMultiPoolManager),
)

type IPAMConfig struct {
	ResourceIPAMMultiPoolPreAllocation map[string]string
}

var defaultIPAMConfig = IPAMConfig{}

func (cfg IPAMConfig) Flags(flags *pflag.FlagSet) {
	flags.StringToString(ResourceIPAMMultiPoolPreAllocation, cfg.ResourceIPAMMultiPoolPreAllocation,
		fmt.Sprintf("Defines the minimum number of IPs for DRA resources a node should pre-allocate from each pool (default %s=8)", defaults.IPAMDefaultIPPool))
}

func newMultiPoolManager(
	Logger *slog.Logger,
	DaemonCfg *option.DaemonConfig,
	LocalNode k8s.LocalCiliumNodeResource,
	ClientSet k8sClient.Clientset,
	JobGroup job.Group,
	Cfg IPAMConfig,
) *ipam.MultiPoolManager {
	if !ClientSet.IsEnabled() || !DaemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	preallocMap, err := ipam.ParseMultiPoolPreAllocMap(Cfg.ResourceIPAMMultiPoolPreAllocation)
	if err != nil {
		Logger.Error("Invalid flag value",
			logfields.Flag, ResourceIPAMMultiPoolPreAllocation,
			logfields.Error, err)
		return nil
	}

	return ipam.NewMultiPoolManager(ipam.MultiPoolManagerParams{
		Logger:               Logger,
		IPv4Enabled:          DaemonCfg.IPv4Enabled(),
		IPv6Enabled:          DaemonCfg.IPv6Enabled(),
		CiliumNodeUpdateRate: DaemonCfg.IPAMCiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 LocalNode,
		CNClient:             ClientSet.CiliumV2().CiliumNodes(),
		JobGroup:             JobGroup,
		PoolsFromResource: func(cn *v2.CiliumNode) *ipamtypes.IPAMPoolSpec {
			return &cn.Spec.IPAM.ResourcePools
		},
	})
}
