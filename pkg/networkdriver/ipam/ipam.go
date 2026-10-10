// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/option"
)

// resourceIPAMMultiPoolPreAllocation defines the pre-allocation value for each resource
// IPAM pool.
const resourceIPAMMultiPoolPreAllocation = "resource-ipam-multi-pool-pre-allocation"

var Cell = cell.Group(
	cell.Config(defaultIPAMConfig),

	cell.ProvidePrivate(newMultiPoolManager),
)

type IPAMConfig struct {
	ResourceIPAMMultiPoolPreAllocation map[string]string
}

var defaultIPAMConfig = IPAMConfig{}

func (cfg IPAMConfig) Flags(flags *pflag.FlagSet) {
	flags.StringToString(resourceIPAMMultiPoolPreAllocation, cfg.ResourceIPAMMultiPoolPreAllocation,
		fmt.Sprintf("Defines the minimum number of IPs for DRA resources a node should pre-allocate from each pool (default %s=8)", defaults.IPAMDefaultIPPool))
}

func newMultiPoolManager(
	Logger *slog.Logger,
	DaemonCfg *option.DaemonConfig,
	LocalNode k8s.LocalCiliumNodeResource,
	ClientSet k8sClient.Clientset,
	JobGroup job.Group,
	Cfg IPAMConfig,
	driverConf config.Config,
) (*ipam.MultiPoolManager, error) {
	if !ClientSet.IsEnabled() || !driverConf.Enabled {
		return nil, nil
	}

	preallocMap, err := ipam.ParseMultiPoolPreAllocMap(Cfg.ResourceIPAMMultiPoolPreAllocation)
	if err != nil {
		return nil, fmt.Errorf("Invalid value for flag %s: %w", resourceIPAMMultiPoolPreAllocation, err)
	}

	return ipam.NewMultiPoolManager(ipam.MultiPoolManagerParams{
		Logger:               Logger,
		IPv4Enabled:          driverConf.IPv4Enabled,
		IPv6Enabled:          driverConf.IPv6Enabled,
		CiliumNodeUpdateRate: DaemonCfg.IPAMCiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 LocalNode,
		CNClient:             ClientSet.CiliumV2().CiliumNodes(),
		JobGroup:             JobGroup,
		PoolSpecAccessors:    ResourceMultiPoolAccessor,
	}), nil
}
