// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Group(
	cell.ProvidePrivate(newMultiPoolManager),
)

func newMultiPoolManager(
	Logger *slog.Logger,
	DaemonCfg *option.DaemonConfig,
	LocalNode k8s.LocalCiliumNodeResource,
	ClientSet k8sClient.Clientset,
	JobGroup job.Group,
	driverConf config.Config,
) (*ipam.MultiPoolManager, error) {
	if !ClientSet.IsEnabled() || !driverConf.Enabled {
		return nil, nil
	}

	// TODO: we need to implement the pre-allocation logic
	preallocMap, err := ipam.ParseMultiPoolPreAllocMap(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate empty pre-allocation map: %w", err)
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
		CIDRRelease:          ipam.CIDRReleaseConfig{Enabled: true},
	}), nil
}
