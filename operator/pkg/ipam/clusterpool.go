// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/clusterpool"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

// ClusterPoolConfig contains the configuration for the ClusterPool IPAM allocator.
type ClusterPoolConfig struct {
	ClusterPoolIPv4CIDR     []string
	ClusterPoolIPv4MaskSize int
	ClusterPoolIPv6CIDR     []string
	ClusterPoolIPv6MaskSize int
}

var defaultClusterPoolConfig = ClusterPoolConfig{
	ClusterPoolIPv4CIDR:     []string{},
	ClusterPoolIPv4MaskSize: 24,
	ClusterPoolIPv6CIDR:     []string{},
	ClusterPoolIPv6MaskSize: 112,
}

// Flags registers the flags for ClusterPoolConfig.
func (cfg ClusterPoolConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("cluster-pool-ipv4-cidr", defaultClusterPoolConfig.ClusterPoolIPv4CIDR,
		fmt.Sprintf("IPv4 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv4Name, "true"))
	flags.Int("cluster-pool-ipv4-mask-size", defaultClusterPoolConfig.ClusterPoolIPv4MaskSize,
		fmt.Sprintf("Mask size for each IPv4 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv4Name, "true"))
	flags.StringSlice("cluster-pool-ipv6-cidr", defaultClusterPoolConfig.ClusterPoolIPv6CIDR,
		fmt.Sprintf("IPv6 CIDR Range for Pods in cluster. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv6Name, "true"))
	flags.Int("cluster-pool-ipv6-mask-size", defaultClusterPoolConfig.ClusterPoolIPv6MaskSize,
		fmt.Sprintf("Mask size for each IPv6 podCIDR per node. Requires '%s=%s' and '%s=%s'",
			option.IPAM, ipamOption.IPAMClusterPool,
			option.EnableIPv6Name, "true"))
}

func init() {
	allocators = append(allocators, cell.Module(
		"clusterpool-ipam-allocator",
		"Cluster Pool IP Allocator",

		cell.Config(defaultClusterPoolConfig),
		cell.Invoke(startClusterPoolAllocator),
	))
}

type clusterPoolParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	IPAMMetrics        *ipamMetrics.Metrics
	DaemonCfg          *option.DaemonConfig
	ClusterPoolCfg     ClusterPoolConfig
	NodeWatcherFactory nodeWatcherJobFactory
}

func startClusterPoolAllocator(p clusterPoolParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMClusterPool {
		return
	}

	allocator := &clusterpool.AllocatorOperator{
		ClusterPoolIPv4CIDR:     p.ClusterPoolCfg.ClusterPoolIPv4CIDR,
		ClusterPoolIPv4MaskSize: p.ClusterPoolCfg.ClusterPoolIPv4MaskSize,
		ClusterPoolIPv6CIDR:     p.ClusterPoolCfg.ClusterPoolIPv6CIDR,
		ClusterPoolIPv6MaskSize: p.ClusterPoolCfg.ClusterPoolIPv6MaskSize,
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger); err != nil {
					return fmt.Errorf("unable to init ClusterPool allocator: %w", err)
				}

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.IPAMMetrics.K8sSyncTrigger())
				if err != nil {
					return fmt.Errorf("unable to start ClusterPool allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
