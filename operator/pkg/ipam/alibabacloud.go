// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_alibabacloud

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam/allocator/alibabacloud"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	allocators = append(allocators, cell.Module(
		"alibabacloud-ipam-allocator",
		"Alibaba Cloud IP Allocator",

		cell.Config(defaultAlibabaCloudConfig),
		cell.Invoke(startAlibabaAllocator),
	))
}

type AlibabaCloudConfig struct {
	AlibabaCloudVPCID            string
	AlibabaCloudReleaseExcessIPs bool
}

var defaultAlibabaCloudConfig = AlibabaCloudConfig{
	AlibabaCloudVPCID:            "",
	AlibabaCloudReleaseExcessIPs: false,
}

func (cfg AlibabaCloudConfig) Flags(flags *pflag.FlagSet) {
	flags.String(operatorOption.AlibabaCloudVPCID, defaultAlibabaCloudConfig.AlibabaCloudVPCID, "Specific VPC ID for AlibabaCloud ENI. If not set use same VPC as operator")
	flags.Bool(operatorOption.AlibabaCloudReleaseExcessIPs, defaultAlibabaCloudConfig.AlibabaCloudReleaseExcessIPs, "Enable releasing excess free IP addresses from Alibaba Cloud ENI.")
}

type alibabaParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	MetricsRegistry    *metrics.Registry
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory

	Cfg        Config
	AlibabaCfg AlibabaCloudConfig
}

func startAlibabaAllocator(p alibabaParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMAlibabaCloud {
		return
	}

	allocator := &alibabacloud.AllocatorAlibabaCloud{
		AlibabaCloudVPCID:            p.AlibabaCfg.AlibabaCloudVPCID,
		AlibabaCloudReleaseExcessIPs: p.AlibabaCfg.AlibabaCloudReleaseExcessIPs,
		ParallelAllocWorkers:         p.Cfg.ParallelAllocWorkers,
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.MetricsRegistry); err != nil {
					return fmt.Errorf("unable to init AlibabaCloud allocator: %w", err)
				}

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.MetricsRegistry)
				if err != nil {
					return fmt.Errorf("unable to start AlibabaCloud allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
