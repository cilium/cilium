// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_alibabacloud

package ipam

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ipam/allocator/alibabacloud"
	ipamMetrics "github.com/cilium/cilium/operator/pkg/ipam/metrics"
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
		metrics.Metric(alibabacloud.NewMetrics),
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
	AlibabaMetrics     *alibabacloud.Metrics
	IPAMMetrics        *ipamMetrics.Metrics
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory

	Cfg        Config
	AlibabaCfg AlibabaCloudConfig
}

func startAlibabaAllocator(p alibabaParams) {
	alloc := &alibabacloud.AllocatorAlibabaCloud{
		AlibabaCloudVPCID:            p.AlibabaCfg.AlibabaCloudVPCID,
		AlibabaCloudReleaseExcessIPs: p.AlibabaCfg.AlibabaCloudReleaseExcessIPs,
		ParallelAllocWorkers:         p.Cfg.ParallelAllocWorkers,
		LimitIPAMAPIBurst:            p.Cfg.LimitIPAMAPIBurst,
		LimitIPAMAPIQPS:              p.Cfg.LimitIPAMAPIQPS,
		AlibabaMetrics:               p.AlibabaMetrics,
	}

	startCloudAllocator(cloudAllocatorBootstrap{
		Logger:             p.Logger,
		Lifecycle:          p.Lifecycle,
		JobGroup:           p.JobGroup,
		Clientset:          p.Clientset,
		IPAMMetrics:        p.IPAMMetrics,
		DaemonCfg:          p.DaemonCfg,
		NodeWatcherFactory: p.NodeWatcherFactory,
	}, "AlibabaCloud", ipamOption.IPAMAlibabaCloud, alloc)
}
