// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"lbipam",
	"LB-IPAM",
	// Provide LBIPAM so instances of it can be used while testing
	cell.Provide(
		newLBIPAMCell,
		func(c lbipamConfig) Config { return c },
	),
	// Invoke an empty function which takes an LBIPAM to force its construction.
	cell.Invoke(func(*LBIPAM) {}),
	// Provide LB-IPAM related metrics
	metrics.Metric(newMetrics),
	// Register configuration flags
	cell.Config(lbipamConfig{
		EnableLBIPAM: true,
	}),
	cell.Config(SharedConfig{
		DefaultLBServiceIPAM: DefaultLBClassLBIPAM,
	}),
)

type lbipamConfig struct {
	EnableLBIPAM bool
}

func (lc lbipamConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&lc.EnableLBIPAM, "enable-lb-ipam", lc.EnableLBIPAM, "Enable LB IPAM")
}

func (lc lbipamConfig) IsEnabled() bool {
	return lc.EnableLBIPAM
}

type Config interface {
	IsEnabled() bool
}

type lbipamCellParams struct {
	cell.In

	Logger *slog.Logger

	LC       cell.Lifecycle
	JobGroup job.Group
	Health   cell.Health

	Clientset    k8sClient.Clientset
	PoolResource resource.Resource[*cilium_api_v2.CiliumLoadBalancerIPPool]
	SvcResource  resource.Resource[*slim_core_v1.Service]

	DaemonConfig *option.DaemonConfig

	Metrics *ipamMetrics

	Config       lbipamConfig
	SharedConfig SharedConfig

	TestCounters *testCounters `optional:"true"`
}

func newLBIPAMCell(params lbipamCellParams) *LBIPAM {
	if !params.Clientset.IsEnabled() || !params.Config.EnableLBIPAM {
		return nil
	}

	var lbClasses []string
	if params.DaemonConfig.EnableBGPControlPlane {
		lbClasses = append(lbClasses, cilium_api_v2alpha1.BGPLoadBalancerClass)
	}

	if params.DaemonConfig.EnableL2Announcements {
		lbClasses = append(lbClasses, cilium_api_v2alpha1.L2AnnounceLoadBalancerClass)
	}

	lbIPAM := newLBIPAM(lbIPAMParams{
		logger:       params.Logger,
		poolResource: params.PoolResource,
		svcResource:  params.SvcResource,
		metrics:      params.Metrics,
		lbClasses:    lbClasses,
		ipv4Enabled:  option.Config.IPv4Enabled(),
		ipv6Enabled:  option.Config.IPv6Enabled(),
		lbProtoDiff:  option.Config.LBProtoDiffEnabled(),
		poolClient:   params.Clientset.CiliumV2().CiliumLoadBalancerIPPools(),
		svcClient:    params.Clientset.Slim().CoreV1(),
		jobGroup:     params.JobGroup,
		config:       params.Config,
		defaultIPAM:  params.SharedConfig.DefaultLBServiceIPAM == DefaultLBClassLBIPAM,
		testCounters: params.TestCounters,
	})

	lbIPAM.jobGroup.Add(
		job.OneShot("lbipam-main", func(ctx context.Context, health cell.Health) error {
			lbIPAM.Run(ctx, health)
			return nil
		}),
	)

	return lbIPAM
}

const (
	DefaultLBClassLBIPAM   = "lbipam"
	DefaultLBClassNodeIPAM = "nodeipam"
)

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator configurations.
type SharedConfig struct {
	// DefaultLBServiceIPAM indicate the default LoadBalancer Service IPAM
	DefaultLBServiceIPAM string
}

func (sc SharedConfig) Flags(flags *pflag.FlagSet) {
	flags.StringVar(&sc.DefaultLBServiceIPAM, "default-lb-service-ipam", sc.DefaultLBServiceIPAM,
		"Indicates the default LoadBalancer Service IPAM when no LoadBalancer class is set."+
			"Applicable values: lbipam, nodeipam, none")
}
