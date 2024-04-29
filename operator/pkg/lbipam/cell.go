// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

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
	cell.Provide(newLBIPAMCell),
	// Invoke an empty function which takes an LBIPAM to force its construction.
	cell.Invoke(func(*LBIPAM) {}),
	// Provide LB-IPAM related metrics
	metrics.Metric(newMetrics),
)

type lbipamCellParams struct {
	cell.In

	Logger logrus.FieldLogger

	LC       cell.Lifecycle
	JobGroup job.Group
	Health   cell.Health

	Clientset    k8sClient.Clientset
	PoolResource resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	SvcResource  resource.Resource[*slim_core_v1.Service]

	DaemonConfig *option.DaemonConfig

	Metrics *ipamMetrics
}

func newLBIPAMCell(params lbipamCellParams) *LBIPAM {
	if !params.Clientset.IsEnabled() {
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
		poolClient:   params.Clientset.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
		svcClient:    params.Clientset.Slim().CoreV1(),
		jobGroup:     params.JobGroup,
	})

	lbIPAM.jobGroup.Add(
		job.OneShot("lbipam main", func(ctx context.Context, health cell.Health) error {
			lbIPAM.Run(ctx, health)
			return nil
		}),
	)

	return lbIPAM
}
