// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/operator/pkg/multipool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	allocators = append(allocators, cell.Module(
		"multipool-ipam-allocator",
		"Multi Pool IP Allocator",

		cell.Invoke(startMultiPoolAllocator),
	))
}

type multiPoolParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	MetricsRegistry    *metrics.Registry
	DaemonCfg          *option.DaemonConfig
	CiliumPodIPPools   resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool]
	NodeWatcherFactory nodeWatcherJobFactory
}

func startMultiPoolAllocator(p multiPoolParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMMultiPool {
		return
	}

	logger := p.Logger.With([]any{logfields.LogSubsys, "ipam-allocator-multi-pool"}...)

	allocator := multipool.NewPoolAllocator(logger)

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				// The following operation will block until all pools are restored, thus it
				// is safe to continue starting node allocation right after return.
				multipool.StartIPPoolAllocator(
					ctx, p.Clientset, allocator, p.CiliumPodIPPools,
					p.Logger.With(logfields.LogSubsys, "ip-pool-watcher"),
				)

				nm := multipool.NewNodeHandler(logger, allocator, &ciliumNodeUpdateImplementation{p.Clientset})

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
