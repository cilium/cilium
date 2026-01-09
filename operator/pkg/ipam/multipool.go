// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/ipam/allocator/multipool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var multiPoolCell = cell.Module(
	"multipool-ipam-allocator",
	"Multi Pool IP Allocator",

	cell.Invoke(startMultiPoolAllocator),
)

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

	allocator := &multipool.Allocator{}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.MetricsRegistry); err != nil {
					return fmt.Errorf("unable to init AWS allocator: %w", err)
				}

				// The following operation will block until all pools are restored, thus it
				// is safe to continue starting node allocation right after return.
				watchers.StartIPPoolAllocator(
					ctx, p.Clientset, allocator, p.CiliumPodIPPools,
					p.Logger.With(logfields.LogSubsys, "ip-pool-watcher"),
				)

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.MetricsRegistry)
				if err != nil {
					return fmt.Errorf("unable to start AWS allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
