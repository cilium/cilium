// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	allocators = append(allocators, cell.Module(
		"clusterpool-ipam-allocator",
		"Cluster Pool IP Allocator",

		cell.Invoke(startClusterPoolAllocator),
	))
}

type clusterPoolParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	MetricsRegistry    *metrics.Registry
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory
}

func startClusterPoolAllocator(p clusterPoolParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMClusterPool {
		return
	}

	allocator := &clusterpool.AllocatorOperator{}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.MetricsRegistry); err != nil {
					return fmt.Errorf("unable to init AWS allocator: %w", err)
				}

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
