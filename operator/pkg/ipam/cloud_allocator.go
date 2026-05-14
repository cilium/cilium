// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws || ipam_provider_azure || ipam_provider_alibabacloud

package ipam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/operator/pkg/ipam/metrics"
	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

// CloudAllocator is the lifecycle contract implemented by every cloud-provider
// IPAM allocator (AWS, Azure, AlibabaCloud). It exists so the per-cloud cell
// files can share a single bootstrap path (startCloudAllocator) instead of
// duplicating identical lifecycle plumbing.
type CloudAllocator interface {
	Init(ctx context.Context, logger *slog.Logger) error
	Start(ctx context.Context, getterUpdater allocator.CiliumNodeGetterUpdater, iMetrics nodemanager.MetricsAPI) (allocator.NodeEventHandler, error)
}

// cloudAllocatorBootstrap groups the dependencies that every cloud allocator
// cell hands to startCloudAllocator.
type cloudAllocatorBootstrap struct {
	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	IPAMMetrics        *ipamMetrics.Metrics
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory
}

// startCloudAllocator registers the OnStart lifecycle hook that drives the
// Init -> Start -> NodeWatcher wiring shared by every cloud-provider allocator.
// It is a no-op unless the configured IPAM mode matches.
func startCloudAllocator(b cloudAllocatorBootstrap, name, mode string, alloc CloudAllocator) {
	if b.DaemonCfg.IPAM != mode {
		return
	}
	b.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if err := alloc.Init(ctx, b.Logger); err != nil {
				return fmt.Errorf("unable to init %s allocator: %w", name, err)
			}
			b.JobGroup.Add(b.NodeWatcherFactory(
				func(ctx context.Context) (allocator.NodeEventHandler, error) {
					nm, err := alloc.Start(ctx, &ciliumNodeUpdateImplementation{b.Clientset}, b.IPAMMetrics)
					if err != nil {
						return nil, fmt.Errorf("unable to start %s allocator: %w", name, err)
					}
					return nm, nil
				},
			))
			return nil
		},
	})
}
