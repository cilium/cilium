// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/multipool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
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

		cell.Config(multiPoolDefaultConfig),
		cell.Invoke(startMultiPoolAllocator),
	))
}

type MultiPoolConfig struct {
	AutoCreatePools map[string]string `mapstructure:"auto-create-cilium-pod-ip-pools"`
}

var multiPoolDefaultConfig = MultiPoolConfig{
	AutoCreatePools: nil,
}

func (cfg MultiPoolConfig) Flags(flags *pflag.FlagSet) {
	flags.StringToString(operatorOption.IPAMAutoCreateCiliumPodIPPools, multiPoolDefaultConfig.AutoCreatePools,
		"Automatically create CiliumPodIPPool resources on startup. "+
			"Specify pools in the form of <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size> (multiple pools can also be passed by repeating the CLI flag)")
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

	MultiPoolCfg MultiPoolConfig
}

func startMultiPoolAllocator(p multiPoolParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMMultiPool {
		return
	}

	logger := p.Logger.With([]any{logfields.LogSubsys, "ipam-allocator-multi-pool"}...)

	allocator := multipool.NewPoolAllocator(logger, p.DaemonCfg.EnableIPv4, p.DaemonCfg.EnableIPv6)

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := multiPoolAutoCreatePools(ctx, p.Clientset, p.MultiPoolCfg.AutoCreatePools, logger); err != nil {
					return err
				}

				// The following operation will block until all pools are restored, thus it
				// is safe to continue starting node allocation right after return.
				startIPPoolAllocator(
					ctx, allocator, p.CiliumPodIPPools,
					p.Logger.With(logfields.LogSubsys, "ip-pool-watcher"),
				)

				nm := multipool.NewNodeHandler(
					"ipam-multi-pool-sync",
					logger, allocator, p.Clientset.CiliumV2().CiliumNodes(),
					func(cn *v2.CiliumNode) *types.IPAMPoolSpec {
						return &cn.Spec.IPAM.Pools
					},
				)

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}

func multiPoolAutoCreatePools(ctx context.Context, clientset client.Clientset, poolMap map[string]string, logger *slog.Logger) error {
	for poolName, poolSpecStr := range poolMap {
		v4PoolSpec, v6PoolSpec, err := multipool.ParsePoolSpec(poolSpecStr)
		if err != nil {
			logger.ErrorContext(ctx,
				fmt.Sprintf("Failed to parse IP pool spec in %q flag", operatorOption.IPAMAutoCreateCiliumPodIPPools),
				logfields.PoolName, poolName,
				logfields.PoolSpec, poolSpecStr,
				logfields.Error, err)
			return err
		}

		pool := &cilium_v2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: cilium_v2alpha1.IPPoolSpec{
				IPv4: v4PoolSpec,
				IPv6: v6PoolSpec,
			},
		}

		_, err = clientset.CiliumV2alpha1().CiliumPodIPPools().Create(ctx, pool, metav1.CreateOptions{})
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				// Nothing to do, we will not try to update an existing resource
				logger.InfoContext(ctx,
					"Found existing CiliumPodIPPool resource. Skipping creation",
					logfields.PoolName, poolName)
			} else {
				logger.ErrorContext(ctx,
					"Failed to create CiliumPodIPPool resource",
					logfields.PoolName, poolName,
					logfields.Object, pool,
					logfields.Error, err)
			}
			continue
		}

		logger.InfoContext(ctx, "Created CiliumPodIPPool resource", logfields.PoolName, poolName)
	}

	return nil
}

func startIPPoolAllocator(
	ctx context.Context,
	allocator *multipool.PoolAllocator,
	ipPools resource.Resource[*cilium_v2alpha1.CiliumPodIPPool],
	logger *slog.Logger,
) {
	logger.InfoContext(ctx, "Starting CiliumPodIPPool allocator watcher")

	synced := make(chan struct{})

	go func() {
		for ev := range ipPools.Events(ctx) {
			var err error
			var action string

			switch ev.Kind {
			case resource.Sync:
				close(synced)
			case resource.Upsert:
				err = multipool.UpsertPool(allocator, ev.Object.Name, ev.Object.Spec.IPv4, ev.Object.Spec.IPv6)
				action = "upsert"
			case resource.Delete:
				err = multipool.DeletePool(allocator, ev.Object.Name)
				action = "delete"
			}
			ev.Done(err)
			if err != nil {
				logger.ErrorContext(ctx, fmt.Sprintf("failed to %s pool %q", action, ev.Key), logfields.Error, err)
			}
		}
	}()

	// Block until all pools are restored, so callers can safely start node allocation
	// right after return.
	<-synced
	logger.InfoContext(ctx, "All CiliumPodIPPool resources synchronized")
}
