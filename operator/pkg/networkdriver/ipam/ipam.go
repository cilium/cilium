// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	cilium_v2_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type AllocatorParams struct {
	cell.In

	Logger                *slog.Logger
	Lifecycle             cell.Lifecycle
	JobGroup              job.Group
	Clientset             k8sClient.Clientset
	CiliumResourceIPPools resource.Resource[*cilium_v2alpha1_api.CiliumResourceIPPool]
	CiliumNodes           resource.Resource[*cilium_v2_api.CiliumNode]

	DaemonCfg *option.DaemonConfig
	Cfg       Config
}

var MultiPoolAccessor = ipam.PoolSpecAccessors{
	FromResource: func(cn *cilium_v2_api.CiliumNode) ipamTypes.IPAMPoolSpec {
		return cn.Spec.IPAM.ResourcePools
	},
	ToResource: func(cn *cilium_v2_api.CiliumNode, spec ipamTypes.IPAMPoolSpec) bool {
		if !cn.Spec.IPAM.ResourcePools.DeepEqual(&spec) {
			cn.Spec.IPAM.ResourcePools = spec
			return true
		}
		return false
	},
}

func registerAllocator(p AllocatorParams) {
	if !p.Clientset.IsEnabled() || !p.DaemonCfg.EnableCiliumNetworkDriver {
		return
	}

	logger := p.Logger.With([]any{logfields.LogSubsys, "network-driver-ipam-allocator"}...)

	allocator := multipool.NewPoolAllocator(logger, p.DaemonCfg.EnableIPv4, p.DaemonCfg.EnableIPv6)

	nodeHandler := multipool.NewNodeHandler(
		"network-driver-ipam-sync",
		logger, allocator, p.Clientset.CiliumV2().CiliumNodes(), MultiPoolAccessor,
	)

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := autoCreatePools(
					ctx,
					p.Clientset.CiliumV2alpha1().CiliumResourceIPPools(),
					p.Cfg.AutoCreateCiliumResourceIPPools,
					logger,
				); err != nil {
					return err
				}

				poolSynced, nodeSynced := make(chan struct{}), make(chan struct{})

				p.JobGroup.Add(
					job.OneShot(
						"network-driver-ip-pool-handler",
						func(ctx context.Context, health cell.Health) error {
							logger.InfoContext(ctx, "Starting CiliumResourceIPPool allocator watcher")

							for ev := range p.CiliumResourceIPPools.Events(ctx) {
								var err error
								var action string

								switch ev.Kind {
								case resource.Sync:
									logger.InfoContext(ctx, "All CiliumResourceIPPool resources synchronized")
									close(poolSynced)
								case resource.Upsert:
									err = multipool.UpsertPool(allocator, ev.Object.Name, ev.Object.Spec.IPv4, ev.Object.Spec.IPv6, false, false)
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

							return nil
						},
					),
					job.OneShot(
						"network-driver-node-handler",
						func(ctx context.Context, health cell.Health) error {
							for ev := range p.CiliumNodes.Events(ctx) {
								switch ev.Kind {
								case resource.Sync:
									logger.InfoContext(ctx, "All CiliumNode resources synchronized")
									close(nodeSynced)
								case resource.Upsert:
									nodeHandler.Upsert(ev.Object)
								case resource.Delete:
									nodeHandler.Delete(ev.Object)
								}
								ev.Done(nil)
							}
							return nil
						},
					),
					job.OneShot(
						"network-driver-initial-resync",
						func(ctx context.Context, health cell.Health) error {
							// poolSynced and nodeSynced are closed by the
							// pool/node handler jobs above on resource.Sync.
							// On shutdown those event loops exit via context
							// cancellation and may never close their channel,
							// so we must also observe ctx.Done() here to avoid
							// blocking Hive.Stop indefinitely.
							select {
							case <-poolSynced:
							case <-ctx.Done():
								return nil
							}
							select {
							case <-nodeSynced:
							case <-ctx.Done():
								return nil
							}
							nodeHandler.Resync(ctx, time.Time{})
							return nil
						},
					),
				)

				return nil
			},
			OnStop: func(ctx cell.HookContext) error {
				nodeHandler.Stop()
				return nil
			},
		},
	)
}

func autoCreatePools(ctx context.Context, client cilium_v2alpha1.CiliumResourceIPPoolInterface, poolMap map[string]string, logger *slog.Logger) error {
	// we do a first pass to ensure all pools are valid,
	// then proceed with the creation if the objects if
	// no malformed pools are seen
	validated := make([]cilium_v2alpha1_api.CiliumResourceIPPool, 0, len(poolMap))

	for poolName, poolSpecStr := range poolMap {
		poolSpec, err := multipool.ParsePoolSpec(poolSpecStr)
		if err != nil {
			logger.ErrorContext(ctx,
				fmt.Sprintf("Failed to parse IP pool spec in %q flag", AutoCreateCiliumResourceIPPools),
				logfields.PoolName, poolName,
				logfields.PoolSpec, poolSpecStr,
				logfields.Error, err,
			)

			return err
		}

		validated = append(validated, cilium_v2alpha1_api.CiliumResourceIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: cilium_v2alpha1_api.ResourceIPPoolSpec{
				IPv4: poolSpec.IPv4,
				IPv6: poolSpec.IPv6,
			},
		})
	}

	for _, pool := range validated {
		_, err := client.Create(ctx, &pool, metav1.CreateOptions{})
		if err != nil {
			if k8sErrors.IsAlreadyExists(err) {
				// Nothing to do, we will not try to update an existing resource
				logger.InfoContext(ctx,
					"Found existing CiliumResourceIPPool resource. Skipping creation",
					logfields.PoolName, pool.GetObjectMeta().GetName(),
				)
			} else {
				logger.ErrorContext(ctx,
					"Failed to create CiliumResourceIPPool resource",
					logfields.PoolName, pool.GetObjectMeta().GetName(),
					logfields.Object, pool,
					logfields.Error, err,
				)
			}

			continue
		}

		logger.InfoContext(
			ctx, "Created CiliumResourceIPPool resource",
			logfields.PoolName, pool.GetObjectMeta().GetName(),
		)
	}

	return nil
}

func ciliumResourceIPPool(
	lc cell.Lifecycle,
	cs client.Clientset,
	mp workqueue.MetricsProvider,
) (resource.Resource[*cilium_v2alpha1_api.CiliumResourceIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumResourceIPPools()))
	return resource.New[*cilium_v2alpha1_api.CiliumResourceIPPool](lc, lw, mp, resource.WithMetric("CiliumResourceIPPool")), nil
}
