// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	ciliumv2alpha1client "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	networkdriverConfig "github.com/cilium/cilium/pkg/networkdriver/config"
)

type allocatorParams struct {
	cell.In

	Logger                *slog.Logger
	Lifecycle             cell.Lifecycle
	JobGroup              job.Group
	Clientset             client.Clientset
	CiliumResourceIPPools resource.Resource[*ciliumv2alpha1.CiliumResourceIPPool]
	CiliumNodes           resource.Resource[*ciliumv2.CiliumNode]
	NetworkDriverConfig   networkdriverConfig.Config
	Config                Config
}

var resourceMultiPoolAccessor = ipam.PoolSpecAccessors{
	FromResource: func(node *ciliumv2.CiliumNode) ipamTypes.IPAMPoolSpec {
		return node.Spec.IPAM.ResourcePools
	},
	ToResource: func(node *ciliumv2.CiliumNode, spec ipamTypes.IPAMPoolSpec) bool {
		if node.Spec.IPAM.ResourcePools.DeepEqual(&spec) {
			return false
		}
		node.Spec.IPAM.ResourcePools = spec
		return true
	},
}

func registerAllocator(p allocatorParams) {
	if !p.Clientset.IsEnabled() || !p.NetworkDriverConfig.Enabled {
		return
	}

	allocator := multipool.NewPoolAllocator(p.Logger, p.NetworkDriverConfig.IPv4Enabled, p.NetworkDriverConfig.IPv6Enabled)
	nodeHandler := multipool.NewNodeHandler(
		"network-driver-ipam-sync",
		p.Logger,
		allocator,
		p.Clientset.CiliumV2().CiliumNodes(),
		resourceMultiPoolAccessor,
	)

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if err := autoCreatePools(
				ctx,
				p.Clientset.CiliumV2alpha1().CiliumResourceIPPools(),
				p.Config.AutoCreatePools,
				p.Logger,
			); err != nil {
				return err
			}

			poolSynced := make(chan struct{})
			nodeSynced := make(chan struct{})

			p.JobGroup.Add(
				job.OneShot("network-driver-ipam-pool-handler", func(ctx context.Context, _ cell.Health) error {
					p.Logger.InfoContext(ctx, "Starting CiliumResourceIPPool allocator watcher")

					for ev := range p.CiliumResourceIPPools.Events(ctx) {
						var err error

						switch ev.Kind {
						case resource.Sync:
							p.Logger.InfoContext(ctx, "All CiliumResourceIPPool resources synchronized")
							close(poolSynced)
						case resource.Upsert:
							err = upsertPool(allocator, ev.Object)
						case resource.Delete:
							err = multipool.DeletePool(allocator, ev.Object.Name)
						}

						ev.Done(err)
						if err != nil {
							p.Logger.ErrorContext(ctx, fmt.Sprintf("failed to %s pool %q", ev.Kind, ev.Key), logfields.Error, err)
						}
					}
					return nil
				}),
				job.OneShot("network-driver-ipam-node-handler", func(ctx context.Context, _ cell.Health) error {
					for ev := range p.CiliumNodes.Events(ctx) {
						switch ev.Kind {
						case resource.Sync:
							p.Logger.InfoContext(ctx, "All CiliumNode resources synchronized")
							close(nodeSynced)
						case resource.Upsert:
							if value, ok := ev.Object.Annotations[annotation.IPAMIgnore]; !ok || !strings.EqualFold(value, "true") {
								nodeHandler.Upsert(ev.Object)
							}
						case resource.Delete:
							nodeHandler.Delete(ev.Object)
						}
						ev.Done(nil)
					}
					return nil
				}),
				job.OneShot("network-driver-ipam-initial-resync", func(ctx context.Context, _ cell.Health) error {
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
				}),
			)

			return nil
		},
		OnStop: func(cell.HookContext) error {
			nodeHandler.Stop()
			return nil
		},
	})
}

func upsertPool(allocator *multipool.PoolAllocator, pool *ciliumv2alpha1.CiliumResourceIPPool) error {
	return multipool.UpsertPool(
		allocator,
		pool.Name,
		pool.Spec.IPv4,
		pool.Spec.IPv6,
		pool.Spec.AllowFirstIP,
		pool.Spec.AllowLastIP,
	)
}

func autoCreatePools(
	ctx context.Context,
	poolClient ciliumv2alpha1client.CiliumResourceIPPoolInterface,
	poolMap map[string]string,
	logger *slog.Logger,
) error {
	pools := make([]ciliumv2alpha1.CiliumResourceIPPool, 0, len(poolMap))
	for poolName, poolSpecString := range poolMap {
		parsed, err := multipool.ParsePoolSpec(poolSpecString)
		if err != nil {
			logger.ErrorContext(ctx,
				fmt.Sprintf("Failed to parse IP pool spec in %q flag", autoCreateCiliumResourceIPPoolsFlag),
				logfields.PoolName, poolName,
				logfields.PoolSpec, poolSpecString,
				logfields.Error, err,
			)
			return err
		}

		pool := ciliumv2alpha1.CiliumResourceIPPool{
			ObjectMeta: metav1.ObjectMeta{Name: poolName},
			Spec: ciliumv2alpha1.ResourceIPPoolSpec{
				AllowFirstIP: parsed.AllowFirstIP,
				AllowLastIP:  parsed.AllowLastIP,
			},
		}
		pool.Spec.IPv4 = parsed.IPv4
		pool.Spec.IPv6 = parsed.IPv6
		pools = append(pools, pool)
	}

	for i := range pools {
		pool := &pools[i]
		_, err := poolClient.Create(ctx, pool, metav1.CreateOptions{})
		switch {
		case err == nil:
			logger.InfoContext(ctx, "Created CiliumResourceIPPool resource", logfields.PoolName, pool.Name)
		case k8sErrors.IsAlreadyExists(err):
			logger.InfoContext(ctx, "Found existing CiliumResourceIPPool resource. Skipping creation", logfields.PoolName, pool.Name)
		default:
			logger.ErrorContext(ctx,
				"Failed to create CiliumResourceIPPool resource",
				logfields.PoolName, pool.Name,
				logfields.Object, pool,
				logfields.Error, err,
			)
		}
	}

	return nil
}

func ciliumResourceIPPool(
	lifecycle cell.Lifecycle,
	clientset client.Clientset,
	metricsProvider workqueue.MetricsProvider,
	config networkdriverConfig.Config,
) (resource.Resource[*ciliumv2alpha1.CiliumResourceIPPool], error) {
	if !clientset.IsEnabled() || !config.Enabled {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(utils.ListerWatcherFromTyped(clientset.CiliumV2alpha1().CiliumResourceIPPools()))
	return resource.New[*ciliumv2alpha1.CiliumResourceIPPool](
		lifecycle,
		lw,
		metricsProvider,
		resource.WithMetric("CiliumResourceIPPool"),
	), nil
}
