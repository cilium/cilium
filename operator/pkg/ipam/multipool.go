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
	CiliumPodIPPools   resource.Resource[*v2.CiliumPodIPPool]
	CiliumPodIPPoolsV2Alpha1 resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool]
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
				
				StartIPPoolMigrator(
					ctx, p.Clientset, p.CiliumPodIPPoolsV2Alpha1,
					p.Logger.With(logfields.LogSubsys, "ip-pool-migrator"),
				)

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

		pool := &v2.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: v2.IPPoolSpec{
				IPv4: v4PoolSpec,
				IPv6: v6PoolSpec,
			},
		}

		_, err = clientset.CiliumV2().CiliumPodIPPools().Create(ctx, pool, metav1.CreateOptions{})
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
	ipPools resource.Resource[*v2.CiliumPodIPPool],
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

// convertV2Alpha1ToV2 converts a v2alpha1 CiliumPodIPPool to v2 format.
func convertV2Alpha1ToV2(pool *cilium_v2alpha1.CiliumPodIPPool) *v2.CiliumPodIPPool {
	v2Pool := &v2.CiliumPodIPPool{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumPodIPPool",
		},
	}

	v2Pool.Spec.PodSelector = pool.Spec.PodSelector.DeepCopy()
	v2Pool.Spec.NamespaceSelector = pool.Spec.NamespaceSelector.DeepCopy()
	pool.ObjectMeta.DeepCopyInto(&v2Pool.ObjectMeta)

	// Clear server-managed fields that should not be set on new objects
	v2Pool.ObjectMeta.ResourceVersion = ""
	v2Pool.ObjectMeta.UID = ""
	v2Pool.ObjectMeta.CreationTimestamp = metav1.Time{}

	// Convert IPv4 spec
	if pool.Spec.IPv4 != nil {
		v2Pool.Spec.IPv4 = &v2.IPv4PoolSpec{
			MaskSize: pool.Spec.IPv4.MaskSize,
		}
		for _, cidr := range pool.Spec.IPv4.CIDRs {
			// Skip empty CIDRs
			if string(cidr) == "" {
				continue
			}
			v2Pool.Spec.IPv4.CIDRs = append(v2Pool.Spec.IPv4.CIDRs, v2.PoolCIDR{
				CIDR: string(cidr),
			})
		}
	}

	// Convert IPv6 spec
	if pool.Spec.IPv6 != nil {
		v2Pool.Spec.IPv6 = &v2.IPv6PoolSpec{
			MaskSize: pool.Spec.IPv6.MaskSize,
		}
		for _, cidr := range pool.Spec.IPv6.CIDRs {
			// Skip empty CIDRs
			if string(cidr) == "" {
				continue
			}
			v2Pool.Spec.IPv6.CIDRs = append(v2Pool.Spec.IPv6.CIDRs, v2.PoolCIDR{
				CIDR: string(cidr),
			})
		}
	}

	return v2Pool
}

const (
	// AnnotationDisableMigration is the annotation key to disable automatic migration from v2alpha1 to v2.
	// By default, the operator will automatically migrate v2alpha1 CiliumPodIPPool resources to v2.
	// Set this annotation to "true" to prevent automatic migration.
	AnnotationDisableMigration = "cilium.io/ipam-disable-migration"
)

// StartIPPoolMigrator watches V2Alpha1 CiliumPodIPPool resources and migrates them to V2.
// Migration is automatic by default. Set AnnotationDisableMigration to "true" to prevent migration.
func StartIPPoolMigrator(
	ctx context.Context,
	clientset client.Clientset,
	ipPoolsV2alpha1 resource.Resource[*cilium_v2alpha1.CiliumPodIPPool],
	logger *slog.Logger,
) {
	logger.InfoContext(ctx, "Starting CiliumPodIPPool migrator")

	synced := make(chan struct{})

	go func() {
		for ev := range ipPoolsV2alpha1.Events(ctx) {
			switch ev.Kind {
			case resource.Sync:
				close(synced)
			case resource.Upsert:
				// Skip migration if disabled via annotation
				if val, ok := ev.Object.Annotations[AnnotationDisableMigration]; ok && val == "true" {
					logger.DebugContext(ctx, "Migration disabled via annotation, skipping", logfields.PoolName, ev.Key.Name)
					ev.Done(nil)
					continue
				}

				v2Pool := convertV2Alpha1ToV2(ev.Object)
				// Skip if conversion returned nil (pool already in v2 format, no valid CIDRs)
				if v2Pool == nil {
					logger.WarnContext(ctx, "Pool has no valid CIDRs (likely already v2), skipping migration", logfields.PoolName, ev.Key.Name)
					ev.Done(nil)
					continue
				}

				_, createErr := clientset.CiliumV2().CiliumPodIPPools().Create(ctx, v2Pool, metav1.CreateOptions{})
				if createErr != nil {
					if k8sErrors.IsAlreadyExists(createErr) {
						logger.DebugContext(ctx, "V2 pool already exists, skipping migration", logfields.PoolName, ev.Key.Name)
					} else {
						logger.WarnContext(ctx, "Failed to migrate pool to v2",
							logfields.PoolName, ev.Key.Name,
							logfields.Error, createErr,
						)
					}
				} else {
					logger.InfoContext(ctx, "Successfully migrated pool to v2", logfields.PoolName, ev.Key.Name)
				}
			case resource.Delete:
				logger.DebugContext(ctx, "V2Alpha1 pool deleted, V2 pool not affected", logfields.PoolName, ev.Key.Name)
			}

			ev.Done(nil)
		}
	}()

	<-synced
	logger.InfoContext(ctx, "All CiliumPodIPPool V2Alpha1 resources synchronized")
}