// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	"github.com/spf13/pflag"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	allocatorTypes "github.com/cilium/cilium/operator/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// autoCreateCiliumPodIPPoolsFlag is the flag name used to pre-declare
	// CiliumPodIPPool resources to be auto-created on startup.
	autoCreateCiliumPodIPPoolsFlag = "auto-create-cilium-pod-ip-pools"

	// enableClusterPoolToMultiPoolMigration is the flag name to enable the migration
	// of all nodes from cluster-pool IPAM to multi-pool IPAM
	enableClusterPoolToMultiPoolMigration = "enable-cluster-pool-to-multi-pool-migration"

	// migrationWorker is the flag name to set the number of workers to use for migrating
	// nodes from cluster-pool IPAM to multi-pool IPAM.
	migrationWorker = "multi-pool-migration-workers"
)

type Config struct {
	AutoCreatePools          map[string]string `mapstructure:"auto-create-cilium-pod-ip-pools"`
	IPAMDefaultPool          string            `mapstructure:"ipam-default-ip-pool"` // keep this in sync with agent config "IPAMDefaultIPPool"
	FromClusterPoolMigration bool              `mapstructure:"enable-cluster-pool-to-multi-pool-migration"`
	MigrationWorkers         int               `mapstructure:"multi-pool-migration-workers"`
}

var DefaultConfig = Config{
	AutoCreatePools:          nil,
	FromClusterPoolMigration: false,
	IPAMDefaultPool:          defaults.IPAMDefaultIPPool,
	MigrationWorkers:         16,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.StringToString(autoCreateCiliumPodIPPoolsFlag, DefaultConfig.AutoCreatePools,
		"Automatically create CiliumPodIPPool resources on startup. "+
			"Specify pools in the form of <pool>=ipv4-cidrs:<cidr>,[<cidr>...];ipv4-mask-size:<size>[;allow-first-ip:<bool>][;allow-last-ip:<bool>] (multiple pools can also be passed by repeating the CLI flag)")
	flags.Bool(enableClusterPoolToMultiPoolMigration, DefaultConfig.FromClusterPoolMigration,
		"Enable the migration of all nodes from cluster-pool IPAM to multi-pool IPAM")
	flags.String(option.IPAMDefaultIPPool, DefaultConfig.IPAMDefaultPool, "Name of the default IP Pool when using multi-pool")
	flags.Int(migrationWorker, DefaultConfig.MigrationWorkers, "Number of workers to use for migrating nodes from cluster-pool IPAM to multi-pool IPAM")
}

type multiPoolParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	DaemonCfg          *option.DaemonConfig
	CiliumPodIPPools   resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool]
	NodeWatcherFactory allocatorTypes.NodeWatcherJobFactory
	CiliumNodes        resource.Resource[*v2.CiliumNode]

	Allocator *PoolAllocator

	MultiPoolCfg Config
}

func StartAllocator(p multiPoolParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMMultiPool {
		return
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := multiPoolAutoCreatePools(ctx, p.Clientset, p.MultiPoolCfg.AutoCreatePools, p.Logger); err != nil {
					return err
				}

				migrationDone := make(chan struct{})

				p.JobGroup.Add(
					job.OneShot(
						"from-cluster-pool-migration",
						func(ctx context.Context, _ cell.Health) error {
							defer close(migrationDone)

							if !p.MultiPoolCfg.FromClusterPoolMigration {
								return nil
							}

							store, err := p.CiliumNodes.Store(ctx)
							if err != nil {
								return fmt.Errorf("failed to get CiliumNode store, migration to multi-pool IPAM failed: %w", err)
							}

							wp := workerpool.NewWithContext(ctx, max(p.MultiPoolCfg.MigrationWorkers, 1))
							defer wp.Close()

							iter := store.IterKeys()
							for iter.Next() {
								key := iter.Key()
								wp.Submit(
									key.Name,
									func(ctx context.Context) error {
										var errs []error
										if err := migrateNode(
											ctx, store, p.Clientset.CiliumV2().CiliumNodes(),
											key, p.MultiPoolCfg.IPAMDefaultPool,
										); err != nil {
											errs = append(errs, fmt.Errorf("failed to migrate node %q: %w", key.Name, err))

											if err := updateStatusForFailure(
												ctx, store, p.Clientset.CiliumV2().CiliumNodes(),
												key, err,
											); err != nil {
												errs = append(errs, fmt.Errorf("failed to update CiliumNode status for node %q after migration failure: %w", key.Name, err))
											}
										}
										return errors.Join(errs...)
									},
								)
							}

							tasks, err := wp.Drain()
							if err != nil {
								p.Logger.ErrorContext(
									ctx, "Failed to drain worker pool for multi-pool migration",
									logfields.Error, err,
								)
							}
							for _, task := range tasks {
								if err := task.Err(); err != nil {
									p.Logger.ErrorContext(
										ctx, "Migration to multi-pool IPAM failed for node",
										logfields.Error, err,
										logfields.Node, task,
									)
								}
							}

							return nil
						},
					),
				)

				p.JobGroup.Add(p.NodeWatcherFactory(
					func(ctx context.Context) (allocatorTypes.NodeEventHandler, error) {
						// The following operation will block until all pools are restored, thus it
						// is safe to continue starting node allocation right after return.
						startIPPoolAllocator(ctx, p.Allocator, p.CiliumPodIPPools, p.Logger)

						// Wait for all nodes to be migrated to multi-pool
						<-migrationDone

						nm := NewNodeHandler(
							"ipam-multi-pool-sync",
							p.Logger, p.Allocator, p.Clientset.CiliumV2().CiliumNodes(),
							ipam.MultiPoolAccessor,
						)

						return nm, nil
					},
				))

				return nil
			},
		},
	)
}

func multiPoolAutoCreatePools(ctx context.Context, clientset client.Clientset, poolMap map[string]string, logger *slog.Logger) error {
	for poolName, poolSpecStr := range poolMap {
		poolSpec, err := ParsePoolSpec(poolSpecStr)
		if err != nil {
			logger.ErrorContext(ctx,
				fmt.Sprintf("Failed to parse IP pool spec in %q flag", autoCreateCiliumPodIPPoolsFlag),
				logfields.PoolName, poolName,
				logfields.PoolSpec, poolSpecStr,
				logfields.Error, err)
			return err
		}

		pool := &cilium_api_v2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: poolName,
			},
			Spec: cilium_api_v2alpha1.IPPoolSpec{
				IPv4:         poolSpec.IPv4,
				IPv6:         poolSpec.IPv6,
				AllowFirstIP: poolSpec.AllowFirstIP,
				AllowLastIP:  poolSpec.AllowLastIP,
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

func migrateNode(
	ctx context.Context,
	store resource.Store[*v2.CiliumNode],
	client cilium_v2.CiliumNodeInterface,
	key resource.Key,
	pool string,
) error {
	return updateNodeWithRetries(
		ctx, store, key,
		func(node *v2.CiliumNode) (done bool, conflict bool, err error) {
			if len(node.Spec.IPAM.PodCIDRs) == 0 {
				return true, false, nil
			}

			newNode := node.DeepCopy()
			cidrs := make([]iputil.Prefix, 0, len(node.Spec.IPAM.PodCIDRs))
			for _, cidr := range node.Spec.IPAM.PodCIDRs {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil {
					return true, false, fmt.Errorf("unable to parse CIDR %q: %w", cidr, err)
				}
				cidrs = append(cidrs, iputil.PrefixFrom(prefix))
			}
			newNode.Spec.IPAM.Pools = types.IPAMPoolSpec{
				Allocated: []types.IPAMPoolAllocation{
					{
						Pool:  pool,
						CIDRs: cidrs,
					},
				},
			}
			newNode.Spec.IPAM.PodCIDRs = nil

			if _, err := client.Update(ctx, newNode, metav1.UpdateOptions{}); err != nil {
				switch {
				case k8sErrors.IsConflict(err):
					return false, true, err
				case k8sErrors.IsNotFound(err):
					// node was deleted after we read it, nothing to do
					return true, false, nil
				default:
					return false, false, fmt.Errorf("unable to update node: %w", err)
				}
			}

			return true, false, nil
		},
	)
}

func updateStatusForFailure(
	ctx context.Context,
	store resource.Store[*v2.CiliumNode],
	client cilium_v2.CiliumNodeInterface,
	key resource.Key,
	migrationErr error,
) error {
	errorMessage := fmt.Sprintf("migration to multi-pool IPAM failed: %s", migrationErr)

	return updateNodeWithRetries(
		ctx, store, key,
		func(node *v2.CiliumNode) (done bool, conflict bool, err error) {
			if node.Status.IPAM.OperatorStatus.Error == errorMessage {
				return true, false, nil
			}

			newNode := node.DeepCopy()
			newNode.Status.IPAM.OperatorStatus.Error = errorMessage
			if _, err := client.UpdateStatus(ctx, newNode, metav1.UpdateOptions{}); err != nil {
				switch {
				case k8sErrors.IsConflict(err):
					return false, true, err
				case k8sErrors.IsNotFound(err):
					// node was deleted after we read it, nothing to do
					return true, false, nil
				default:
					return false, false, fmt.Errorf("unable to update node status: %w", err)
				}
			}

			return true, false, nil
		},
	)
}

func updateNodeWithRetries(
	ctx context.Context,
	store resource.Store[*v2.CiliumNode],
	key resource.Key,
	updateFunc func(node *v2.CiliumNode) (bool, bool, error),
) error {
	var (
		node      *v2.CiliumNode
		updateErr error
	)

	backoff := wait.Backoff{
		Steps:    10,
		Duration: 10 * time.Millisecond,
		Factor:   2.5,
		Jitter:   0.1,
	}

	var conflict bool
	if err := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		updNode, exists, err := store.GetByKey(key)
		if err != nil {
			return false, fmt.Errorf("unable to get node from store: %w", err)
		}
		if !exists {
			// node was deleted, nothing to do
			return true, nil
		}
		if conflict && node.ResourceVersion == updNode.ResourceVersion {
			// wait for the store to be updated after a conflict
			return false, nil
		}
		node = updNode
		conflict = false

		var done bool

		done, conflict, err = updateFunc(node)

		// propagate last error
		updateErr = err

		if !done {
			// keep retrying
			return false, nil
		}

		return true, err
	}); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return updateErr
	}

	return nil
}

func startIPPoolAllocator(
	ctx context.Context,
	allocator *PoolAllocator,
	ipPools resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool],
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
				err = UpsertPool(allocator, ev.Object.Name, ev.Object.Spec.IPv4, ev.Object.Spec.IPv6, ev.Object.Spec.AllowFirstIP, ev.Object.Spec.AllowLastIP)
				action = "upsert"
			case resource.Delete:
				err = DeletePool(allocator, ev.Object.Name)
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
