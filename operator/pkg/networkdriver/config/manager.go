// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2alpha1_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type ConfigManagerParams struct {
	cell.In

	Logger           *slog.Logger
	Lifecycle        cell.Lifecycle
	JobGroup         job.Group
	Clientset        k8sClient.Clientset
	DB               *statedb.DB
	CiliumNodes      statedb.Table[ciliumNode]
	ClusterConfigs   statedb.Table[driverClusterConfig]
	NodeConfigs      statedb.RWTable[*driverNodeConfig]
	ReconcilerParams reconciler.Params
	Ops              reconciler.Operations[*driverNodeConfig]

	DaemonCfg *option.DaemonConfig
}

func registerConfigManager(p ConfigManagerParams) error {
	if !p.Clientset.IsEnabled() || !p.DaemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	logger := p.Logger.With([]any{logfields.LogSubsys, "network-driver-config-manager"}...)

	client := p.Clientset.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()

	wtxn := p.DB.WriteTxn(p.CiliumNodes, p.ClusterConfigs, p.NodeConfigs)
	defer wtxn.Abort()

	initialized := p.NodeConfigs.RegisterInitializer(wtxn, "initial-node-configs-snapshot")

	ciliumNodesIt, err := p.CiliumNodes.Changes(wtxn)
	if err != nil {
		logger.Error("failed to watch changes on cilium nodes k8s table",
			logfields.Error, err,
		)
		return err
	}
	clusterConfigsIt, err := p.ClusterConfigs.Changes(wtxn)
	if err != nil {
		logger.Error("failed to watch changes on network driver cluster configurations k8s table",
			logfields.Error, err,
		)
		return err
	}

	wtxn.Commit()

	p.JobGroup.Add(job.OneShot(
		"network-driver-config-init-snapshot",
		func(ctx context.Context, health cell.Health) error {
			wtxn := p.DB.WriteTxn(p.NodeConfigs)

			txn := p.DB.ReadTxn()
			clusterCfgs := p.ClusterConfigs.All(txn)
			ciliumNodes := p.CiliumNodes.All(txn)

			var errs []error

			for clusterCfg := range clusterCfgs {
				var conflictErrs []error

				for ciliumNode := range ciliumNodes {
					if !clusterCfg.NodeSelector.Matches(labels.Set(ciliumNode.Labels)) {
						continue
					}

					// detect conflicting configurations
					if prevCfg, _, found := p.NodeConfigs.Get(wtxn, statedb.Query[*driverNodeConfig](DriverNodeConfigIndex.Query(ciliumNode.Name))); found {
						err := fmt.Errorf("conflicting network driver configurations %s and %s found for node %s", prevCfg.ClusterConfig, clusterCfg.Name, ciliumNode.Name)
						conflictErrs = append(conflictErrs, err)
						errs = append(errs, err)
						continue
					}

					if _, _, err := p.NodeConfigs.Insert(wtxn, &driverNodeConfig{
						Node:          ciliumNode.Name,
						ClusterConfig: clusterCfg.Name,
						Config:        *clusterCfg.NodeConfig.DeepCopy(),
						Status:        reconciler.StatusPending(),
					}); err != nil {
						errs = append(errs, fmt.Errorf("failed to create network driver node configuration for node %s: %w", ciliumNode.Name, err))
					}
				}

				var conds []metav1.Condition
				if len(conflictErrs) > 0 {
					conds = append(conds, conditionConflict(errors.Join(conflictErrs...)))
				}
				if err := updateClusterConfigStatus(ctx, client, clusterCfg, conds...); err != nil {
					errs = append(errs, fmt.Errorf("failed to update network driver cluster config %s status: %w", clusterCfg.Name, err))
				}
			}

			// enable pruning of stale network drive node configurations
			initialized(wtxn)
			wtxn.Commit()

			if len(errs) > 0 {
				err := errors.Join(errs...)
				reason := "failed to generate network driver node configurations initial shapshot"
				p.Logger.ErrorContext(ctx, reason, logfields.Error, err)
				health.Degraded(reason, err)
				return errors.Join(errs...)
			}

			health.OK("network driver node configurations initial snapshot completed")

			return nil
		},
	))

	p.JobGroup.Add(job.OneShot(
		"network-driver-node-handler",
		func(ctx context.Context, health cell.Health) error {
			_, initialized := p.NodeConfigs.Initialized(p.DB.ReadTxn())
			<-initialized

			for {
				txn := p.DB.ReadTxn()

				clusterConfigs := make([]driverClusterConfig, 0, p.ClusterConfigs.NumObjects(txn))
				for config := range p.ClusterConfigs.All(txn) {
					clusterConfigs = append(clusterConfigs, config)
				}

				wtxn := p.DB.WriteTxn(p.NodeConfigs)

				var errs []error

				changes, watch := ciliumNodesIt.Next(txn)
				for change := range changes {
					if change.Deleted {
						if _, _, err := p.NodeConfigs.Delete(wtxn, &driverNodeConfig{Node: change.Object.Name}); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete network driver node configuration for node %s: %w", change.Object.Name, err))
						}
						continue
					}

					for _, config := range clusterConfigs {
						if !config.NodeSelector.Matches(labels.Set(change.Object.Labels)) {
							continue
						}

						// discard cluster configs marked as conflicting
						if slices.ContainsFunc(config.Conditions, func(c metav1.Condition) bool {
							return c.Type == cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict
						}) {
							continue
						}

						if _, _, err := p.NodeConfigs.Insert(wtxn, &driverNodeConfig{
							Node:          change.Object.Name,
							ClusterConfig: config.Name,
							Config:        *config.NodeConfig.DeepCopy(),
							Status:        reconciler.StatusPending(),
						}); err != nil {
							errs = append(errs, fmt.Errorf("failed to create network driver node configuration for node %s: %w", change.Object.Name, err))
						}
					}
				}

				wtxn.Commit()

				if len(errs) > 0 {
					err := errors.Join(errs...)
					reason := "failed to update network driver configurations after node event"
					p.Logger.ErrorContext(ctx, reason, logfields.Error, err)
					health.Degraded(reason, err)
				} else {
					health.OK("network driver node configurations updated after node event")
				}

				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				}
			}
		},
	))

	p.JobGroup.Add(job.OneShot(
		"network-driver-cluster-config-handler",
		func(ctx context.Context, health cell.Health) error {
			_, initialized := p.NodeConfigs.Initialized(p.DB.ReadTxn())
			<-initialized

			for {
				txn := p.DB.ReadTxn()

				wtxn := p.DB.WriteTxn(p.NodeConfigs)

				var errs []error

				changes, watch := clusterConfigsIt.Next(txn)
				for change := range changes {
					if change.Deleted {
						for nodeConfig := range p.NodeConfigs.List(wtxn, DriverNodeConfigClusterConfigRefIndex.Query(change.Object.Name)) {
							if _, _, err := p.NodeConfigs.Delete(wtxn, nodeConfig); err != nil {
								errs = append(errs, fmt.Errorf("failed to delete network driver node configuration for node %s: %w", change.Object.Name, err))
							}
						}
						continue
					}

					var conflictErrs []error

					for node := range p.CiliumNodes.All(txn) {
						if !change.Object.NodeSelector.Matches(labels.Set(node.Labels)) {
							continue
						}

						// detect conflicting configurations
						prevCfg, _, found := p.NodeConfigs.Get(wtxn, statedb.Query[*driverNodeConfig](DriverNodeConfigIndex.Query(node.Name)))
						if found && prevCfg.ClusterConfig != change.Object.Name {
							err = fmt.Errorf("conflicting network driver configurations %s and %s found for node %s", prevCfg.ClusterConfig, change.Object.Name, node.Name)
							errs = append(errs, err)
							conflictErrs = append(conflictErrs, err)
						} else {
							if _, _, err := p.NodeConfigs.Insert(wtxn, &driverNodeConfig{
								Node:          node.Name,
								ClusterConfig: change.Object.Name,
								Config:        *change.Object.NodeConfig.DeepCopy(),
								Status:        reconciler.StatusPending(),
							}); err != nil {
								errs = append(errs, fmt.Errorf("failed to create network driver node configuration for node %s: %w", node.Name, err))
							}
						}
					}

					var conds []metav1.Condition
					if len(conflictErrs) > 0 {
						conds = append(conds, conditionConflict(errors.Join(conflictErrs...)))
					}
					if err := updateClusterConfigStatus(ctx, client, change.Object, conds...); err != nil {
						errs = append(errs, fmt.Errorf("failed to update network driver cluster config %s status: %w", change.Object.Name, err))
					}
				}

				wtxn.Commit()

				if len(errs) > 0 {
					err := errors.Join(errs...)
					reason := "failed to update network driver configurations after cluster config event"
					p.Logger.ErrorContext(ctx, reason, logfields.Error, err)
					health.Degraded(reason, err)
				} else {
					health.OK("network driver node configurations updated after cluster config event")
				}

				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				}
			}
		},
	))

	return nil
}

func updateClusterConfigStatus(
	ctx context.Context,
	client cilium_v2alpha1.CiliumNetworkDriverClusterConfigInterface,
	cfg driverClusterConfig,
	conds ...metav1.Condition,
) error {
	if slices.EqualFunc(cfg.Conditions, conds, func(c1, c2 metav1.Condition) bool {
		return c1.Type == c2.Type &&
			c1.Status == c2.Status &&
			c1.Reason == c2.Reason &&
			c1.Message == c2.Message
	}) {
		return nil
	}

	config, err := client.Get(ctx, cfg.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get network driver cluster config %s to update its status: %w", cfg.Name, err)
	}

	newConfig := config.DeepCopy()
	newConfig.Status.Conditions = conds
	_, err = client.UpdateStatus(ctx, newConfig, metav1.UpdateOptions{})

	return err
}

func conditionConflict(err error) metav1.Condition {
	return metav1.Condition{
		Type:               cilium_v2alpha1_api.NetworkDriverClusterConfigConditionConflict,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Reason:             cilium_v2alpha1_api.NetworkDriverClusterConfigReasonConflict,
		Message:            err.Error(),
	}
}
