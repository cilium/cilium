// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type ConfigManagerParams struct {
	cell.In

	Logger              *slog.Logger
	Lifecycle           cell.Lifecycle
	JobGroup            job.Group
	Clientset           k8sClient.Clientset
	CiliumNodes         resource.Resource[*cilium_api_v2.CiliumNode]
	ClusterConfigs      resource.Resource[*cilium_api_v2alpha1.CiliumNetworkDriverClusterConfig]
	DB                  *statedb.DB
	NodeConfigsTable    statedb.RWTable[*driverNodeConfig]
	ClusterConfigsTable statedb.RWTable[*driverClusterConfig]

	DaemonCfg *option.DaemonConfig
}

func registerConfigManager(params ConfigManagerParams) error {
	if !params.Clientset.IsEnabled() || !params.DaemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	mgr := manager{
		logger:         params.Logger,
		nodes:          make(map[string]ciliumNode),
		configs:        make(map[string]clusterConfig),
		db:             params.DB,
		nodeConfigs:    params.NodeConfigsTable,
		clusterConfigs: params.ClusterConfigsTable,
	}

	wtxn := params.DB.WriteTxn(mgr.nodeConfigs)
	initialized := mgr.nodeConfigs.RegisterInitializer(wtxn, "node-configs-initialized")
	wtxn.Commit()

	params.JobGroup.Add(
		job.OneShot(
			"network-driver-config-reconciler",
			func(ctx context.Context, health cell.Health) error {
				mgr.run(ctx, params.CiliumNodes, params.ClusterConfigs, params.DB, initialized)
				return nil
			},
		),
	)

	return nil
}

type ciliumNode struct {
	name   string
	labels labels.Set
}

type clusterConfig struct {
	name         string
	createdAt    time.Time
	nodeSelector labels.Selector
	spec         cilium_api_v2alpha1.CiliumNetworkDriverNodeConfigSpec
}

type manager struct {
	logger *slog.Logger

	nodes   map[string]ciliumNode
	configs map[string]clusterConfig

	db             *statedb.DB
	nodeConfigs    statedb.RWTable[*driverNodeConfig]
	clusterConfigs statedb.RWTable[*driverClusterConfig]
}

func (mgr *manager) run(
	ctx context.Context,
	ciliumNodes resource.Resource[*cilium_api_v2.CiliumNode],
	clusterConfigs resource.Resource[*cilium_api_v2alpha1.CiliumNetworkDriverClusterConfig],
	db *statedb.DB,
	initialized func(statedb.WriteTxn),
) {
	var initDone, cnInit, ccInit bool

	cnEvents := ciliumNodes.Events(ctx)
	ccEvents := clusterConfigs.Events(ctx)

	for cnEvents != nil && ccEvents != nil {
		select {
		case ev, ok := <-cnEvents:
			if !ok {
				cnEvents = nil
				continue
			}

			var err error
			if ev.Kind == resource.Sync {
				cnInit = true
			} else {
				err = mgr.handleCiliumNodeEvent(ctx, ev)
			}
			ev.Done(err)
		case ev, ok := <-ccEvents:
			if !ok {
				ccEvents = nil
				continue
			}

			var err error
			if ev.Kind == resource.Sync {
				ccInit = true
			} else {
				err = mgr.handleClusterConfigEvent(ctx, ev)
			}
			ev.Done(err)
		}

		// enable pruning of stale network driver node configurations
		if !initDone && cnInit && ccInit {
			initDone = true
			wtxn := db.WriteTxn(mgr.nodeConfigs)
			initialized(wtxn)
			wtxn.Commit()
		}
	}
}

func (mgr *manager) handleCiliumNodeEvent(ctx context.Context, ev resource.Event[*cilium_api_v2.CiliumNode]) error {
	// in case of error the transaction is aborted and the event is marked for retry,
	// therefore we need to restore the initial status of the nodes and configs caches
	oldNodes, oldConfigs := mgr.snapshot()

	switch ev.Kind {
	case resource.Upsert:
		if node, found := mgr.nodes[ev.Object.Name]; found {
			if labels.Equals(node.labels, ev.Object.Labels) {
				return nil
			}
		}

		node := ciliumNode{
			name:   ev.Object.Name,
			labels: labels.Set(ev.Object.Labels),
		}
		mgr.nodes[node.name] = node
	case resource.Delete:
		if _, found := mgr.nodes[ev.Object.Name]; !found {
			return nil
		}

		delete(mgr.nodes, ev.Object.Name)
	}

	return mgr.reconcileConfigsWithRollback(ctx, oldNodes, oldConfigs)
}

func (mgr *manager) handleClusterConfigEvent(ctx context.Context, ev resource.Event[*cilium_api_v2alpha1.CiliumNetworkDriverClusterConfig]) error {
	// in case of error the transaction is aborted and the event is marked for retry,
	// therefore we need to restore the initial status of the nodes and configs caches
	oldNodes, oldConfigs := mgr.snapshot()

	switch ev.Kind {
	case resource.Upsert:
		obj := ev.Object

		var nodeSel labels.Selector
		if obj.Spec.NodeSelector == nil {
			nodeSel = labels.Everything()
		} else {
			sel, err := slimv1.LabelSelectorAsSelector(obj.Spec.NodeSelector)
			if err != nil {
				return err
			}
			nodeSel = sel
		}

		if cfg, found := mgr.configs[obj.Name]; found {
			if obj.CreationTimestamp.Time.Equal(cfg.createdAt) &&
				nodeSel.String() == cfg.nodeSelector.String() &&
				obj.Spec.Spec.DeepEqual(&cfg.spec) {
				return nil
			}
		}

		config := clusterConfig{
			name:         obj.Name,
			createdAt:    obj.CreationTimestamp.Time,
			nodeSelector: nodeSel,
			spec:         *obj.Spec.Spec.DeepCopy(),
		}
		mgr.configs[obj.Name] = config
	case resource.Delete:
		if _, found := mgr.configs[ev.Object.Name]; !found {
			return nil
		}

		delete(mgr.configs, ev.Object.Name)
	}

	return mgr.reconcileConfigsWithRollback(ctx, oldNodes, oldConfigs)
}

func (mgr *manager) snapshot() (map[string]ciliumNode, map[string]clusterConfig) {
	return maps.Clone(mgr.nodes), maps.Clone(mgr.configs)
}

func (mgr *manager) reconcileConfigsWithRollback(ctx context.Context, oldNodes map[string]ciliumNode, oldConfigs map[string]clusterConfig) error {
	if err := mgr.reconcileConfigs(ctx); err != nil {
		mgr.nodes = oldNodes
		mgr.configs = oldConfigs
		return err
	}

	return nil
}

func (mgr *manager) reconcileConfigs(ctx context.Context) error {
	cfgs := make([]clusterConfig, 0, len(mgr.configs))
	for _, cfg := range mgr.configs {
		cfgs = append(cfgs, cfg)
	}

	// sort cluster configs by creation time to prioritize older configs
	slices.SortFunc(cfgs, func(a, b clusterConfig) int {
		return cmp.Or(
			a.createdAt.Compare(b.createdAt),
			cmp.Compare(a.name, b.name),
		)
	})

	occupiedNodes := sets.New[string]()
	conflictingCfgs := sets.New[string]()
	nodeCfgs := make(map[string]clusterConfig)

	for _, cfg := range cfgs {
		matchedNodes := sets.New[string]()

		for _, node := range mgr.nodes {
			if cfg.nodeSelector.Matches(node.labels) {
				matchedNodes.Insert(node.name)
			}
		}

		if matchedNodes.Len() == 0 {
			continue
		}

		// if there's at least one node already "occupied" (that is, with a higher
		// priority cluster config that matches it) then we should mark this config
		// as conflicting
		if matchedNodes.Intersection(occupiedNodes).Len() > 0 {
			conflictingCfgs.Insert(cfg.name)
			continue
		}

		// otherwise all the matched nodes will be "occupied" by this config
		for node := range matchedNodes {
			nodeCfgs[node] = cfg
		}
		occupiedNodes.Insert(matchedNodes.UnsortedList()...)
	}

	wtxn := mgr.db.WriteTxn(mgr.clusterConfigs, mgr.nodeConfigs)
	defer wtxn.Abort()

	if err := mgr.reconcileClusterConfigs(ctx, wtxn, conflictingCfgs); err != nil {
		return fmt.Errorf("failed to reconcile cluster configs: %w", err)
	}

	if err := mgr.reconcileNodeConfigs(ctx, wtxn, nodeCfgs); err != nil {
		return fmt.Errorf("failed to reconcile node configs: %w", err)
	}

	wtxn.Commit()

	return nil
}

func (mgr *manager) reconcileClusterConfigs(ctx context.Context, wtxn statedb.WriteTxn, conflictingCfgs sets.Set[string]) error {
	var errs []error

	for _, cfg := range statedb.Collect(mgr.clusterConfigs.All(wtxn)) {
		// delete stale cluster configs
		if _, found := mgr.configs[cfg.Name]; !found {
			if _, _, err := mgr.clusterConfigs.Delete(wtxn, cfg); err != nil {
				mgr.logger.ErrorContext(ctx, "failed to delete network driver cluster config from stateDB",
					logfields.ClusterConfig, cfg.Name,
					logfields.Error, err,
				)
				errs = append(errs, fmt.Errorf("failed to delete cluster config %s: %w", cfg.Name, err))
			} else {
				mgr.logger.DebugContext(ctx, "deleted network driver cluster config from stateDB",
					logfields.NodeConfig, cfg.Name,
				)
			}
			continue
		}
	}

	for _, cfg := range mgr.configs {
		if conflictingCfgs.Has(cfg.name) {
			errs = append(errs, mgr.updateClusterConfig(ctx, wtxn, cfg.name, true))
		} else {
			errs = append(errs, mgr.updateClusterConfig(ctx, wtxn, cfg.name, false))
		}
	}

	return errors.Join(errs...)
}

func (mgr *manager) updateClusterConfig(ctx context.Context, wtxn statedb.WriteTxn, cfg string, isConflicting bool) error {
	old, _, found := mgr.clusterConfigs.Get(wtxn, DriverClusterConfigIndex.Query(cfg))
	if found && old.IsConflicting == isConflicting {
		return nil
	}

	clusterCfg := driverClusterConfig{
		Name:          cfg,
		IsConflicting: isConflicting,
		Status:        reconciler.StatusPending(),
	}
	if _, _, err := mgr.clusterConfigs.Insert(wtxn, &clusterCfg); err != nil {
		mgr.logger.ErrorContext(ctx, "failed to update network driver cluster config status in stateDB",
			logfields.ClusterConfig, cfg,
			logfields.Error, err,
		)
		return fmt.Errorf("failed to update cluster config %s status: %w", cfg, err)
	} else {
		mgr.logger.DebugContext(ctx, "network driver cluster config status updated in stateDB",
			logfields.NodeConfig, cfg,
		)
	}

	return nil
}

func (mgr *manager) reconcileNodeConfigs(ctx context.Context, wtxn statedb.WriteTxn, nodeCfgs map[string]clusterConfig) error {
	var errs []error

	// delete node configs
	for _, cfg := range statedb.Collect(mgr.nodeConfigs.All(wtxn)) {
		if _, found := nodeCfgs[cfg.Node]; found {
			continue
		}

		if _, _, err := mgr.nodeConfigs.Delete(wtxn, cfg); err != nil {
			mgr.logger.ErrorContext(ctx, "failed to delete network driver node config from stateDB",
				logfields.NodeConfig, cfg.Node,
				logfields.Error, err,
			)
			errs = append(errs, fmt.Errorf("failed to delete node config %s: %w", cfg.Node, err))
		} else {
			mgr.logger.DebugContext(ctx, "deleted network driver node config from stateDB",
				logfields.NodeConfig, cfg.Node,
			)
		}
	}

	// upsert node configs
	for node, cfg := range nodeCfgs {
		old, _, found := mgr.nodeConfigs.Get(wtxn, DriverNodeConfigIndex.Query(node))
		if found && old.ClusterConfig == cfg.name && old.Config.DeepEqual(&cfg.spec) {
			continue
		}

		nodeCfg := driverNodeConfig{
			Node:          node,
			ClusterConfig: cfg.name,
			Config:        &cfg.spec,
			Status:        reconciler.StatusPending(),
		}
		if _, _, err := mgr.nodeConfigs.Insert(wtxn, &nodeCfg); err != nil {
			mgr.logger.ErrorContext(ctx, "failed to upsert network driver node config into stateDB",
				logfields.NodeConfig, node,
				logfields.ClusterConfig, cfg.name,
				logfields.Error, err,
			)
			errs = append(errs, fmt.Errorf("failed to upsert node config %s: %w", node, err))
		} else {
			mgr.logger.DebugContext(ctx, "upserted network driver node config into stateDB",
				logfields.NodeConfig, node,
				logfields.ClusterConfig, cfg.name,
			)
		}
	}

	return errors.Join(errs...)
}
