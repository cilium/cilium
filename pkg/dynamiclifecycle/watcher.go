// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamiclifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type FeatureStatus struct {
	Feature DynamicFeatureName
	Enabled bool
}

type watcherParams struct {
	cell.In

	JobGroup                job.Group
	Logger                  *slog.Logger
	DynamicFeatureTable     statedb.RWTable[*DynamicFeature]
	DB                      *statedb.DB
	ManagerConfig           config
	DynamicConfigTable      statedb.Table[dynamicconfig.DynamicConfig]
	DynamicConfigCellConfig dynamicconfig.Config
	FeatureRegistrations    []featureRegistration `group:"dynamiclifecycle-registrations"`
}

type configWatcher struct {
	watcherParams
}

// setEnabled sets the enablement flag for DynamicFeatureName
// If enabled is marked true the Lifecycle hooks are started by the DynamicFeature reconciler considering the dependencies.
// If one of the DynamicFeatureName hooks fail to start, the reconciler attempts
// to stop already started hooks. The reconciler will retry to start the DynamicFeatureName.
// If enabled is marked false the Lifecycle hooks are stopped by the DynamicFeature reconciler.
// Currently, without tracking the dependencies.
func (cw *configWatcher) setEnabled(feature DynamicFeatureName, enabled bool, tx statedb.WriteTxn) {
	obj, _, found := cw.DynamicFeatureTable.Get(tx, ByFeature(feature))
	if !found {
		return
	}
	if obj.Enabled == enabled {
		return
	}

	obj = obj.Clone()
	obj.Enabled = enabled
	obj.Status = reconciler.StatusPending()

	_, _, _ = cw.DynamicFeatureTable.Insert(tx, obj)

	cw.Logger.Info("DynamicFeatureName Enablement",
		logfields.Feature, feature,
		logfields.Enabled, enabled)
}

func (cw *configWatcher) processDynamicFeatures(dfcJson string) error {
	fs, err := decodeJson(dfcJson)
	if err != nil {
		return fmt.Errorf("failed to decode JSON %w", err)
	}

	// Getting a writeTxn and reuse the same transaction for updating the table
	wTx := cw.DB.WriteTxn(cw.DynamicFeatureTable)
	defer wTx.Commit()
	for _, status := range fs {
		cw.setEnabled(status.Feature, status.Enabled, wTx)
	}
	return nil
}

func (cw *configWatcher) watch(ctx context.Context, health cell.Health) error {
	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()
	for {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		entry, found, w := dynamicconfig.WatchKey(cw.DB.ReadTxn(), cw.DynamicConfigTable, ConfigKey)
		fs := cw.ManagerConfig.DynamicLifecycleConfig
		if found {
			fs = entry.Value
		}

		if err := cw.processDynamicFeatures(fs); err != nil {
			cw.Logger.Error("Failed to process dynamic feature configuration", logfields.Error, err)
			health.Degraded("Failed to process dynamic feature configuration", err)
		} else {
			health.OK("OK")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w:
			continue
		}
	}
}

func decodeJson(in string) ([]FeatureStatus, error) {
	sources := make([]FeatureStatus, 0)
	if err := json.Unmarshal([]byte(in), &sources); err != nil {
		return sources, err
	}
	return sources, nil
}

func registerWatcher(p watcherParams) error {
	if !p.ManagerConfig.EnableDynamicLifecycleManager {
		return nil
	}
	if !p.DynamicConfigCellConfig.EnableDynamicConfig {
		return fmt.Errorf("failed to start dynamic-lifecycle-manager with enable-dynamic-config=%t", p.DynamicConfigCellConfig.EnableDynamicConfig)
	}

	w := &configWatcher{p}
	p.JobGroup.Add(job.OneShot("dynamic-config-watcher", func(ctx context.Context, health cell.Health) error {
		return w.watch(ctx, health)
	}))
	return nil
}
