// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamiclifecycle

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
)

var (
	goodHook = cell.Hook{
		OnStart: func(ctx cell.HookContext) error { return nil },
		OnStop:  func(ctx cell.HookContext) error { return nil },
	}
	badHook = cell.Hook{
		OnStart: func(ctx cell.HookContext) error { return fmt.Errorf("error on start") },
		OnStop:  func(ctx cell.HookContext) error { return fmt.Errorf("error on stop") },
	}
	dcKey = dynamicconfig.Key{Name: ConfigKey, Source: "cilium-config"}
)

func TestManager_Enablement(t *testing.T) {
	var start, stop int
	hook := cell.Hook{
		OnStart: func(ctx cell.HookContext) error { start++; return nil },
		OnStop:  func(ctx cell.HookContext) error { stop++; return nil },
	}

	_, db, dc, df := fixture(t)

	// Register a new feature
	wTxn := db.WriteTxn(df)
	f := &DynamicFeature{
		Name:      "new_feature",
		Hooks:     []cell.HookInterface{hook},
		Deps:      nil,
		IsRunning: false,
		Enabled:   false,
		Status:    reconciler.StatusDone(),
	}
	_, _, _ = df.Insert(wTxn, f)
	wTxn.Commit()

	// Repeat the operation 2 times
	for i := range 2 {
		// Start the registered feature
		wTxn = db.WriteTxn(dc)
		c := dynamicconfig.DynamicConfig{
			Key:      dcKey,
			Value:    `[{"Feature":"new_feature","Enabled":true}]`,
			Priority: 0,
		}
		_, _, _ = dc.Insert(wTxn, c)
		wTxn.Commit()

		// Ensure the feature is actually running
		assert.Eventually(t, func() bool {
			return start == i+1
		}, 5*time.Second, time.Millisecond)

		// Stop the registered feature
		wTxn = db.WriteTxn(dc)
		c = dynamicconfig.DynamicConfig{
			Key:      dcKey,
			Value:    `[{"Feature":"new_feature","Enabled":false}]`,
			Priority: 0,
		}
		_, _, _ = dc.Insert(wTxn, c)
		wTxn.Commit()

		// Ensure the feature is actually stopped
		assert.Eventually(t, func() bool {
			return stop == i+1
		}, 5*time.Second, time.Millisecond)
	}
}

func TestManager(t *testing.T) {

	tests := []struct {
		name                   string
		feature                DynamicFeatureName
		deps                   []DynamicFeatureName
		hooks                  []cell.HookInterface
		dynamicConfig          dynamicconfig.DynamicConfig
		expectedDynamicFeature DynamicFeature
	}{
		{
			name:    "new_feature",
			feature: DynamicFeatureName("new_feature"),
			deps:    nil,
			hooks:   []cell.HookInterface{goodHook},
			dynamicConfig: dynamicconfig.DynamicConfig{
				Key:      dcKey,
				Value:    `[{"Feature":"new_feature","Enabled":true}]`,
				Priority: 0,
			},
			expectedDynamicFeature: DynamicFeature{
				Name:      "new_feature",
				Hooks:     []cell.HookInterface{goodHook},
				Deps:      nil,
				IsRunning: true,
				Enabled:   true,
				Status:    reconciler.StatusDone(),
			},
		},
		{
			name:    "bad_hook",
			feature: DynamicFeatureName("new_feature"),
			deps:    nil,
			hooks:   []cell.HookInterface{badHook},
			dynamicConfig: dynamicconfig.DynamicConfig{
				Key:      dcKey,
				Value:    `[{"Feature":"new_feature","Enabled":true}]`,
				Priority: 0,
			},
			expectedDynamicFeature: DynamicFeature{
				Name:      "new_feature",
				Hooks:     []cell.HookInterface{badHook},
				Deps:      nil,
				IsRunning: false,
				Enabled:   true,
				Status:    reconciler.StatusError(fmt.Errorf("mock error")),
			},
		},
		{
			name:    "not_started",
			feature: DynamicFeatureName("new_feature"),
			deps:    nil,
			hooks:   []cell.HookInterface{goodHook},
			dynamicConfig: dynamicconfig.DynamicConfig{
				Key:      dcKey,
				Value:    `[{"Feature":"new_feature","Enabled":false}]`,
				Priority: 0,
			},
			expectedDynamicFeature: DynamicFeature{
				Name:      "new_feature",
				Hooks:     []cell.HookInterface{goodHook},
				Deps:      nil,
				IsRunning: false,
				Enabled:   false,
				Status:    reconciler.StatusDone(),
			},
		},
		{
			name:    "missing_dynamic_config",
			feature: DynamicFeatureName("new_feature"),
			deps:    nil,
			hooks:   []cell.HookInterface{goodHook},
			dynamicConfig: dynamicconfig.DynamicConfig{
				Key:      dcKey,
				Value:    ``,
				Priority: 0,
			},
			expectedDynamicFeature: DynamicFeature{
				Name:      "new_feature",
				Hooks:     []cell.HookInterface{goodHook},
				Deps:      nil,
				IsRunning: false,
				Enabled:   false,
				Status:    reconciler.StatusDone(),
			},
		},
		{
			name:    "missing_dep_enabled",
			feature: DynamicFeatureName("new_feature"),
			deps:    []DynamicFeatureName{"missing_dependency"},
			hooks:   []cell.HookInterface{goodHook},
			dynamicConfig: dynamicconfig.DynamicConfig{
				Key:      dcKey,
				Value:    `[{"Feature":"new_feature","Enabled":true}]`,
				Priority: 0,
			},
			expectedDynamicFeature: DynamicFeature{
				Name:      "new_feature",
				Hooks:     []cell.HookInterface{goodHook},
				Deps:      []DynamicFeatureName{"missing_dependency"},
				IsRunning: false,
				Enabled:   true,
				Status:    reconciler.StatusError(fmt.Errorf("mock error")),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, db, dc, df := fixture(t)

			wTxn := db.WriteTxn(df)
			_, _, _ = df.Insert(wTxn, newDynamicFeature(tt.feature, tt.deps, tt.hooks))
			wTxn.Commit()

			wTxn = db.WriteTxn(dc)
			_, _, _ = dc.Insert(wTxn, tt.dynamicConfig)
			wTxn.Commit()

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				obj, _, _ := df.Get(db.ReadTxn(), ByFeature(tt.feature))
				cmpDynamicFeature(c, obj, &tt.expectedDynamicFeature)
			}, 5*time.Second, time.Millisecond)
		})
	}
}

func cmpDynamicFeature(t *assert.CollectT, actual *DynamicFeature, expected *DynamicFeature) bool {
	if actual == nil {
		t.Errorf("Condition not met: actual is nil")
		return false
	}
	if actual.Name != expected.Name {
		t.Errorf("Condition not met: actual.Name (%s) != expected.Name (%s)", actual.Name, expected.Name)
		return false
	}
	if actual.Enabled != expected.Enabled {
		t.Errorf("Condition not met: actual.Enabled (%t) != expected.Enabled (%t)", actual.Enabled, expected.Enabled)
		return false
	}
	if actual.IsRunning != expected.IsRunning {
		t.Errorf("Condition not met: actual.IsRunning (%t) != expected.IsRunning (%t)", actual.IsRunning, expected.IsRunning)
		return false
	}
	if len(actual.Hooks) != len(expected.Hooks) {
		t.Errorf("Condition not met: len(actual.Hooks) (%d) != len(expected.Hooks) (%d)", len(actual.Hooks), len(expected.Hooks))
		return false
	}
	if actual.Status.Kind != expected.Status.Kind {
		t.Errorf("Condition not met: actual.Status.Kind (%v) != expected.Status.Kind (%v)", actual.Status.Kind, expected.Status.Kind)
		return false
	}
	return true
}

func fixture(t *testing.T) (*hive.Hive, *statedb.DB, statedb.RWTable[dynamicconfig.DynamicConfig], statedb.RWTable[*DynamicFeature]) {
	var (
		db      *statedb.DB
		dcTable statedb.RWTable[dynamicconfig.DynamicConfig]
		tlTable statedb.RWTable[*DynamicFeature]
	)

	h := hive.New(
		cell.Provide(
			dynamicconfig.NewConfigTable,
			func(table statedb.RWTable[dynamicconfig.DynamicConfig]) statedb.Table[dynamicconfig.DynamicConfig] {
				return table
			},
			func(table statedb.RWTable[*DynamicFeature]) statedb.Table[*DynamicFeature] {
				return table
			},
			func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
				h := p.ForModule(cell.FullModuleID{"test"})
				return jr.NewGroup(h, lc)
			},
			func() config {
				return config{
					EnableDynamicLifecycleManager: true,
					DynamicLifecycleConfig:        "",
				}
			},
			func() dynamicconfig.Config {
				return dynamicconfig.Config{
					EnableDynamicConfig:    true,
					ConfigSources:          "",
					ConfigSourcesOverrides: "",
				}
			},
			newDynamicFeatureTable,
			newOps,
		),
		cell.Invoke(
			registerWatcher,
			registerReconciler,
			func(tdc statedb.RWTable[dynamicconfig.DynamicConfig], ttl statedb.RWTable[*DynamicFeature], db_ *statedb.DB) error {
				dcTable = tdc
				tlTable = ttl
				db = db_
				return nil
			},
		),
	)

	ctx := context.Background()
	tLog := hivetest.Logger(t)
	if err := h.Start(tLog, ctx); err != nil {
		t.Fatalf("starting hive encountered: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(tLog, ctx); err != nil {
			t.Fatalf("stopping hive encountered: %s", err)
		}
	})

	return h, db, dcTable, tlTable
}
