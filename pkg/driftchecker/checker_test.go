// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driftchecker

import (
	"context"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestWatchTableChanges(t *testing.T) {
	tests := []struct {
		name          string
		cellSettings  map[string]any
		table         map[string]string
		expectedCount int
		expectedValue float64
	}{
		{
			name:          "No mismatches",
			cellSettings:  map[string]any{"key": "value"},
			table:         map[string]string{"key": "value"},
			expectedCount: 1,
			expectedValue: 0,
		},
		{
			name:          "Missing Key",
			table:         map[string]string{"key2": "value"},
			expectedCount: 1,
			expectedValue: 1,
		},
		{
			name:          "Value missmatch",
			cellSettings:  map[string]any{"key": "other_value"},
			table:         map[string]string{"key": "value"},
			expectedCount: 1,
			expectedValue: 1,
		},
		{
			name:          "Key missmatch",
			cellSettings:  map[string]any{"key2": "value"},
			table:         map[string]string{"key": "value"},
			expectedCount: 1,
			expectedValue: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, db, s, m := fixture(t, tt.cellSettings)
			for k, v := range tt.table {
				upsertEntry(db, s, k, v)
			}

			if err := testutils.WaitUntil(func() bool {
				return prometheustestutil.CollectAndCount(m.DriftCheckerConfigDelta) > 0
			}, 5*time.Second); err != nil {
				t.Errorf("expected DriftCheckerConfigDelta to be collected, but got error: %v", err)
			}

			if err := testutils.WaitUntil(func() bool {
				return prometheustestutil.ToFloat64(m.DriftCheckerConfigDelta) == tt.expectedValue
			}, 5*time.Second); err != nil {
				t.Errorf("expected DriftCheckerConfigDelta to be %f, but got error: %v", tt.expectedValue, err)
			}

		})
	}

}

func TestComputeDelta(t *testing.T) {
	tests := []struct {
		name     string
		desired  map[string]dynamicconfig.DynamicConfig
		actual   cell.AllSettings
		ignored  []string
		expected []string
	}{
		{
			name: "No mismatches",
			desired: map[string]dynamicconfig.DynamicConfig{
				"key1": newDynamicConfig("key1", "value1"),
				"key2": newDynamicConfig("key2", "123"),
			},
			actual: cell.AllSettings{
				"key1": "value1",
				"key2": 123,
			},
			ignored:  []string{},
			expected: nil,
		},
		{
			name: "Mismatches present",
			desired: map[string]dynamicconfig.DynamicConfig{
				"key1": newDynamicConfig("key1", "value1"),
				"key2": newDynamicConfig("key2", "123"),
				"key3": newDynamicConfig("key3", "true"),
			},
			actual: cell.AllSettings{
				"key1": "value1",
				"key2": 456,
			},
			ignored: []string{},
			expected: []string{
				"Mismatch for key [key2]: expecting \"123\" but got \"456\"",
				"No entry found for key: [key3]",
			},
		},
		{
			name: "Ignored flags",
			desired: map[string]dynamicconfig.DynamicConfig{
				"key1": newDynamicConfig("key1", "value1"),
				"key2": newDynamicConfig("key2", "123"),
			},
			actual: cell.AllSettings{
				"key1": "different_value",
			},
			ignored:  []string{"key1"},
			expected: []string{"No entry found for key: [key2]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := checker{
				l:            slog.Default(),
				ignoredFlags: sets.New[string](tt.ignored...),
			}
			result := c.computeDelta(tt.desired, tt.actual)
			if !reflect.DeepEqual(tt.expected, result) {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}

func newDynamicConfig(key string, value string) dynamicconfig.DynamicConfig {
	return dynamicconfig.DynamicConfig{
		Key: dynamicconfig.Key{
			Name:   key,
			Source: "kube-system",
		},
		Value:    value,
		Priority: 0,
	}
}

func upsertEntry(db *statedb.DB, table statedb.RWTable[dynamicconfig.DynamicConfig], k string, v string) {
	txn := db.WriteTxn(table)
	defer txn.Commit()

	entry := dynamicconfig.DynamicConfig{Key: dynamicconfig.Key{Name: k, Source: "kube-system"}, Value: v, Priority: 0}
	_, _, _ = table.Insert(txn, entry)
}

func fixture(t *testing.T, cellAllSettings map[string]any) (*hive.Hive, *statedb.DB, statedb.RWTable[dynamicconfig.DynamicConfig], Metrics) {
	var (
		db    *statedb.DB
		table statedb.RWTable[dynamicconfig.DynamicConfig]
		m     Metrics
	)

	h := hive.New(
		k8sClient.FakeClientCell,
		metrics.Metric(MetricsProvider),
		cell.Provide(
			dynamicconfig.NewConfigTable,
			func(table statedb.RWTable[dynamicconfig.DynamicConfig]) statedb.Table[dynamicconfig.DynamicConfig] {
				return table
			},
			func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
				h := p.ForModule(cell.FullModuleID{"test"})
				jg := jr.NewGroup(h)
				lc.Append(jg)
				return jg
			},
			func() config {
				return config{
					EnableDriftChecker:      true,
					IgnoreFlagsDriftChecker: nil,
				}
			},
			func() dynamicconfig.Config {
				return dynamicconfig.Config{
					EnableDynamicConfig:    true,
					ConfigSources:          "",
					ConfigSourcesOverrides: "",
				}
			},
		),
		cell.Invoke(
			func(params checkerParams) {
				params.CellAllSettings = cellAllSettings
				Register(params)
			},
			func(t statedb.RWTable[dynamicconfig.DynamicConfig], db_ *statedb.DB, c *k8sClient.FakeClientset, metrics_ Metrics) error {
				table = t
				db = db_
				m = metrics_
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

	return h, db, table, m
}
