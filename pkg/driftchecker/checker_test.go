// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driftchecker

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
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
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Regression test: the drift checker must wait for all config source
// reflectors to initialize before computing deltas. Otherwise, it may
// report spurious mismatches when a higher-priority source (e.g.
// CiliumNodeConfig) hasn't populated the table yet.
func TestWatchTableChangesWaitsForInitialization(t *testing.T) {
	var (
		db    *statedb.DB
		table statedb.RWTable[dynamicconfig.DynamicConfig]
		m     Metrics
	)

	var initDone func(statedb.WriteTxn)

	h := hive.New(
		k8sClient.FakeClientCell(),
		metrics.Metric(MetricsProvider),
		cell.Provide(
			dynamicconfig.NewConfigTable,
			func(table statedb.RWTable[dynamicconfig.DynamicConfig]) statedb.Table[dynamicconfig.DynamicConfig] {
				return table
			},
			func() config {
				return config{EnableDriftChecker: true}
			},
			func() dynamicconfig.Config {
				return dynamicconfig.Config{EnableDynamicConfig: true}
			},
		),
		cell.Invoke(
			func(params checkerParams) {
				params.CellAllSettings = map[string]any{"datapath-mode": "veth"}
				Register(params)
			},
			func(t statedb.RWTable[dynamicconfig.DynamicConfig], db_ *statedb.DB, c *k8sClient.FakeClientset, metrics_ Metrics) error {
				table = t
				db = db_
				m = metrics_

				txn := db.WriteTxn(table)
				initDone = table.RegisterInitializer(txn, "cnc-reflector")
				txn.Commit()
				return nil
			},
		),
	)

	ctx := context.Background()
	tLog := hivetest.Logger(t)
	if err := h.Start(tLog, ctx); err != nil {
		t.Fatalf("starting hive: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(tLog, ctx); err != nil {
			t.Fatalf("stopping hive: %s", err)
		}
	})

	// Simulate the ConfigMap reflector populating first with a value that
	// differs from what the agent is running (veth vs netkit).
	upsertEntryWithSource(db, table, "datapath-mode", "netkit", "cilium-config", 2)

	// Give the drift checker time to (incorrectly) react. If the drift
	// checker fires before initialization, it would see the ConfigMap
	// mismatch and set the metric to 1.
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, float64(0), prometheustestutil.ToFloat64(m.DriftCheckerConfigDelta),
		"drift checker should not compute deltas before table is initialized")

	// Complete initialization without inserting the CNC override. The drift
	// checker should now unblock and report the mismatch.
	txn := db.WriteTxn(table)
	initDone(txn)
	txn.Commit()

	if err := testutils.WaitUntil(func() bool {
		return prometheustestutil.ToFloat64(m.DriftCheckerConfigDelta) == 1
	}, 5*time.Second); err != nil {
		t.Fatal("drift checker did not report the expected mismatch after initialization")
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
	upsertEntryWithSource(db, table, k, v, "kube-system", 0)
}

func upsertEntryWithSource(db *statedb.DB, table statedb.RWTable[dynamicconfig.DynamicConfig], k, v, source string, priority int) {
	txn := db.WriteTxn(table)
	defer txn.Commit()

	entry := dynamicconfig.DynamicConfig{Key: dynamicconfig.Key{Name: k, Source: source}, Value: v, Priority: priority}
	_, _, _ = table.Insert(txn, entry)
}

func fixture(t *testing.T, cellAllSettings map[string]any) (*hive.Hive, *statedb.DB, statedb.RWTable[dynamicconfig.DynamicConfig], Metrics) {
	var (
		db    *statedb.DB
		table statedb.RWTable[dynamicconfig.DynamicConfig]
		m     Metrics
	)

	h := hive.New(
		k8sClient.FakeClientCell(),
		metrics.Metric(MetricsProvider),
		cell.Provide(
			dynamicconfig.NewConfigTable,
			func(table statedb.RWTable[dynamicconfig.DynamicConfig]) statedb.Table[dynamicconfig.DynamicConfig] {
				return table
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
