// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"strings"
	"time"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type StateDBMetrics struct {
	// How long a read transaction was held.
	WriteTxnDuration metric.Vec[metric.Observer]
	// How long it took to acquire a write transaction for all tables.
	WriteTxnAcquisition metric.Vec[metric.Observer]
	// How long writers were blocked while waiting to acquire a write transaction for a specific table.
	TableContention metric.Vec[metric.Gauge]
	// The amount of objects in a given table.
	TableObjectCount metric.Vec[metric.Gauge]
	// The current revision of a given table.
	TableRevision metric.Vec[metric.Gauge]
	// The amount of delete trackers for a given table.
	TableDeleteTrackerCount metric.Vec[metric.Gauge]
	// The amount of objects in the graveyard for a given table.
	TableGraveyardObjectCount metric.Vec[metric.Gauge]
	// The lowest revision of a given table that has been processed by the graveyard garbage collector.
	TableGraveyardLowWatermark metric.Vec[metric.Gauge]
	// The time it took to clean the graveyard for a given table.
	TableGraveyardCleaningDuration metric.Vec[metric.Observer]
}

type stateDBMetricsImpl struct {
	m StateDBMetrics
}

// DeleteTrackerCount implements statedb.Metrics.
func (i stateDBMetricsImpl) DeleteTrackerCount(tableName string, numTrackers int) {
	if i.m.TableDeleteTrackerCount.IsEnabled() {
		i.m.TableDeleteTrackerCount.WithLabelValues("table", tableName).Set(float64(numTrackers))
	}
}

// GraveyardCleaningDuration implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardCleaningDuration(tableName string, duration time.Duration) {
	if i.m.TableGraveyardCleaningDuration.IsEnabled() {
		i.m.TableGraveyardCleaningDuration.WithLabelValues("table", tableName).Observe(float64(duration.Seconds()))
	}
}

// GraveyardLowWatermark implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardLowWatermark(tableName string, lowWatermark uint64) {
	if i.m.TableGraveyardLowWatermark.IsEnabled() {
		i.m.TableGraveyardLowWatermark.WithLabelValues("table", tableName).Set(float64(lowWatermark))
	}
}

// GraveyardObjectCount implements statedb.Metrics.
func (i stateDBMetricsImpl) GraveyardObjectCount(tableName string, numDeletedObjects int) {
	if i.m.TableGraveyardObjectCount.IsEnabled() {
		i.m.TableGraveyardObjectCount.WithLabelValues("table", tableName).Set(float64(numDeletedObjects))
	}
}

// ObjectCount implements statedb.Metrics.
func (i stateDBMetricsImpl) ObjectCount(tableName string, numObjects int) {
	if i.m.TableObjectCount.IsEnabled() {
		i.m.TableObjectCount.WithLabelValues("table", tableName).Set(float64(numObjects))
	}
}

// Revision implements statedb.Metrics.
func (i stateDBMetricsImpl) Revision(tableName string, revision uint64) {
	if i.m.TableRevision.IsEnabled() {
		i.m.TableRevision.WithLabelValues("table", tableName).Set(float64(revision))
	}
}

// WriteTxnDuration implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnDuration(handle string, tables []string, acquire time.Duration) {
	if i.m.WriteTxnDuration.IsEnabled() {
		i.m.WriteTxnDuration.WithLabelValues(
			"handle", handle,
			"tables", strings.Join(tables, ","),
		).Observe(acquire.Seconds())
	}
}

// WriteTxnTableAcquisition implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnTableAcquisition(handle string, tableName string, acquire time.Duration) {
	if i.m.TableContention.IsEnabled() {
		i.m.TableContention.WithLabelValues(
			"handle", handle,
			"table", tableName,
		)
	}
}

// WriteTxnTotalAcquisition implements statedb.Metrics.
func (i stateDBMetricsImpl) WriteTxnTotalAcquisition(handle string, tables []string, acquire time.Duration) {
	if i.m.WriteTxnAcquisition.IsEnabled() {
		i.m.WriteTxnAcquisition.WithLabelValues(
			"handle", handle,
			"tables", strings.Join(tables, ","),
		)
	}
}

var _ statedb.Metrics = stateDBMetricsImpl{}

func NewStateDBMetrics() (StateDBMetrics, statedb.Metrics) {
	m := StateDBMetrics{
		WriteTxnDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "write_txn_duration_seconds",
			Help:      "How long a write transaction was held.",
			Disabled:  true,
		}, []string{"tables", "handle"}),
		WriteTxnAcquisition: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "write_txn_acquisition_seconds",
			Help:      "How long it took to acquire a write transaction for all tables.",
			Disabled:  true,
		}, []string{"tables", "handle"}),
		TableContention: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_contention_seconds",
			Help:      "How long writers were blocked while waiting to acquire a write transaction for a specific table.",
			Disabled:  true,
		}, []string{"table"}),
		TableObjectCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_objects",
			Help:      "The amount of objects in a given table.",
			Disabled:  true,
		}, []string{"table"}),
		TableRevision: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_revision",
			Help:      "The current revision of a given table.",
			Disabled:  true,
		}, []string{"table"}),
		TableDeleteTrackerCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_delete_trackers",
			Help:      "The amount of delete trackers for a given table.",
			Disabled:  true,
		}, []string{"table"}),
		TableGraveyardObjectCount: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_objects",
			Help:      "The amount of objects in the graveyard for a given table.",
			Disabled:  true,
		}, []string{"table"}),
		TableGraveyardLowWatermark: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_low_watermark",
			Help:      "The lowest revision of a given table that has been processed by the graveyard garbage collector.",
			Disabled:  true,
		}, []string{"table"}),
		TableGraveyardCleaningDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumAgentNamespace,
			Subsystem: "statedb",
			Name:      "table_graveyard_cleaning_duration_seconds",
			Help:      "The time it took to clean the graveyard for a given table.",
			Disabled:  true,
		}, []string{"table"}),
	}
	return m, stateDBMetricsImpl{m}
}
