// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metricOpCreate     = "create"
	metricOpUpdate     = "update"
	metricOpLookup     = "lookup"
	metricOpDelete     = "delete"
	metricOpGetNextKey = "getNextKey"
)

const (
	tablePressureMetricsInterval = 30 * time.Second // Interval for updating the pressure gauge
)

type mapPressureMetricsOps interface {
	IsOpen() bool
	NonPrefixedName() string
	MaxEntries() uint32
}

// RegisterTablePressureMetricsJob adds a timer job to track the map pressure of a BPF map
// where the desired state is stored in a StateDB table.
//
// Example usage:
//
//	type myBPFMap struct { *bpf.Map }
//	cell.Invoke(
//	  bpf.RegisterTablePressureMetricsJob[MyObj, myBPFMap],
//	)
func RegisterTablePressureMetricsJob[Obj any, Map mapPressureMetricsOps](g job.Group, registry *metrics.Registry, db *statedb.DB, table statedb.Table[Obj], m Map) {
	name := m.NonPrefixedName()
	var pressureGauge *metrics.GaugeWithThreshold
	g.Add(job.Timer(
		"pressure-metric-"+name,
		func(context.Context) error {
			if !m.IsOpen() {
				// Map not opened, do nothing.
				return nil
			}

			if pressureGauge == nil {
				pressureGauge = registry.NewBPFMapPressureGauge(name, 0.0)
			}

			txn := db.ReadTxn()
			pressureGauge.Set(float64(table.NumObjects(txn)) / float64(m.MaxEntries()))
			return nil
		},
		tablePressureMetricsInterval,
	))

}
