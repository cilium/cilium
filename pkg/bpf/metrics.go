// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"
	"reflect"

	"github.com/cilium/hive/cell"
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

// isZeroValue returns an error if the provided value is a nil pointer or if its
// underlying type has the zero value. Otherwise, it returns nil.
//
// This is mainly useful for validating interface values, since we cannot
// enforce interfaces being implemented with pointer receivers.
func isZeroValue(m any) error {
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Invalid:
		return fmt.Errorf("provided a nil interface")
	case reflect.Pointer:
		if v.IsNil() {
			return fmt.Errorf("provided a nil %T", m)
		}
	default:
		if v.IsZero() {
			return fmt.Errorf("provided a zero %T", m)
		}
	}

	return nil
}

func jobName(name string) string {
	return "pressure-metric-" + name
}

// TablePressureMetrics adds a timer job to track the map pressure of a BPF map
// where the desired state is stored in a StateDB table.
//
// Example usage:
//
//	type myBPFMap struct { *bpf.Map }
//	cell.Invoke(
//	  bpf.TablePressureMetrics[MyObj, myBPFMap],
//	)
//
// The provided map must be a non-nil pointer or a non-zero value.
//
// If m is a non-nil pointer, its *bpf.Map may be populated later when the Hive
// is started.
//
// If m is provided by-value and has a zero value, like a struct wrapping a nil
// *bpf.Map, an error is returned. Since m was passed by-value, it can no longer
// be backfilled on Hive start.
func TablePressureMetrics[Obj any, Map mapPressureMetricsOps](
	g job.Group, registry *metrics.Registry, db *statedb.DB, table statedb.Table[Obj], m Map) error {
	if err := isZeroValue(m); err != nil {
		return fmt.Errorf("invalid provided map: %w", err)
	}

	name := m.NonPrefixedName()
	var pressureGauge *metrics.GaugeWithThreshold
	g.Add(job.Timer(jobName(name),
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

	return nil
}

// MaybeTablePressureMetrics is a wrapper around TablePressureMetrics that
// receives an optional map.
//
// If the provided map is a [NoneMap], the Map is considered disabled and the
// reconciler won't be started.
func MaybeTablePressureMetrics[Obj any, M mapPressureMetricsOps](
	g job.Group, registry *metrics.Registry, db *statedb.DB,
	table statedb.Table[Obj], mi MaybeMap[M]) error {
	m, ok := mi.Get()
	if !ok {
		g.Add(job.OneShot(jobName(m.NonPrefixedName()),
			func(_ context.Context, health cell.Health) error {
				health.OK(fmt.Sprintf("Map %s was disabled", m.NonPrefixedName()))
				return nil
			}))

		return nil
	}

	return TablePressureMetrics(g, registry, db, table, m)
}
