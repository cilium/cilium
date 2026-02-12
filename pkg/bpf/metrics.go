// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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

var errMapDisabled = errors.New("nil pointer provided to Hive, map disabled")

// validProvidedMap returns [errMapDisabled] if the provided Map is a nil
// pointer. If it's not a pointer, check if it's the zero value of its type and
// return an error if so. Otherwise, return nil.
func validProvidedMap[Map mapPressureMetricsOps](m Map) error {
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return errMapDisabled
		}
	default:
		if v.IsZero() {
			return fmt.Errorf("provided a zero %T", m)
		}
	}

	return nil
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
//
// The provided [Map] must be a non-nil pointer or a non-zero value.
//
// If m is a non-nil pointer, its *bpf.Map may be populated later when the Hive
// is started. If m itself is nil, the Map is considered disabled and no job
// will be registered.
//
// If m is provided by-value and has a zero value, like a struct wrapping a nil
// *bpf.Map, an error is returned. Since m was passed by-value, it can no longer
// be populated during Hive startup.
func RegisterTablePressureMetricsJob[Obj any, Map mapPressureMetricsOps](g job.Group, registry *metrics.Registry, db *statedb.DB, table statedb.Table[Obj], m Map) error {
	err := validProvidedMap(m)
	if errors.Is(err, errMapDisabled) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid provided map: %w", err)
	}

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

	return nil
}
