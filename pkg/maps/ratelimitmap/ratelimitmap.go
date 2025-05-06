// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ratelimitmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"ratelimitmap",
	"eBPF Ratelimit Map",
	cell.Provide(newRatelimitMap),
	cell.Provide(newRatelimitMetricsMap),
	cell.Invoke(RegisterCollector),
)

// DumpCallback represents the signature of the callback function expected by
// the DumpWithCallback method, which in turn is used to iterate all the
// keys/values of a ratelimit metrics map.
type DumpCallback func(*MetricsKey, *MetricsValue)

// RatelimitMetricsMap interface represents a ratelimit metrics map, and can be reused
// to implement mock maps for unit tests.
type RatelimitMetricsMap interface {
	DumpWithCallback(DumpCallback) error
}

type ratelimitMetricsMap struct {
	*bpf.Map
}

type ratelimitMap struct {
	*bpf.Map
}

const (
	// MetricsMapName for ratelimit metrics map.
	MetricsMapName = "cilium_ratelimit_metrics"
	// MapName for ratelimit map.
	MapName = "cilium_ratelimit"
	// MetricsMaxEntries is the maximum number of keys that can be present in
	// the Ratelimit Metrics Map.
	MaxMetricsEntries = 64
	// MaxEntries is the maximum number of keys that can be present in the
	// Ratelimit Map.
	MaxEntries = 1024
)

// usageType represents source of ratelimiter usage in datapath code.
type usageType uint32

const (
	// keep in sync with defines in <bpf/lib/ratelimit.h>
	ICMPV6 usageType = iota + 1
	EVENTS_MAP
)

func (t usageType) String() string {
	switch t {
	case ICMPV6:
		return "icmpv6"
	case EVENTS_MAP:
		return "events"
	}

	return ""
}

// Key must be in sync with struct ratelimit_key in <bpf/lib/ratelimit.h>
type Key struct {
	Usage usageType `align:"usage"`
	Key   uint32    `align:"key"`
}

func (k *Key) New() bpf.MapKey {
	return &Key{}
}

func (k *Key) String() string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("%d", k.Usage)
}

// Value must be in sync with struct ratelimit_value in <bpf/lib/ratelimit.h>
type Value struct {
	LastTopup uint64 `align:"last_topup"`
	Tokens    uint64 `align:"tokens"`
}

func (v *Value) New() bpf.MapValue {
	return &Value{}
}

func (v *Value) String() string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d %d", v.LastTopup, v.Tokens)
}

// MetricsKey must be in sync with struct ratelimit_metrics_key in <bpf/lib/ratelimit.h>
type MetricsKey struct {
	Usage usageType `align:"usage"`
}

func (k *MetricsKey) New() bpf.MapKey {
	return &MetricsKey{}
}

func (k *MetricsKey) String() string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("%d", k.Usage)
}

// MetricsValue must be in sync with struct ratelimit_metrics_value in <bpf/lib/ratelimit.h>
type MetricsValue struct {
	Dropped uint64 `align:"dropped"`
}

func (v *MetricsValue) New() bpf.MapValue {
	return &MetricsValue{}
}

func (v *MetricsValue) String() string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", v.Dropped)
}

// DumpWithCallback iterates through all the keys/values of the ratelimit metrics map,
// passing each key/value pair to the cb callback
func (rm ratelimitMetricsMap) DumpWithCallback(cb DumpCallback) error {
	return rm.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*MetricsKey)
		value := v.(*MetricsValue)
		cb(key, value)
	})
}

// ratelimitMetricsMapCollector implements Prometheus Collector interface
type ratelimitMetricsMapCollector struct {
	logger *slog.Logger

	mutex lock.Mutex

	droppedDesc         *prometheus.Desc
	droppedMap          map[usageType]float64
	ratelimitMetricsMap *ratelimitMetricsMap
}

func newRatelimitMetricsMapCollector(logger *slog.Logger, ratelimitMetricsMap *ratelimitMetricsMap) *ratelimitMetricsMapCollector {
	return &ratelimitMetricsMapCollector{
		logger:     logger,
		droppedMap: make(map[usageType]float64),
		droppedDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "bpf_ratelimit_dropped_total"),
			"Total drops resulting from BPF ratelimiter, tagged by source of drop",
			[]string{"usage"}, nil,
		),
		ratelimitMetricsMap: ratelimitMetricsMap,
	}
}

func (rc *ratelimitMetricsMapCollector) Collect(ch chan<- prometheus.Metric) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	err := rc.ratelimitMetricsMap.DumpWithCallback(func(k *MetricsKey, val *MetricsValue) {
		rc.droppedMap[k.Usage] = float64(val.Dropped)
	})
	if err != nil {
		rc.logger.Warn("Failed to read ratelimit metrics from BPF map", logfields.Error, err)
		// Do not update partial metrics
		return
	}

	for usage, val := range rc.droppedMap {
		rc.updateCounterMetric(rc.droppedDesc, ch, val, usage.String())
	}
}

func (rc *ratelimitMetricsMapCollector) updateCounterMetric(desc *prometheus.Desc, ch chan<- prometheus.Metric, value float64, labelValues ...string) {
	ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value, labelValues...)
}

func (rc *ratelimitMetricsMapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- rc.droppedDesc
}

func RegisterCollector(logger *slog.Logger, ratelimitMetricsMap *ratelimitMetricsMap) {
	if err := metrics.Register(newRatelimitMetricsMapCollector(logger, ratelimitMetricsMap)); err != nil {
		logger.Error(
			"Failed to register ratelimit metrics map collector to Prometheus registry. "+
				"BPF ratelimit metrics will not be collected",
			logfields.Error, err,
		)
	}
}

func newRatelimitMap(lifecycle cell.Lifecycle) bpf.MapOut[*ratelimitMap] {
	ratelimitMap := &ratelimitMap{bpf.NewMap(
		MapName,
		ebpf.LRUHash,
		&Key{},
		&Value{},
		MaxEntries,
		0,
	)}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			if err := ratelimitMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to init ratelimit bpf map: %w", err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			if err := ratelimitMap.Close(); err != nil {
				return fmt.Errorf("failed to close ratelimit bpf map: %w", err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(ratelimitMap)
}

func newRatelimitMetricsMap(lifecycle cell.Lifecycle) bpf.MapOut[*ratelimitMetricsMap] {
	// ratelimitMetrics is the bpf ratelimit metrics map.
	ratelimitMetricsMap := &ratelimitMetricsMap{bpf.NewMap(
		MetricsMapName,
		ebpf.Hash,
		&MetricsKey{},
		&MetricsValue{},
		MaxMetricsEntries,
		0,
	)}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			if err := ratelimitMetricsMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to init ratelimit metrics bpf map: %w", err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			if err := ratelimitMetricsMap.Close(); err != nil {
				return fmt.Errorf("failed to close ratelimit metrics bpf map: %w", err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(ratelimitMetricsMap)
}
