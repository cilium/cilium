// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ratelimitmetricsmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"ratelimitmetricsmap",
	"eBPF Ratelimit Metrics Map",
	cell.Invoke(RegisterCollector),
)

// DumpCallback represents the signature of the callback function expected by
// the DumpWithCallback method, which in turn is used to iterate all the
// keys/values of a ratelimit metrics map.
type DumpCallback func(*Key, *Value)

// RatelimitMetricsMap interface represents a ratelimit metrics map, and can be reused
// to implement mock maps for unit tests.
type RatelimitMetricsMap interface {
	DumpWithCallback(DumpCallback) error
}

type ratelimitMetricsMap struct {
	*bpf.Map
}

var (
	// RatelimitMetrics is the bpf ratelimit metrics map.
	RatelimitMetrics = ratelimitMetricsMap{bpf.NewMap(
		MapName,
		ebpf.Hash,
		&Key{},
		&Value{},
		MaxEntries,
		0,
	)}
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ratelimit-map-metrics")
)

const (
	// MapName for ratelimit metrics map.
	MapName = "cilium_ratelimit_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Ratelimit Metrics Map.
	MaxEntries = 64
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

// Key must be in sync with struct ratelimit_metrics_key in <bpf/lib/ratelimit.h>
type Key struct {
	Usage usageType `align:"usage"`
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

// Value must be in sync with struct ratelimit_metrics_value in <bpf/lib/ratelimit.h>
type Value struct {
	Dropped uint64 `align:"dropped"`
}

func (v *Value) New() bpf.MapValue {
	return &Value{}
}

func (v *Value) String() string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", v.Dropped)
}

// DumpWithCallback iterates through all the keys/values of the ratelimit metrics map,
// passing each key/value pair to the cb callback
func (rm ratelimitMetricsMap) DumpWithCallback(cb DumpCallback) error {
	return rm.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*Key)
		value := v.(*Value)
		cb(key, value)
	})
}

// ratelimitMetricsMapCollector implements Prometheus Collector interface
type ratelimitMetricsMapCollector struct {
	mutex lock.Mutex

	droppedDesc *prometheus.Desc
	droppedMap  map[usageType]float64
}

func newRatelimitMetricsMapCollector() *ratelimitMetricsMapCollector {
	return &ratelimitMetricsMapCollector{
		droppedMap: make(map[usageType]float64),
		droppedDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "bpf_ratelimit_dropped_total"),
			"Total drops resulting from BPF ratelimiter, tagged by source of drop",
			[]string{"usage"}, nil,
		),
	}
}

func (rc *ratelimitMetricsMapCollector) Collect(ch chan<- prometheus.Metric) {
	rc.mutex.Lock()
	defer rc.mutex.Unlock()

	err := RatelimitMetrics.DumpWithCallback(func(k *Key, val *Value) {
		rc.droppedMap[k.Usage] = float64(val.Dropped)
	})
	if err != nil {
		log.WithError(err).Warn("Failed to read ratelimit metrics from BPF map")
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

func RegisterCollector() {
	if err := metrics.Register(newRatelimitMetricsMapCollector()); err != nil {
		log.WithError(err).Error("Failed to register ratelimit metrics map collector to Prometheus registry. " +
			"BPF ratelimit metrics will not be collected")
	}
}
