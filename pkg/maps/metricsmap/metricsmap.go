// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metricsmap

import (
	"context"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a metrics map.
type IterateCallback func(*Key, *Values)

// MetricsMap interface represents a metrics map, and can be reused to implement
// mock maps for unit tests.
type MetricsMap interface {
	IterateWithCallback(IterateCallback) error
}

type metricsMap struct {
	*ebpf.Map
}

var (
	// Metrics is the bpf metrics map
	Metrics metricsMap
	log     = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-metrics")
)

const (
	// MapName for metrics map.
	MapName = "cilium_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Metrics Map.
	//
	// Currently max. 2 bits of the Key.Dir member are used (unknown,
	// ingress or egress). Thus we can reduce from the theoretical max. size
	// of 2**16 (2 uint8) to 2**10 (1 uint8 + 2 bits).
	MaxEntries = 1024
	// dirIngress and dirEgress values should match with
	// METRIC_INGRESS, METRIC_EGRESS and METRIC_SERVICE
	// in bpf/lib/common.h
	dirUnknown = 0
	dirIngress = 1
	dirEgress  = 2
	dirService = 3
)

// direction is the metrics direction i.e ingress (to an endpoint),
// egress (from an endpoint) or service (NodePort service being accessed from
// outside or a ClusterIP service being accessed from inside the cluster).
// If it's none of the above, we return UNKNOWN direction.
var direction = map[uint8]string{
	dirUnknown: "UNKNOWN",
	dirIngress: "INGRESS",
	dirEgress:  "EGRESS",
	dirService: "SERVICE",
}

// Key must be in sync with struct metrics_key in <bpf/lib/common.h>
type Key struct {
	Reason   uint8     `align:"reason"`
	Dir      uint8     `align:"dir"`
	Reserved [3]uint16 `align:"reserved"`
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type Value struct {
	Count uint64 `align:"count"`
	Bytes uint64 `align:"bytes"`
}

// Values is a slice of Values
type Values []Value

// IterateWithCallback iterates through all the keys/values of a metrics map,
// passing each key/value pair to the cb callback
func (m metricsMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.IterateWithCallback(&Key{}, &Values{}, func(k, v interface{}) {
		key := k.(*Key)
		values := v.(*Values)

		cb(key, values)
	})
}

// MetricDirection gets the direction in human readable string format
func MetricDirection(dir uint8) string {
	if desc, ok := direction[dir]; ok {
		return desc
	}
	return direction[dirUnknown]
}

// Direction gets the direction in human readable string format
func (k *Key) Direction() string {
	return MetricDirection(k.Dir)
}

// DropForwardReason gets the forwarded/dropped reason in human readable string format
func (k *Key) DropForwardReason() string {
	return monitorAPI.DropReason(k.Reason)
}

// IsDrop checks if the reason is drop or not.
func (k *Key) IsDrop() bool {
	return k.Reason == monitorAPI.DropInvalid || k.Reason >= monitorAPI.DropMin
}

// Count returns the sum of all the per-CPU count values
func (vs Values) Count() uint64 {
	c := uint64(0)
	for _, v := range vs {
		c += v.Count
	}

	return c
}

// Bytes returns the sum of all the per-CPU bytes values
func (vs Values) Bytes() uint64 {
	b := uint64(0)
	for _, v := range vs {
		b += v.Bytes
	}

	return b
}

func updateMetric(getCounter func() (prometheus.Counter, error), newValue float64) {
	counter, err := getCounter()
	if err != nil {
		log.WithError(err).Warn("Failed to update prometheus metrics")
		return
	}

	oldValue := metrics.GetCounterValue(counter)
	if newValue > oldValue {
		counter.Add(newValue - oldValue)
	}
}

// updatePrometheusMetrics checks the metricsmap key value pair
// and determines which prometheus metrics along with respective labels
// need to be updated.
func updatePrometheusMetrics(key *Key, values *Values) {
	updateMetric(func() (prometheus.Counter, error) {
		if key.IsDrop() {
			return metrics.DropCount.GetMetricWithLabelValues(key.DropForwardReason(), key.Direction())
		}
		return metrics.ForwardCount.GetMetricWithLabelValues(key.Direction())
	}, float64(values.Count()))

	updateMetric(func() (prometheus.Counter, error) {
		if key.IsDrop() {
			return metrics.DropBytes.GetMetricWithLabelValues(key.DropForwardReason(), key.Direction())
		}
		return metrics.ForwardBytes.GetMetricWithLabelValues(key.Direction())
	}, float64(values.Bytes()))
}

// SyncMetricsMap is called periodically to sync off the metrics map by
// aggregating it into drops (by drop reason and direction) and
// forwards (by direction) with the prometheus server.
func SyncMetricsMap(ctx context.Context) error {
	return Metrics.IterateWithCallback(func(key *Key, values *Values) {
		updatePrometheusMetrics(key, values)
	})
}

func init() {
	Metrics.Map = ebpf.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    uint32(unsafe.Sizeof(Key{})),
		ValueSize:  uint32(unsafe.Sizeof(Value{})),
		MaxEntries: MaxEntries,
		Pinning:    ebpf.PinByName,
	})
}
