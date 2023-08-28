// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metricsmap

import (
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var Cell = cell.Module(
	"metricsmap",
	"eBPF Metrics Map",
	cell.Invoke(RegisterCollector),
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
	Metrics = metricsMap{ebpf.NewMap(&ebpf.MapSpec{
		Name:       MapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    uint32(unsafe.Sizeof(Key{})),
		ValueSize:  uint32(unsafe.Sizeof(Value{})),
		MaxEntries: MaxEntries,
		Pinning:    ebpf.PinByName,
	})}
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-metrics")
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

// metricsMapCollector implements Prometheus Collector interface
type metricsmapCollector struct {
	droppedCountDesc *prometheus.Desc
	droppedByteDesc  *prometheus.Desc
	forwardCountDesc *prometheus.Desc
	forwardByteDesc  *prometheus.Desc

	// eBPF code seems to expose multiple reasons for forwarded metrics
	// as opposed to what is stated in bpf/lib/metrics.h comments.
	// IterateWithCallback iterates through BPF map for each reason and direction.
	// Since we do not have "reason" label on forwarded metrics, we would end up collecting
	// same forwarded metric multiple times which is not allowed by prometheus client.
	// See https://github.com/prometheus/client_golang/issues/242
	//
	// promMetrics is a generic map used to sum all values by desired set of labels
	// for both forwarded and dropped metrics
	forwardedMetricsMap promMetrics[forwardLabels]
	droppedMetricsMap   promMetrics[dropLabels]
}

func newMetricsMapCollector() prometheus.Collector {
	return &metricsmapCollector{
		droppedMetricsMap:   make(map[dropLabels]metricValues),
		forwardedMetricsMap: make(map[forwardLabels]metricValues),
		droppedByteDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "drop_bytes_total"),
			"Total dropped bytes, tagged by drop reason and ingress/egress direction",
			[]string{metrics.LabelDropReason, metrics.LabelDirection}, nil,
		),
		droppedCountDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "drop_count_total"),
			"Total dropped packets, tagged by drop reason and ingress/egress direction",
			[]string{metrics.LabelDropReason, metrics.LabelDirection}, nil,
		),
		forwardCountDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "forward_count_total"),
			"Total forwarded packets, tagged by ingress/egress direction",
			[]string{metrics.LabelDirection}, nil,
		),
		forwardByteDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "forward_bytes_total"),
			"Total forwarded bytes, tagged by ingress/egress direction",
			[]string{metrics.LabelDirection}, nil,
		),
	}
}

type forwardLabels struct {
	direction string
}

type dropLabels struct {
	direction string
	reason    string
}

type metricValues struct {
	bytes float64
	count float64
}

type labels comparable

type promMetrics[k labels] map[k]metricValues

func (p promMetrics[k]) upsert(labels k, values *Values) {
	if v, ok := p[labels]; ok {
		v.bytes = float64(values.Bytes())
		v.count = float64(values.Count())
	}
	p[labels] = metricValues{
		bytes: float64(values.Bytes()),
		count: float64(values.Count()),
	}
}

func (mc *metricsmapCollector) Collect(ch chan<- prometheus.Metric) {
	err := Metrics.IterateWithCallback(func(key *Key, values *Values) {
		if key.IsDrop() {
			labelSet := dropLabels{
				direction: key.Direction(),
				reason:    key.DropForwardReason(),
			}
			mc.droppedMetricsMap.upsert(labelSet, values)
		} else {
			labelSet := forwardLabels{
				direction: key.Direction(),
			}
			mc.forwardedMetricsMap.upsert(labelSet, values)
		}
	})
	if err != nil {
		log.WithError(err).Warn("Failed to read metrics from BPF map")
		// Do not update partial metrics
		return
	}

	for labels, value := range mc.forwardedMetricsMap {
		mc.updateCounterMetric(mc.forwardCountDesc, ch, value.count, labels.direction)
		mc.updateCounterMetric(mc.forwardByteDesc, ch, value.bytes, labels.direction)
	}

	for labels, value := range mc.droppedMetricsMap {
		mc.updateCounterMetric(mc.droppedCountDesc, ch, value.count, labels.reason, labels.direction)
		mc.updateCounterMetric(mc.droppedByteDesc, ch, value.bytes, labels.reason, labels.direction)
	}
}

func (mc *metricsmapCollector) updateCounterMetric(desc *prometheus.Desc, metricsChan chan<- prometheus.Metric, value float64, labelValues ...string) {
	metricsChan <- prometheus.MustNewConstMetric(
		desc,
		prometheus.CounterValue,
		value,
		labelValues...)
}

func (mc *metricsmapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mc.forwardByteDesc
	ch <- mc.forwardCountDesc
	ch <- mc.droppedCountDesc
	ch <- mc.droppedByteDesc
}

func RegisterCollector() {
	if err := metrics.Register(newMetricsMapCollector()); err != nil {
		log.WithError(err).Error("Failed to register metrics map collector to Prometheus registry. " +
			"cilium_datapath_drop/forward metrics will not be collected")
	}
}
