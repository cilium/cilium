// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metricsmap

import (
	"fmt"
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"

	"github.com/prometheus/client_golang/prometheus"
)

var log = logging.DefaultLogger

const (
	// MapName for metrics map.
	MapName = "cilium_metrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// Metrics Map.
	MaxEntries = 65536
	// dirIngress and dirEgress values should match with
	// METRIC_INGRESS and METRIC_EGRESS in bpf/lib/common.h
	dirIngress = 1
	dirEgress  = 2
	dirUnknown = 0
)

// direction is the metrics direction i.e ingress (to an endpoint)
// or egress (from an endpoint). If it's none of the above, we return
// UNKNOWN direction.
var direction = map[uint8]string{
	0: "UNKNOWN",
	1: "INGRESS",
	2: "EGRESS",
}

// Key must be in sync with struct metrics_key in <bpf/lib/common.h>
type Key struct {
	Reason uint8
	Dir    uint8
	Pad1   uint16
	Pad2   uint32
}

// Value must be in sync with struct metrics_value in <bpf/lib/common.h>
type Value struct {
	Count uint64
	Bytes uint64
}

// String converts the key into a human readable string format
func (k *Key) String() string {
	return fmt.Sprintf("reason:%d dir:%d", k.Reason, k.Dir)
}

// Direction gets the direction in human readable string format
func (k *Key) Direction() string {
	switch k.Dir {
	case dirIngress:
		return direction[k.Dir]
	case dirEgress:
		return direction[k.Dir]
	}
	return direction[dirUnknown]
}

// DropForwardReason gets the forwarded/dropped reason in human readable string format
func (k *Key) DropForwardReason() string {
	return monitor.DropReason(k.Reason)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// String converts the value into a human readable string format
func (v *Value) String() string {
	return fmt.Sprintf("count:%d bytes:%d", v.Count, v.Bytes)
}

// RequestCount returns the drop/forward count in a human readable string format
func (v *Value) RequestCount() string {
	return strconv.FormatUint(v.Count, 10)
}

// RequestBytes returns drop/forward bytes in a human readable string format
func (v *Value) RequestBytes() string {
	return strconv.FormatUint(v.Bytes, 10)
}

// IsDrop checks if the reason is drop or not.
func (k *Key) IsDrop() bool {
	return k.Reason != 0
}

// CountFloat converts the request count to float
func (v *Value) CountFloat() float64 {
	return float64(v.Count)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *Key) NewValue() bpf.MapValue { return &Value{} }

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

var (
	// Metrics is a mapping of all packet drops and forwards associated with
	// the node on ingress/egress direction
	Metrics = bpf.NewMap(
		MapName,
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(Key{})),
		int(unsafe.Sizeof(Value{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := Key{}, Value{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return &k, &v, nil
		})
)

// updatePrometheusMetrics checks the metricsmap key value pair
// and determines which prometheus metrics along with respective labels
// need to be updated.
func updatePrometheusMetrics(key *Key, val *Value) {
	var counter prometheus.Counter
	var err error
	if key.IsDrop() {
		counter, err = metrics.DropCount.GetMetricWithLabelValues(key.DropForwardReason(), key.Direction())
	} else {
		counter, err = metrics.ForwardCount.GetMetricWithLabelValues(key.Direction())
	}
	if err != nil {
		log.WithError(err).Warn("Failed to update prometheus metrics")
		return
	}
	oldValue := metrics.GetCounterValue(counter)
	newValue := val.CountFloat()
	// Check if metrics have changed since the last poll.
	// If yes, we need to add only the delta.
	if newValue > oldValue {
		if key.IsDrop() {
			metrics.DropCount.WithLabelValues(key.DropForwardReason(), key.Direction()).Add((newValue - oldValue))
		} else {
			metrics.ForwardCount.WithLabelValues(key.Direction()).Add((newValue - oldValue))
		}
	}
}

// SyncMetricsMap is called periodically to sync off the metrics map by
// aggregating it into drops (by drop reason and direction) and
// forwards (by direction) with the prometheus server.
func SyncMetricsMap() error {
	file := bpf.MapPath(MapName)
	metricsmap, err := bpf.OpenMap(file)

	if err != nil {
		return fmt.Errorf("unable to open metrics map: %s", err)
	}
	defer metricsmap.Close()

	var key, nextKey Key
	for {
		err := metricsmap.GetNextKey(&key, &nextKey)
		if err != nil {
			break
		}
		entry, err := metricsmap.Lookup(&nextKey)
		if err != nil {
			return fmt.Errorf("unable to lookup metrics map: %s", err)
		}
		value := entry.(*Value)
		// Increment Prometheus metrics here.
		updatePrometheusMetrics(&nextKey, value)
		key = nextKey
	}
	return nil
}

func init() {
	err := bpf.OpenAfterMount(Metrics)
	if err != nil {
		log.WithError(err).Error("unable to open metrics map")
	}
}
