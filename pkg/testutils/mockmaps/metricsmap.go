// Copyright 2020 Authors of Cilium
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

package mockmaps

import (
	"github.com/cilium/cilium/pkg/maps/metricsmap"
)

// MetricsRecord designates a map entry (key + value).
// This type is used for mock maps.
type MetricsRecord struct {
	Key    metricsmap.Key
	Values metricsmap.Values
}

// MetricsMockMap implements the MetricsMap interface and can be used for unit tests.
type MetricsMockMap struct {
	Entries []MetricsRecord
}

// NewMetricsMockMap is a constructor for a MetricsMockMap.
func NewMetricsMockMap(records []MetricsRecord) *MetricsMockMap {
	m := &MetricsMockMap{}
	m.Entries = records
	return m
}

// DumpWithCallback runs the callback on each entry of the mock map.
func (m *MetricsMockMap) IterateWithCallback(cb metricsmap.IterateCallback) error {
	if cb == nil {
		return nil
	}

	for _, e := range m.Entries {
		cb(&e.Key, &e.Values)
	}

	return nil
}
