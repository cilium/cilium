// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
