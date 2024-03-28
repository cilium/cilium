// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mockmaps

import (
	"github.com/cilium/cilium/pkg/maps/ratelimitmetricsmap"
)

// RatelimitMetricsRecord designates a map entry (key + value).
// This type is used for mock maps.
type RatelimitMetricsRecord struct {
	Key   ratelimitmetricsmap.Key
	Value ratelimitmetricsmap.Value
}

// RatelimitMetricsMockMap implements the RatelimitMetricsMap interface and can be used for unit tests.
type RatelimitMetricsMockMap struct {
	Entries []RatelimitMetricsRecord
}

// NewRatelimitMetricsMockMap is a constructor for a MetricsMockMap.
func NewRatelimitMetricsMockMap(records []MetricsRecord) *MetricsMockMap {
	m := &MetricsMockMap{}
	m.Entries = records
	return m
}

// DumpWithCallback runs the callback on each entry of the mock map.
func (m *RatelimitMetricsMockMap) DumpWithCallback(cb ratelimitmetricsmap.DumpCallback) error {
	if cb == nil {
		return nil
	}

	for _, e := range m.Entries {
		cb(&e.Key, &e.Value)
	}

	return nil
}
