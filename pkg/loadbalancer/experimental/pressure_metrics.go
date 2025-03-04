// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

type pressureMetricsParams struct {
	cell.In

	JobGroup        job.Group
	MetricsRegistry *metrics.Registry
	DB              *statedb.DB
	Frontends       statedb.Table[*Frontend]
	Backends        statedb.Table[*Backend]
	ExtConfig       ExternalConfig
	TestConfig      *TestConfig `optional:"true"`
	LBMaps          LBMaps
}

type pressureMetrics struct {
	pressureMetricsParams

	bpfMaps *BPFLBMaps
	gauges  map[string]*metrics.GaugeWithThreshold
}

func registerPressureMetricsReporter(p pressureMetricsParams) {
	bpfMaps, ok := p.LBMaps.(*BPFLBMaps)
	if !ok {
		return
	}

	pm := &pressureMetrics{
		pressureMetricsParams: p,
		gauges:                map[string]*metrics.GaugeWithThreshold{},
		bpfMaps:               bpfMaps,
	}

	// Update the metrics only once every 5 minutes as we need to iterate over all
	// keys in each map to extract the count. If we're testing update the metrics
	// frequently.
	updateInterval := 5 * time.Minute
	if pm.TestConfig != nil {
		updateInterval = 10 * time.Millisecond
	}
	p.JobGroup.Add(job.Timer(
		"pressure-metrics-reporter",
		pm.report,
		updateInterval,
	))
}

func (pm *pressureMetrics) getGauge(mapName string) *metrics.GaugeWithThreshold {
	mapName = strings.TrimPrefix(mapName, metrics.Namespace+"_")
	if g, found := pm.gauges[mapName]; found {
		return g
	}
	// Create a new metric. This will be registered/unregistered on-demand based on
	// the threshold. E.g. if map pressure is 0.0 it won't appear in metrics.
	g := pm.MetricsRegistry.NewBPFMapPressureGauge(mapName, 0.0)
	pm.gauges[mapName] = g
	return g
}

func (pm *pressureMetrics) report(ctx context.Context) error {
	// openMaps is immutable after Start(), so safe to access here.
	for name, m := range pm.bpfMaps.openMaps {
		if ctx.Err() != nil {
			break
		}
		pm.getGauge(name).Set(
			float64(m.Count()) / float64(m.MaxEntries()),
		)
	}
	return nil
}
