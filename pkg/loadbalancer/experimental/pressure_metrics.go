// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
)

type pressureMetricsParams struct {
	cell.In

	JobGroup        job.Group
	MetricsRegistry *metrics.Registry
	DB              *statedb.DB
	Frontends       statedb.Table[*Frontend]
	Backends        statedb.Table[*Backend]
	Config          Config
	LBMaps          LBMaps
}

type pressureMetrics struct {
	pressureMetricsParams

	bpfMaps *BPFLBMaps
	gauges  map[string]*metrics.GaugeWithThreshold
}

func registerPressureMetricsReporter(p pressureMetricsParams) {
	if !p.Config.EnableExperimentalLB || p.Config.LBPressureMetricsInterval == 0 {
		return
	}

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
	updateInterval := p.Config.LBPressureMetricsInterval
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
	var errs error

	// openMaps is immutable after Start(), so safe to access here.
	for name, m := range pm.bpfMaps.openMaps {
		if ctx.Err() != nil {
			break
		}
		if count, err := m.Count(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("count on %s failed: %w", name, err))
		} else {
			pm.getGauge(name).Set(
				float64(count) / float64(m.MaxEntries()),
			)
		}
	}
	return nil
}
