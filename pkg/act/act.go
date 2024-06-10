// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"context"
	"fmt"
	"math"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/act"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metricsUpdateInterval = 15 * time.Second
	metricsTimeout        = 10 * time.Minute
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "act-metrics")

var Cell = cell.Module(
	"act-metrics",
	"Metrics with counts of new and active connections for each service-zone pair",

	metrics.Metric(NewActiveConnectionTrackingMetrics),
	cell.Provide(NewACT),
	cell.Invoke(func(*ACT) {}),
)

type ActiveConnectionTrackingMetrics struct {
	New, Active, Failed metric.DeletableVec[metric.Gauge]
	ProcessingTime      metric.Histogram
}

func NewActiveConnectionTrackingMetrics() ActiveConnectionTrackingMetrics {
	return ActiveConnectionTrackingMetrics{
		New: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_act_new_connections_total",
			Subsystem:  "act",
			Namespace:  metrics.Namespace,
			Name:       "new_connections_total",
		}, []string{"zone", "service"}),
		Active: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_act_active_connections_total",
			Subsystem:  "act",
			Namespace:  metrics.Namespace,
			Name:       "active_connections_total",
		}, []string{"zone", "service"}),
		Failed: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_act_failed_connections_total",
			Subsystem:  "act",
			Namespace:  metrics.Namespace,
			Name:       "failed_connections_total",
			Help:       "number of service connections purged from conntrack table",
		}, []string{"zone", "service"}),
		ProcessingTime: metric.NewHistogram(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_act_processing_time_seconds",
			Subsystem:  "act",
			Namespace:  metrics.Namespace,
			Name:       "processing_time_seconds",
			Help:       "time to go over ACT map and update the metrics",
		}),
	}
}

type actMetric struct {
	opened, closed    uint64
	newFailed, failed uint64
	updated           time.Time
	labelValues       []string
}

type ACT struct {
	src          act.ActiveConnectionTrackingMap
	metrics      ActiveConnectionTrackingMetrics
	keyToStrings func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error)

	// mux protects tracker map
	mux *lock.Mutex
	// tracker is a map[zone][svc]metric
	tracker map[uint8]map[uint16]*actMetric
}

func NewACT(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Source    act.ActiveConnectionTrackingMap
	Metrics   ActiveConnectionTrackingMetrics
}) *ACT {
	if in.Source == nil {
		// Active Connection Tracking is disabled.
		return nil
	}
	a := newAct(in.Source, in.Metrics, option.Config)
	ctx, cancel := context.WithCancel(context.Background())
	in.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			go a.run(ctx)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cancel()
			return nil
		},
	})
	ctmap.ACT = a
	return a
}

func newAct(src act.ActiveConnectionTrackingMap, metrics ActiveConnectionTrackingMetrics, opts *option.DaemonConfig) *ACT {
	tracker := make(map[uint8]map[uint16]*actMetric, len(opts.FixedZoneMapping))
	for zone := range opts.ReverseFixedZoneMapping {
		tracker[zone] = make(map[uint16]*actMetric)
	}
	kts := func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		zone = opts.GetZone(key.Zone)
		if zone == "" {
			return "", "", fmt.Errorf("resolve zone id: %w", err)
		}

		ref, err := service.GetID(uint32(byteorder.NetworkToHost16(key.SvcID)))
		if err != nil || ref == nil {
			return "", "", fmt.Errorf("resolve svc id: %w", err)
		}
		svc = ref.String()
		return
	}
	return &ACT{
		src:          src,
		metrics:      metrics,
		keyToStrings: kts,
		mux:          new(lock.Mutex),
		tracker:      tracker,
	}
}

func (a *ACT) callback(key *act.ActiveConnectionTrackerKey, value *act.ActiveConnectionTrackerValue) {
	a.mux.Lock()
	defer a.mux.Unlock()

	entry, ok := a.tracker[key.Zone][key.SvcID]
	if !ok {
		zone, svc, err := a.keyToStrings(key)
		if err != nil {
			log.Debugf("Failed to create ACT map key from %q in callback", key.String())
			return
		}
		a.tracker[key.Zone][key.SvcID] = &actMetric{
			opened:      uint64(value.Opened),
			closed:      uint64(value.Closed),
			labelValues: []string{zone, svc},
		}
		return
	}

	opened, closed := uint64(value.Opened), uint64(value.Closed)
	if opened == entry.opened && closed == entry.closed && entry.newFailed == 0 {
		a.metrics.New.WithLabelValues(entry.labelValues...).Set(0)
		a.metrics.Failed.WithLabelValues(entry.labelValues...).Set(0)
		return
	}
	scopedLog := log.WithField("svc", key.SvcID).WithField("zone", key.Zone)

	// Opened/Closed are 32-bit values, so they can roll-over. Adjust
	if opened < entry.opened {
		opened += math.MaxUint32
	}
	if closed < entry.closed {
		closed += math.MaxUint32
	}

	entry.failed += entry.newFailed
	a.metrics.Failed.WithLabelValues(entry.labelValues...).Set(float64(entry.newFailed))

	active := opened - (closed + entry.failed)
	if sumClosed := (closed + entry.failed); sumClosed > opened {
		scopedLog.Errorf("Unexpected closed+failed, got=%d(%d+%d), want>=%d. Resetting opened value", sumClosed, closed, entry.failed, opened)
		opened = closed + entry.failed
	}
	a.metrics.Active.WithLabelValues(entry.labelValues...).Set(float64(active))

	new := opened - entry.opened
	a.metrics.New.WithLabelValues(entry.labelValues...).Set(float64(new))

	entry.opened = opened
	entry.closed = closed
	entry.newFailed = 0
	entry.updated = time.Now()
}

func (a *ACT) update() {
	start := time.Now()
	err := a.src.IterateWithCallback(a.callback)
	if err != nil {
		log.Errorf("Iterate over %q: %v", act.ActiveConnectionTrackingMapName, err)
		return
	}
	a.metrics.ProcessingTime.Observe(time.Since(start).Seconds())
}

func (a *ACT) dropEntry(zone uint8, svc uint16) {
	entry := a.tracker[zone][svc]
	a.metrics.New.DeleteLabelValues(entry.labelValues...)
	a.metrics.Active.DeleteLabelValues(entry.labelValues...)
	a.metrics.Failed.DeleteLabelValues(entry.labelValues...)

	mapKey := &act.ActiveConnectionTrackerKey{SvcID: svc, Zone: zone}
	err := a.src.Delete(mapKey)
	if err != nil {
		log.WithField("key", mapKey.String()).Debug("Failed to delete ACT map entry")
	}
	delete(a.tracker[zone], svc)
}

func (a *ACT) cleanup(cutoff time.Time) {
	a.mux.Lock()
	defer a.mux.Unlock()

	for zone, services := range a.tracker {
		for svc, entry := range services {
			if entry.updated.IsZero() || entry.updated.Before(cutoff) {
				log.WithField("svc", svc).WithField("zone", zone).Debug("delete")
				a.dropEntry(zone, svc)
			}
		}
	}
}

func (a *ACT) CountFailed4(svc uint16, backend uint32) {
	key := lbmap.NewBackend4KeyV3(loadbalancer.BackendID(backend))
	a.countFailed(svc, key)
}

func (a *ACT) CountFailed6(svc uint16, backend uint32) {
	key := lbmap.NewBackend6KeyV3(loadbalancer.BackendID(backend))
	a.countFailed(svc, key)
}

func (a *ACT) countFailed(svc uint16, key lbmap.BackendKey) {
	scopedLog := log.WithField("svc", byteorder.NetworkToHost16(svc)).WithField("backend", key.GetID())

	val, err := key.Map().Lookup(key)
	if err != nil {
		scopedLog.WithField("key", key.String()).WithError(err).Errorf("Failed to lookup backend of purged CT entry")
		return
	}
	zone := val.(lbmap.BackendValue).GetZone()
	if zone == 0 {
		scopedLog.Debug("Ignoring backend without zone")
		return
	}

	a.mux.Lock()
	defer a.mux.Unlock()

	old, ok := a.tracker[zone][svc]
	if !ok {
		scopedLog.Debug("Missing ACT entry for purged CT")
		return
	}
	old.newFailed++
}

func (a *ACT) run(ctx context.Context) {
	update := time.NewTicker(metricsUpdateInterval)
	cleanup := time.NewTicker(metricsTimeout)
	for {
		select {
		case <-ctx.Done():
			update.Stop()
			cleanup.Stop()
			return
		case <-update.C:
			a.update()
		case <-cleanup.C:
			cutoff := time.Now().Add(-metricsTimeout)
			a.cleanup(cutoff)
		}
	}
}
