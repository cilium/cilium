// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"math"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
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
	// metricsUpdateInterval is a time interval for between ACT map reads.
	// The number of new connections is calculated by comparing values between reads.
	metricsUpdateInterval = 15 * time.Second
	// metricsTimeout specifies when a stale entry will be removed from the metrics endpoint
	// (it will be no longer available to scrape).
	metricsTimeout = 10 * time.Minute
	// metricsCountSoftLimit specifies when metric series will be deleted more aggresively.
	metricsCountSoftLimit = 300
	// metricsCountHardLimit specifies when new metrics series won't be allocated.
	metricsCountHardLimit = 500
)

var Cell = cell.Module(
	"act-metrics",
	"Metrics with counts of new and active connections for each service-zone pair",

	metrics.Metric(NewActiveConnectionTrackingMetrics),
	cell.Invoke(NewACT),
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
	log     *slog.Logger
	src     act.ActiveConnectionTrackingMap
	metrics ActiveConnectionTrackingMetrics

	// keyToStrings converts (svc, zone) pair to their string versions
	keyToStrings func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error)

	// trig is used to start removeOverflow routine early
	trig job.Trigger

	// mux protects tracker map
	mux *lock.Mutex
	// tracker is a map[zone][svc]metric
	tracker map[uint8]map[uint16]*actMetric
}

func NewACT(in struct {
	cell.In

	Conf      act.Config
	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	Jobs      job.Group
	Source    act.ActiveConnectionTrackingMap
	Metrics   ActiveConnectionTrackingMetrics
}) *ACT {
	if !in.Conf.EnableActiveConnectionTracking {
		// Active Connection Tracking is disabled.
		return nil
	}
	a := newAct(in.Log, in.Source, in.Metrics, option.Config)
	a.trig = job.NewTrigger()

	in.Jobs.Add(job.Timer("act-metrics-update", a.update, metricsUpdateInterval))
	in.Jobs.Add(job.Timer("act-metrics-cleanup", a.cleanup, metricsTimeout))
	in.Jobs.Add(job.Timer("act-metrics-remove-overflow", a.removeOverflow, time.Hour, job.WithTrigger(a.trig)))
	in.Lifecycle.Append(in.Jobs)
	ctmap.ACT = a
	return a
}

func newAct(log *slog.Logger, src act.ActiveConnectionTrackingMap, metrics ActiveConnectionTrackingMetrics, opts *option.DaemonConfig) *ACT {
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
		log:          log,
		src:          src,
		metrics:      metrics,
		keyToStrings: kts,
		mux:          new(lock.Mutex),
		tracker:      tracker,
	}
}

// callback processes an ACT map entry.
//
// It will create the new metrics series if needed. In this case metrics won't
// be presented as the number of new connections can't be calculated yet.
func (a *ACT) callback(key *act.ActiveConnectionTrackerKey, value *act.ActiveConnectionTrackerValue) {
	a.mux.Lock()
	defer a.mux.Unlock()

	entry, ok := a.tracker[key.Zone][key.SvcID]
	if !ok {
		zone, svc, err := a.keyToStrings(key)
		if err != nil {
			a.log.Debug("Failed to construct metrics map key in callback", "from-key", key.String())
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
	scopedLog := a.log.With("svc", key.SvcID, "zone", key.Zone)

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
		scopedLog.Error("Unexpected closed+failed", "got", sumClosed, "want", opened)
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

func (a *ACT) update(ctx context.Context) error {
	start := time.Now()
	err := a.src.IterateWithCallback(ctx, a.callback)
	if err != nil {
		return fmt.Errorf("iterate over %q: %w", act.ActiveConnectionTrackingMapName, err)
	}
	a.metrics.ProcessingTime.Observe(time.Since(start).Seconds())
	return nil
}

func (a *ACT) dropEntry(zone uint8, svc uint16) {
	entry := a.tracker[zone][svc]
	a.metrics.New.DeleteLabelValues(entry.labelValues...)
	a.metrics.Active.DeleteLabelValues(entry.labelValues...)
	a.metrics.Failed.DeleteLabelValues(entry.labelValues...)

	mapKey := &act.ActiveConnectionTrackerKey{SvcID: svc, Zone: zone}
	err := a.src.Delete(mapKey)
	if err != nil {
		a.log.Debug("Failed to delete ACT map entry", "key", mapKey.String())
	}
	delete(a.tracker[zone], svc)
}

func (a *ACT) _cleanup(ctx context.Context, cutoff time.Time) error {
	a.mux.Lock()
	defer a.mux.Unlock()

	n := 0
	for zone, services := range a.tracker {
		for svc, entry := range services {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if entry.updated.IsZero() || entry.updated.Before(cutoff) {
				a.log.Debug("delete", "svc", svc, "zone", zone)
				a.dropEntry(zone, svc)
			}
		}
		n += len(services)
	}
	if n >= metricsCountSoftLimit {
		a.trig.Trigger()
	}
	return nil
}

func (a *ACT) cleanup(ctx context.Context) error {
	cutoff := time.Now().Add(-metricsTimeout)
	return a._cleanup(ctx, cutoff)
}

// CountFailed4 increments a counter of new failed connections
// for a given (svc, backend) pair.
func (a *ACT) CountFailed4(svc uint16, backend uint32) {
	key := lbmap.NewBackend4KeyV3(loadbalancer.BackendID(backend))
	a.countFailed(svc, key)
}

// CountFailed6 increments a counter of new failed connections
// for a given (svc, backend) pair.
func (a *ACT) CountFailed6(svc uint16, backend uint32) {
	key := lbmap.NewBackend6KeyV3(loadbalancer.BackendID(backend))
	a.countFailed(svc, key)
}

// countFailed looks up zone information in the backend map and then increments
// a counter of new failed connection for a constructed (svc, zone) pair.
func (a *ACT) countFailed(svc uint16, key lbmap.BackendKey) {
	scopedLog := a.log.With("svc", byteorder.NetworkToHost16(svc), "backend", key.GetID())

	val, err := key.Map().Lookup(key)
	if err != nil {
		scopedLog.Error("Failed to lookup backend of purged CT entry", "key", key.String(), "err", err)
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

// trackerLen is the total number of metric series held by ACT.
//
// It must be called with lock held to guarantee correctness of the outcome.
func (a *ACT) trackerLen() int {
	n := 0
	for _, services := range a.tracker {
		n += len(services)
	}
	return n
}

// removeOverflow keeps the number of metrics series at or below
// metricsCountSoftLimit. It builds a heap of elements to remove by comparing
// their latest update timestamp. All elements on the heap (metrics that are
// stale for the longest) are removed.
func (a *ACT) removeOverflow(ctx context.Context) error {
	select {
	case <-ctx.Done():
		ctx.Err()
	default:
	}
	a.mux.Lock()
	defer a.mux.Unlock()
	n := a.trackerLen()
	if n < metricsCountSoftLimit {
		// Nothing to do
		return nil
	}
	target := max(n-metricsCountSoftLimit, 100)
	scopedLog := a.log.With("start-count", n, "limit", metricsCountSoftLimit, "target", target)
	scopedLog.Info("Making a sweep of presented metrics")
	gc := make(gcHeap, 0, target+1)
	heap.Init(&gc)
	for zone, services := range a.tracker {
		for svc, entry := range services {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			unix := entry.updated.Unix()
			if gc.Len() == target && unix > gc[0].unix {
				continue
			}
			heap.Push(&gc, gcEntry{unix: unix, svc: svc, zone: zone})
			if gc.Len() > target {
				heap.Pop(&gc)
			}
		}
	}
	tooEarly := 0
	cutoff := time.Now().Add(-metricsUpdateInterval)
	for _, entry := range gc {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		scopedLog.Debug("delete", "svc", entry.svc, "zone", entry.zone)
		if time.Unix(entry.unix, 0).After(cutoff) {
			tooEarly++
		}
		a.dropEntry(entry.zone, entry.svc)
	}
	scopedLog.Info("Removed extra metrics", "removed", gc.Len())
	if tooEarly > 0 {
		scopedLog.Warn("Removed metrics before they were shown", "count", tooEarly)
	}

	return nil
}
