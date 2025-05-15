// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"log/slog"
	"maps"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

// Update upserts the endpoint ID and updates the max endpoint policy map pressure metric.
func (p *policyMapPressure) Update(ev endpoint.PolicyMapPressureEvent) {
	val := ev.Value
	p.Lock()
	p.current[ev.EndpointID] = val
	p.Unlock()

	p.logger.Debug("EndpointManager policymap received event", logfields.Value, val)

	p.trigger.Trigger()
}

// Remove removes an endpoints policy map pressure by endpoint ID.
// Should be called to clean up the metric when an endpoint is removed.
func (p *policyMapPressure) Remove(id uint16) {
	p.Lock()
	delete(p.current, id)
	p.Unlock()

	p.trigger.Trigger()
}

var policyMapPressureMinInterval = 10 * time.Second

func newPolicyMapPressure(logger *slog.Logger, registry *metrics.Registry) *policyMapPressure {
	if !metrics.BPFMapPressure {
		return nil
	}

	p := &policyMapPressure{logger: logger}
	p.gauge = registry.NewBPFMapPressureGauge(policymap.MapName+"*", policymap.PressureMetricThreshold)
	p.current = make(map[uint16]float64)

	var err error
	p.trigger, err = trigger.NewTrigger(trigger.Parameters{
		// It seems like 10s is a small enough window of time where the user
		// can still reasonably react to a rising BPF map pressure. Keep it
		// below the default Prometheus scrape interval of 15s anyway.
		MinInterval: policyMapPressureMinInterval,
		TriggerFunc: func([]string) { p.update() },
		Name:        "endpointmanager-policymap-max-size-metrics",
	})
	if err != nil {
		logging.Panic(logger, "Failed to initialize trigger for policymap pressure metric", logfields.Error, err)
	}

	return p
}

func (p *policyMapPressure) update() {
	p.logger.Debug("EndpointManager policymap event metric update triggered")

	if p.gauge == nil {
		return
	}

	p.RLock()
	max := float64(0)
	for value := range maps.Values(p.current) {
		if value > max {
			max = value
		}
	}
	p.RUnlock()
	p.gauge.Set(max)
}

type metricsGauge interface {
	Set(value float64)
}

// policyMapPressure implements policyMapPressure to provide the endpoint's
// policymap pressure metric. It only exports the maximum policymap pressure
// from all endpoints within the EndpointManager to reduce cardinality of the
// metric.
type policyMapPressure struct {
	logger *slog.Logger

	lock.RWMutex

	// current holds the current maximum policymap pressure values by endpoint ID
	// that is pushed into gauge via trigger..
	current map[uint16]float64

	// gauge is the gauge metric.
	gauge metricsGauge

	// trigger handles exporting / updating the gauge with the value in current
	// on an interval.
	trigger *trigger.Trigger
}
