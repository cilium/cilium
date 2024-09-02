// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"maps"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/lock"
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

	log.WithField(logfields.Value, val).Debug("EndpointManager policymap received event")

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

func newPolicyMapPressure() *policyMapPressure {
	if !metrics.BPFMapPressure {
		return nil
	}

	p := new(policyMapPressure)
	p.gauge = metrics.NewBPFMapPressureGauge(policymap.MapName+"*", policymap.PressureMetricThreshold)
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
		log.WithError(err).Panic("Failed to initialize trigger for policymap pressure metric")
	}

	return p
}

func (mgr *policyMapPressure) update() {
	log.Debug("EndpointManager policymap event metric update triggered")

	if mgr.gauge == nil {
		return
	}

	mgr.RLock()
	max := float64(0)
	for value := range maps.Values(mgr.current) {
		if value > max {
			max = value
		}
	}
	mgr.RUnlock()
	mgr.gauge.Set(max)
}

type metricsGauge interface {
	Set(value float64)
}

// policyMapPressure implements policyMapPressure to provide the endpoint's
// policymap pressure metric. It only exports the maximum policymap pressure
// from all endpoints within the EndpointManager to reduce cardinality of the
// metric.
type policyMapPressure struct {
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
