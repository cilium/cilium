// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"sync/atomic"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

func (p *policyMapPressure) Update(ev endpoint.PolicyMapPressureEvent) {
	val := ev.Value

	log.WithField(logfields.Value, val).Debug("EndpointManager policymap received event")

	cur := p.current.Load()
	if cur == nil || val > *cur {
		p.current.Store(&val)
		p.trigger.Trigger()
	}
}

func newPolicyMapPressure() *policyMapPressure {
	if !metrics.BPFMapPressure {
		return nil
	}

	p := new(policyMapPressure)
	p.gauge = metrics.NewBPFMapPressureGauge(policymap.MapName+"*", policymap.PressureMetricThreshold)

	var err error
	p.trigger, err = trigger.NewTrigger(trigger.Parameters{
		// It seems like 10s is a small enough window of time where the user
		// can still reasonably react to a rising BPF map pressure. Keep it
		// below the default Prometheus scrape interval of 15s anyway.
		MinInterval: 10 * time.Second,
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

	if value := mgr.current.Load(); value != nil {
		mgr.gauge.Set(*value)
	}
}

// policyMapPressure implements policyMapPressure to provide the endpoint's
// policymap pressure metric. It only exports the maximum policymap pressure
// from all endpoints within the EndpointManager to reduce cardinality of the
// metric.
type policyMapPressure struct {
	// current holds the current maximum policymap pressure value that is
	// pushed into gauge via trigger..
	current atomic.Pointer[float64]

	// gauge is the gauge metric.
	gauge *metrics.GaugeWithThreshold

	// trigger handles exporting / updating the gauge with the value in current
	// on an interval.
	trigger *trigger.Trigger
}
