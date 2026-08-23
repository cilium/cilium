// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/utils/clock"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

const subsystem = "scale_to_zero"

type scaleToZeroMetrics struct {
	ServiceDemand *serviceDemand
}

func newMetrics() *scaleToZeroMetrics {
	return &scaleToZeroMetrics{ServiceDemand: newServiceDemand(clock.RealClock{})}
}

// serviceDemand reports 1 for every scale-to-zero service that the datapath
// signalled demand for recently, and nothing for the rest.
//
// It is a [prometheus.Collector] rather than a [metric.DeletableVec] because
// demand expires on its own: the value of a series is a function of the time of
// the last wake, so computing it on scrape means there is no set of active
// series to keep pruned, and no timer to prune them with. Implementing
// [metric.WithMetadata] keeps it in the "hive-metrics" group all the same, so
// it can be turned off with --metrics like any other agent metric.
type serviceDemand struct {
	opts    metric.Opts
	desc    *prometheus.Desc
	clock   clock.PassiveClock
	enabled bool

	mu lock.Mutex
	// expiry holds the time each service stops being in demand. Its size is
	// bounded by the number of services the datapath tracks, and expired
	// entries are dropped on scrape.
	expiry map[loadbalancer.ServiceName]time.Time
}

func newServiceDemand(clock clock.PassiveClock) *serviceDemand {
	opts := metric.Opts{
		Namespace: metrics.CiliumAgentNamespace,
		Subsystem: subsystem,
		Name:      "service_demand",
		Help:      "1 while a scale-to-zero service is within its idle window since the last wake signal",
	}
	return &serviceDemand{
		opts: opts,
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name),
			opts.Help, []string{"namespace", "name"}, nil),
		clock:   clock,
		enabled: !opts.Disabled,
		expiry:  map[loadbalancer.ServiceName]time.Time{},
	}
}

// wake puts a service in demand for the next window.
func (d *serviceDemand) wake(name loadbalancer.ServiceName, window time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.expiry[name] = d.clock.Now().Add(window)
}

func (d *serviceDemand) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.desc
}

func (d *serviceDemand) Collect(ch chan<- prometheus.Metric) {
	now := d.clock.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	for name, expiry := range d.expiry {
		if !now.Before(expiry) {
			delete(d.expiry, name)
			continue
		}
		ch <- prometheus.MustNewConstMetric(d.desc, prometheus.GaugeValue, 1, name.Namespace(), name.Name())
	}
}

func (d *serviceDemand) Opts() metric.Opts { return d.opts }

func (d *serviceDemand) IsEnabled() bool { return d.enabled }

func (d *serviceDemand) SetEnabled(e bool) { d.enabled = e }

var (
	_ prometheus.Collector = &serviceDemand{}
	_ metric.WithMetadata  = &serviceDemand{}
)
