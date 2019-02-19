// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"time"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/go-openapi/runtime/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

type getMetrics struct {
	daemon *Daemon
}

// NewGetMetricsHandler returns the metrics handler
func NewGetMetricsHandler(d *Daemon) restapi.GetMetricsHandler {
	return &getMetrics{daemon: d}
}

func (h *getMetrics) Handle(params restapi.GetMetricsParams) middleware.Responder {
	metrics, err := metrics.DumpMetrics()
	if err != nil {
		return api.Error(
			restapi.GetMetricsInternalServerErrorCode,
			fmt.Errorf("Cannot gather metrics from daemon"))
	}

	return restapi.NewGetMetricsOK().WithPayload(metrics)
}

func initMetrics() <-chan error {
	var errs <-chan error

	if option.Config.PrometheusServeAddr != "" {
		log.Infof("Serving prometheus metrics on %s", option.Config.PrometheusServeAddr)
		errs = metrics.Enable(option.Config.PrometheusServeAddr)
	}

	return errs
}

type bootstrapStatistics struct {
	overall         spanstat.SpanStat
	earlyInit       spanstat.SpanStat
	k8sInit         spanstat.SpanStat
	restore         spanstat.SpanStat
	healthCheck     spanstat.SpanStat
	initAPI         spanstat.SpanStat
	initDaemon      spanstat.SpanStat
	cleanup         spanstat.SpanStat
	bpfBase         spanstat.SpanStat
	clusterMeshInit spanstat.SpanStat
	ipam            spanstat.SpanStat
	daemonInit      spanstat.SpanStat
	mapsInit        spanstat.SpanStat
	workloadsInit   spanstat.SpanStat
	proxyStart      spanstat.SpanStat
	fqdn            spanstat.SpanStat
	enableConntrack spanstat.SpanStat
}

func (b *bootstrapStatistics) updateMetrics() {
	for scope, stat := range b.getMap() {
		if stat.SuccessTotal() != time.Duration(0) {
			metricBootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeSuccess).Observe(stat.SuccessTotal().Seconds())
		}
		if stat.FailureTotal() != time.Duration(0) {
			metricBootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeFail).Observe(stat.FailureTotal().Seconds())
		}
	}
}

func (b *bootstrapStatistics) getMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"overall":         &b.overall,
		"earlyInit":       &b.earlyInit,
		"k8sInit":         &b.k8sInit,
		"restore":         &b.restore,
		"healthCheck":     &b.healthCheck,
		"initAPI":         &b.initAPI,
		"initDaemon":      &b.initDaemon,
		"cleanup":         &b.cleanup,
		"bpfBase":         &b.bpfBase,
		"clusterMeshInit": &b.clusterMeshInit,
		"ipam":            &b.ipam,
		"daemonInit":      &b.daemonInit,
		"mapsInit":        &b.mapsInit,
		"workloadsInit":   &b.workloadsInit,
		"proxyStart":      &b.proxyStart,
		"fqdn":            &b.fqdn,
		"enableConntrack": &b.enableConntrack,
	}
}

const (
	metricSubsystem = "agent"

	metricBootstrapOverall = "overall"
)

var (
	metricBootstrapTimes *prometheus.HistogramVec
)

func init() {
	metricBootstrapTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Subsystem: metricSubsystem,
		Name:      "bootstrap_seconds",
		Help:      "Duration of bootstrap sequence",
	}, []string{metrics.LabelScope, metrics.LabelOutcome})

	if err := metrics.Register(metricBootstrapTimes); err != nil {
		log.WithError(err).Fatal("unable to register prometheus metric")
	}
}

// policyRevChange is an internal type used to coordinate between PolicyAdd and
// the watcher goroutine spawned in startImplementationDelayWatcher. It holds
// the timestamp when that revision was added in PolicyAdd and the source for
// that particular call.
type policyRevChange struct {
	rev       uint64
	timestamp time.Time
	source    string
}

// recordPolicyDelayMetric enqueues this revision for tracking later. The
// information is later used by the goroutine in
// startImplementationDelayWatcher when recording the time taken since the
// policy revision was reached and when it was deployed to the datapath.
func (d *Daemon) recordPolicyDelayMetric(policyRev uint64, start time.Time, source string) {
	select {
	case d.pendingMetricRevisions <- policyRevChange{rev: policyRev, timestamp: start, source: source}:
		// Success. Do nothing.
	default:
		// The channel is full. Write a warning.
		log.WithField(logfields.PolicyRevision, policyRev).Warn("policy_implementation_delay metric collection queue is full. No metric will be recorded for this revision.")
	}
}

// startImplementationDelayWatcher runs a goroutine to record the time taken
// for a policy to be implemented in the datapath. It makes some critical
// assumptions:
//   - A revision is only seen once, from a single source. Note that actual
//     regenerations may be rolled up into one by a trigger.Trigger.
//   - The revision only ever increments and we can never see an older revision
//     once we have successfully waited on it.
// The buffered pendingMetricRevisions channel is used as the input to this
// goroutine and holds an entry for every PolicyAdd call that resulted in a new
// revision. It is expected to remain fairly empty and only fill up when
// multiple revision changes queue up during a slower regeneration. Closing the
// channel causes the goroutine to exit.
func startImplementationDelayWatcher() (pendingMetricRevisions chan policyRevChange) {
	// pendingMetricRevisions is a buffered channel of revisions for which we
	// want the implementation delay. It is returned and used by the daemon.
	// It is returned after the goroutine is started below.
	pendingMetricRevisions = make(chan policyRevChange, 16384)

	// Start a goroutine to wait on revision changes sequentially, then report
	// the PolicyImplementationDelay metric for each entry seen in
	// pendingMetricRevisions
	go func() {
		log.Debug("startImplementationDelayWatcher goroutine started")
		defer log.Debug("startImplementationDelayWatcher goroutine exited")

		var (
			// starts is a map of revision -> metadata for revisions in
			// pendingMetricRevisions that were in the future when returning from
			// WaitForEndpointsAtPolicyRevision. Once we get up to that revision the
			// entry is handled and deleted
			starts = make(map[uint64]policyRevChange)

			// currentRevision is what we are currently operating on. It is only
			// incremented once we succcessfully wait on that revision number and
			// record metrics for it.
			currentRevision = uint64(0)
		)

		for {
			// backoff if there are no endpoints. This is required to avoid
			// spin-looping and incrementing the revision
			// (WaitForEndpointsAtPolicyRevision returns when there are no
			// endpoints).
			if len(endpointmanager.GetEndpoints()) == 0 {
				time.Sleep(10 * time.Second)
				continue
			}

			// Wait for currentRevision and, once it returns, for each entry in pendingMetricRevisions:
			//  - If pendingMetricRevisions is closed, exit the goroutine
			//  - If the desired revision is in the past, record the metric immediately
			//  - If the revision is in the future, store it for when that revision is seen
			// Break out when pendingMetricRevisions is empty
			endpointmanager.WaitForEndpointsAtPolicyRev(context.Background(), currentRevision)
			log.WithField(logfields.PolicyRevision, currentRevision).Debug("startImplementationDelayWatcher finished waiting for a revision")
			now := time.Now()
		pendingRevisions:
			for {
				select {
				case start, stillOpen := <-pendingMetricRevisions:
					switch {
					case !stillOpen:
						return
					case start.rev <= currentRevision:
						duration := now.Sub(start.timestamp)
						metrics.PolicyImplementationDelay.WithLabelValues(start.source).Observe(duration.Seconds())
					default:
						starts[start.rev] = start
					}
				default:
					break pendingRevisions
				}
			}

			// Check for a revision stored previously and record the metric
			if start, exists := starts[currentRevision]; exists {
				duration := now.Sub(start.timestamp)
				metrics.PolicyImplementationDelay.WithLabelValues(start.source).Observe(duration.Seconds())
				delete(starts, currentRevision)
			}

			// Work on the next revision
			currentRevision++
		}
	}()

	return pendingMetricRevisions
}
