// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	metricsSubsystem = "endpoint_restoration"
)

const (
	labelPhase   = "phase"
	labelOutcome = "outcome"
)

const (
	phaseRead                = "read_from_disk"
	phaseRestoration         = "restoration"
	phasePrepareRegeneration = "prepare_regeneration"
	phasePolicyComputation   = "initial_policy_computation"
	phaseRegeneration        = "regeneration"
)

const (
	outcomeTotal      = "total"
	outcomeSuccessful = "successful"
	outcomeSkipped    = "skipped"
	outcomeFailed     = "failed"
)

type endpointRestoreMetrics struct {
	Endpoints metric.Vec[metric.Gauge]
	Duration  metric.Vec[metric.Gauge]
}

func newEndpointRestoreMetrics() *endpointRestoreMetrics {
	return &endpointRestoreMetrics{
		Endpoints: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "endpoints",
			Help:      "Number of restored endpoints labelled by phase and outcome",
		}, []string{labelPhase, labelOutcome}),
		Duration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: metricsSubsystem,
			Name:      "duration_seconds",
			Help:      "Duration of restoration phases in seconds",
		}, []string{labelPhase}),
	}
}
