// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package job

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type jobMetrics struct {
	JobErrorsTotal      metric.Vec[metric.Counter]
	OneShotRunDuration  metric.Vec[metric.Observer]
	TimerRunDuration    metric.Vec[metric.Observer]
	ObserverRunDuration metric.Vec[metric.Observer]
}

func newJobMetrics() *jobMetrics {
	return &jobMetrics{
		JobErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "jobs_errors_total",
			Namespace:  metrics.Namespace,
			Subsystem:  "jobs",
			Name:       "errors_total",
			Help:       "The amount of errors encountered while running jobs",
		}, []string{"job"}),
		OneShotRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "jobs_one_shot_run_seconds",
			Namespace:  metrics.Namespace,
			Subsystem:  "jobs",
			Name:       "one_shot_run_seconds",
			Help:       "The run time of a one shot job",
		}, []string{"job"}),
		TimerRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "jobs_timer_run_seconds",
			Namespace:  metrics.Namespace,
			Subsystem:  "jobs",
			Name:       "timer_run_seconds",
			Help:       "The run time of a timer job",
		}, []string{"job"}),
		ObserverRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "jobs_observer_run_seconds",
			Namespace:  metrics.Namespace,
			Subsystem:  "jobs",
			Name:       "observer_run_seconds",
			Help:       "The run time of a observer job",
		}, []string{"job"}),
	}
}
