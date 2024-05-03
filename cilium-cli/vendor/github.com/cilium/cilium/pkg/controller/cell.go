// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	controllerGroupMetrics = "controller-group-metrics"

	// labelControllerGroupName is the label used
	// to identify controller-specific metrics
	labelControllerGroupName = "group_name"
)

var (
	// GroupMetricEnabled is populated with the set of ControllerGroups for which metrics are enabled
	groupMetricEnabled = map[string]bool{}

	// GroupRuns is a Prometheus-compatible metric for Controller
	// runs, labeled by completion status and Group name
	GroupRuns = metrics.NoOpCounterVec
)

var Cell = cell.Module(
	"controller",
	"Controllers and Controller Lifecycle management",
	cell.Config(Config{}),
	metrics.Metric(NewMetrics),
	cell.Invoke(Init),
)

type Metrics struct {
	ControllerGroupRuns metric.Vec[metric.Counter]
}

func NewMetrics() Metrics {
	return Metrics{
		ControllerGroupRuns: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_controllers_group_runs_total",
			Namespace:  metrics.Namespace,
			Name:       "controllers_group_runs_total",
			Help:       "Number of times that a controller group was run, labeled by completion status and controller group name",
		}, []string{labelControllerGroupName, metrics.LabelStatus}),
	}
}

type Config struct {
	// ControllerGroupMetrics is an option which specifies the set of ControllerGroups names
	// for which metrics will be enabled. The special values 'all' and 'none' are supported.
	ControllerGroupMetrics []string
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(controllerGroupMetrics, cfg.ControllerGroupMetrics,
		"List of controller group names for which to to enable metrics. "+
			"Accepts 'all' and 'none'. "+
			"The set of controller group names available is not guaranteed to be stable between Cilium versions.")
}

func Init(cfg Config, m Metrics) {
	// Initialize package-scoped references to Cell configuration
	for _, name := range cfg.ControllerGroupMetrics {
		groupMetricEnabled[name] = true
	}

	GroupRuns = m.ControllerGroupRuns
}
