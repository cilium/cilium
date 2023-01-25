// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var exampleMetricsCell = cell.Metric(newExampleMetrics)

type exampleMetrics struct {
	ExampleCounter    metric.Counter
	ExampleCounterVec metric.Vec[metric.Counter]
}

func newExampleMetrics() exampleMetrics {
	return exampleMetrics{
		ExampleCounter: metric.NewCounter(metric.CounterOpts{
			Namespace: "cilium",
			Subsystem: metric.Subsystem{
				Name:    "example",
				DocName: "Example",
			},
			Name:             "misc_total",
			Help:             "Counts miscellaneous events",
			Description:      "Counts miscellaneous events, useful for nothing",
			EnabledByDefault: true,
			ConstLabels: metric.ConstLabels{
				metric.ConstLabel{
					Name:        "host",
					Description: "Hostname",
				}: "example.cluster-123.net",
			},
		}),
		ExampleCounterVec: metric.NewCounterVec(
			metric.CounterOpts{
				Namespace: "cilium",
				Subsystem: metric.Subsystem{
					Name:    "example",
					DocName: "Example",
				},
				Name:             "some_other_misc_total",
				Help:             "Counts other types of miscellaneous events",
				Description:      "Counts other types of miscellaneous events, useful for again, nothing",
				EnabledByDefault: true,
				ConstLabels: metric.ConstLabels{
					metric.ConstLabel{
						Name:        "host",
						Description: "Hostname",
					}: "example.cluster-123.net",
				},
			},
			metric.LabelDescriptions{
				metric.LabelDescription{
					Name:        "state",
					Description: "Count per state",
					KnownValues: []metric.KnownValue{
						{Name: "init"},
						{Name: "ready"},
						{Name: "error"},
					},
				},
			},
		),
	}
}
