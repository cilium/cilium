// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"
)

func NewMetrics() *Metrics {
	return &Metrics{
		EndpointGCObjects: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "endpoint_gc_objects",
			Help:      "The number of times endpoint objects have been garbage-collected",
		}, []string{LabelOutcome}),
	}
}

type Metrics struct {
	EndpointGCObjects metric.Vec[metric.Counter]
}
