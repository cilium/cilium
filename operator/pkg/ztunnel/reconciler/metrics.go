// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	LabelOutcome = "outcome"
	LabelMethod  = "method"

	LabelValueOutcomeSuccess = "success"
	LabelValueOutcomeFail    = "fail"

	LabelValueMethodUpsert = "upsert"
	LabelValueMethodDelete = "delete"
)

func NewMetrics() *Metrics {
	return &Metrics{
		EnrollmentOps: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: "ztunnel",
			Name:      "enrollment_ops_total",
			Help:      "Total number of SPIRE enrollment operations for ztunnel mTLS",
			Disabled:  true,
		}, []string{LabelMethod, LabelOutcome}),
	}
}

type Metrics struct {
	EnrollmentOps metric.Vec[metric.Counter]
}
