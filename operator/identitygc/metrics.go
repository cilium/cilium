// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelStatus marks the status of a resource or completed task
	LabelStatus = "status"

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueOutcomeAlive is used as outcome of alive identity entries
	LabelValueOutcomeAlive = "alive"

	// LabelValueOutcomeDeleted is used as outcome of deleted identity entries
	LabelValueOutcomeDeleted = "deleted"
)

func NewMetrics() *Metrics {
	return &Metrics{
		IdentityGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_gc_entries",
			Help:      "The number of alive and deleted identities at the end of a garbage collector run",
		}, []string{LabelStatus}),

		IdentityGCRuns: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_gc_runs",
			Help:      "The number of times identity garbage collector has run",
		}, []string{LabelOutcome}),
	}
}

type Metrics struct {
	// IdentityGCSize records the identity GC results
	IdentityGCSize metric.Vec[metric.Gauge]

	// IdentityGCRuns records how many times identity GC has run
	IdentityGCRuns metric.Vec[metric.Gauge]
}
