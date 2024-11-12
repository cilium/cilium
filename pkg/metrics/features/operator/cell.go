// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
)

// Cell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// features are enabled on the operator.
var Cell = cell.Module(
	"enabled-features",
	"Exports prometheus metrics describing which features are enabled in operator",

	cell.Invoke(newOperatorConfigMetricOnStart),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
	),
	cell.Metric(func() Metrics {
		return NewMetrics(true)
	}),
)

type featuresParams struct {
	cell.In

	Scope       cell.Scope
	JobRegistry job.Registry
	Health      cell.Health
	Lifecycle   cell.Lifecycle
	Metrics     featureMetrics

	OperatorConfig *operatorOption.OperatorConfig

	IngressController ingress.IngressConfig
}

func (p featuresParams) IsIngressControllerEnabled() bool {
	return p.IngressController.IsEnabled()
}

type enabledFeatures interface {
	IsIngressControllerEnabled() bool
}
