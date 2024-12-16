// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	operatorOption "github.com/cilium/cilium/operator/option"
	ciliumenvoyconfig2 "github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/pkg/metrics"
)

// Cell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// features are enabled on the operator.
var Cell = cell.Module(
	"enabled-features",
	"Exports prometheus metrics describing which features are enabled in operator",

	cell.Invoke(updateOperatorConfigMetricOnStart),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
	),
	metrics.Metric(func() Metrics {
		return NewMetrics(true)
	}),
)

type featuresParams struct {
	cell.In

	Log       *slog.Logger
	JobGroup  job.Group
	Health    cell.Health
	Lifecycle cell.Lifecycle
	Metrics   featureMetrics

	OperatorConfig *operatorOption.OperatorConfig

	IngressController ingress.IngressConfig
	LBIPAM            lbipam.Config
	LBConfig          ciliumenvoyconfig2.LoadBalancerConfig
}

func (p featuresParams) IsIngressControllerEnabled() bool {
	return p.IngressController.IsEnabled()
}

func (p featuresParams) IsLBIPAMEnabled() bool {
	return p.LBIPAM.IsEnabled()
}

func (p featuresParams) GetLoadBalancerL7() string {
	return p.LBConfig.GetLoadBalancerL7()
}

type enabledFeatures interface {
	IsIngressControllerEnabled() bool
	IsLBIPAMEnabled() bool
	GetLoadBalancerL7() string
}
