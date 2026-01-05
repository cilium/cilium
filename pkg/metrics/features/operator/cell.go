// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	operatorOption "github.com/cilium/cilium/operator/option"
	ciliumenvoyconfig2 "github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/operator/pkg/ingress"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
)

var (
	// withDefaults will set enable all default metrics in the operator.
	withDefaults = os.Getenv("CILIUM_FEATURE_METRICS_WITH_DEFAULTS")
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
		if withDefaults != "" {
			return NewMetrics(true)
		}
		return NewMetrics(false)
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
	LBIPAM            lbipamconfig.Config
	LBConfig          ciliumenvoyconfig2.LoadBalancerConfig
	NodeIPAM          nodeipamconfig.NodeIPAMConfig
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

func (p featuresParams) IsNodeIPAMEnabled() bool {
	return p.NodeIPAM.IsEnabled()
}

func (p featuresParams) K8sVersion() string {
	return k8sversion.Version().String()
}

type enabledFeatures interface {
	IsIngressControllerEnabled() bool
	IsLBIPAMEnabled() bool
	GetLoadBalancerL7() string
	IsNodeIPAMEnabled() bool
	K8sVersion() string
}
