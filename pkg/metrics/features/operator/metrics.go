// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	ACLBGatewayAPIEnabled               metric.Gauge
	ACLBIngressControllerEnabled        metric.Gauge
	ACLBIPAMEnabled                     metric.Gauge
	ACLBL7AwareTrafficManagementEnabled metric.Gauge
	ACLBNodeIPAMEnabled                 metric.Gauge

	CPKubernetesVersion metric.Vec[metric.Gauge]
}

const (
	subsystemACLB = "feature_adv_connect_and_lb"
	subsystemCP   = "feature_controlplane"
)

// NewMetrics returns all feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewMetrics(withDefaults bool) Metrics {
	return Metrics{
		ACLBGatewayAPIEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Help:      "GatewayAPI enabled on the operator",
			Name:      "gateway_api_enabled",
		}),

		ACLBIngressControllerEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Help:      "IngressController enabled on the operator",
			Name:      "ingress_controller_enabled",
		}),

		ACLBIPAMEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Help:      "LB IPAM enabled on the operator",
			Name:      "lb_ipam_enabled",
		}),

		ACLBL7AwareTrafficManagementEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Help:      "L7 Aware Traffic Management enabled on the operator",
			Name:      "l7_aware_traffic_management_enabled",
		}),

		ACLBNodeIPAMEnabled: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Help:      "Node IPAM enabled on the operator",
			Name:      "node_ipam_enabled",
		}),

		CPKubernetesVersion: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystemCP,
			Help:      "Kubernetes version detected by the operator",
			Name:      "kubernetes_version",
		}, metric.Labels{
			{
				Name: "version",
			},
		}),
	}
}

type featureMetrics interface {
	update(params enabledFeatures, config *option.OperatorConfig)
}

func (m Metrics) update(params enabledFeatures, config *option.OperatorConfig) {
	if config.EnableGatewayAPI {
		m.ACLBGatewayAPIEnabled.Set(1)
	}
	if params.IsIngressControllerEnabled() {
		m.ACLBIngressControllerEnabled.Set(1)
	}
	if params.IsLBIPAMEnabled() {
		m.ACLBIPAMEnabled.Set(1)
	}
	if params.GetLoadBalancerL7() != "" {
		m.ACLBL7AwareTrafficManagementEnabled.Set(1)
	}
	if params.IsNodeIPAMEnabled() {
		m.ACLBNodeIPAMEnabled.Set(1)
	}
	if k8sVersionStr := params.K8sVersion(); k8sVersionStr != "" {
		m.CPKubernetesVersion.WithLabelValues(k8sVersionStr).Set(1)
	}
}
