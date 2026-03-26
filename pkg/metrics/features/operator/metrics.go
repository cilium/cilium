// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"reflect"

	"github.com/prometheus/client_golang/prometheus"

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
// all metrics will have defined all of their possible values.  If 'withEnvVersion'
// is set, then we include things like version information from the host.
func NewMetrics(withDefaults bool, withEnvVersion bool) Metrics {
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
			Disabled:  !withEnvVersion,
		}, metric.Labels{
			{
				Name: "version",
			},
		}),
	}
}

type featureMetrics interface {
	update(params enabledFeatures, config *option.OperatorConfig)
	toGatherer() (prometheus.Gatherer, error)
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
	if m.CPKubernetesVersion.IsEnabled() {
		if k8sVersionStr := params.K8sVersion(); k8sVersionStr != "" {
			m.CPKubernetesVersion.WithLabelValues(k8sVersionStr).Set(1)
		}
	}
}

func (m Metrics) toGatherer() (prometheus.Gatherer, error) {
	rv := reflect.ValueOf(m)
	reg := prometheus.NewPedanticRegistry()
	for i := 0; i < rv.NumField(); i++ {
		if !rv.Field(i).CanInterface() {
			continue
		}
		c, ok := rv.Field(i).Interface().(prometheus.Collector)
		if !ok {
			continue
		}
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("registering metric: %w", err)
		}
	}
	return reg, nil
}
