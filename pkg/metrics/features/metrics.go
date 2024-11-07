// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

// Metrics represents a collection of metrics related to a specific feature.
// Each field is named according to the specific feature that it tracks.
type Metrics struct {
	DPMode                        metric.Vec[metric.Gauge]
	DPIPAM                        metric.Vec[metric.Gauge]
	DPChaining                    metric.Vec[metric.Gauge]
	DPIP                          metric.Vec[metric.Gauge]
	DPIdentityAllocation          metric.Vec[metric.Gauge]
	DPCiliumEndpointSlicesEnabled metric.Gauge
	DPDeviceMode                  metric.Vec[metric.Gauge]
}

const (
	subsystemDP = "feature_datapath"
)

const (
	networkModeOverlayVXLAN  = "overlay-vxlan"
	networkModeOverlayGENEVE = "overlay-geneve"
	networkModeDirectRouting = "direct-routing"

	networkChainingModeNone        = "none"
	networkChainingModeAWSCNI      = "aws-cni"
	networkChainingModeAWSVPCCNI   = "aws-vpc-cni"
	networkChainingModeCalico      = "calico"
	networkChainingModeFlannel     = "flannel"
	networkChainingModeGenericVeth = "generic-veth"

	networkIPv4      = "ipv4-only"
	networkIPv6      = "ipv6-only"
	networkDualStack = "ipv4-ipv6-dual-stack"
)

var (
	defaultNetworkModes = []string{
		networkModeOverlayVXLAN,
		networkModeOverlayGENEVE,
		networkModeDirectRouting,
	}

	defaultIPAMModes = []string{
		ipamOption.IPAMKubernetes,
		ipamOption.IPAMCRD,
		ipamOption.IPAMENI,
		ipamOption.IPAMAzure,
		ipamOption.IPAMClusterPool,
		ipamOption.IPAMMultiPool,
		ipamOption.IPAMAlibabaCloud,
		ipamOption.IPAMDelegatedPlugin,
	}

	defaultChainingModes = []string{
		networkChainingModeNone,
		networkChainingModeAWSCNI,
		networkChainingModeAWSVPCCNI,
		networkChainingModeCalico,
		networkChainingModeFlannel,
		networkChainingModeGenericVeth,
	}

	defaultIProtocols = []string{
		networkIPv4,
		networkIPv6,
		networkDualStack,
	}

	defaultIdentityAllocationModes = []string{
		option.IdentityAllocationModeKVstore,
		option.IdentityAllocationModeCRD,
		option.IdentityAllocationModeDoubleWriteReadKVstore,
		option.IdentityAllocationModeDoubleWriteReadCRD,
	}

	defaultDeviceModes = []string{
		datapathOption.DatapathModeVeth,
		datapathOption.DatapathModeNetkit,
		datapathOption.DatapathModeNetkitL2,
		datapathOption.DatapathModeLBOnly,
	}
)

// NewMetrics returns all feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewMetrics(withDefaults bool) Metrics {
	return Metrics{
		DPMode: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Network mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "network",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultNetworkModes...,
					)
				}(),
			},
		}),

		DPIPAM: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "IPAM mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "ipam",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultIPAMModes...,
					)
				}(),
			},
		}),

		DPChaining: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Chaining mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "chaining_enabled",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultChainingModes...,
					)
				}(),
			},
		}),

		DPIP: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "IP mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "internet_protocol",
		}, metric.Labels{
			{
				Name: "protocol", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultIProtocols...,
					)
				}(),
			},
		}),

		DPIdentityAllocation: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Identity Allocation mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "identity_allocation",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultIdentityAllocationModes...,
					)
				}(),
			},
		}),

		DPCiliumEndpointSlicesEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium Endpoint Slices enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "cilium_endpoint_slices_enabled",
		}),

		DPDeviceMode: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Device mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "device",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultDeviceModes...,
					)
				}(),
			},
		}),
	}
}

type featureMetrics interface {
	update(params enabledFeatures, config *option.DaemonConfig)
}

func (m Metrics) update(params enabledFeatures, config *option.DaemonConfig) {
	networkMode := networkModeDirectRouting
	if config.TunnelingEnabled() {
		switch params.TunnelProtocol() {
		case tunnel.VXLAN:
			networkMode = networkModeOverlayVXLAN
		case tunnel.Geneve:
			networkMode = networkModeOverlayGENEVE
		}
	}
	m.DPMode.WithLabelValues(networkMode).Add(1)

	ipamMode := config.IPAMMode()
	m.DPIPAM.WithLabelValues(ipamMode).Add(1)

	chainingMode := params.GetChainingMode()
	m.DPChaining.WithLabelValues(chainingMode).Add(1)

	var ip string
	switch {
	case config.IsDualStack():
		ip = networkDualStack
	case config.IPv4Enabled():
		ip = networkIPv4
	case config.IPv6Enabled():
		ip = networkIPv6
	}
	m.DPIP.WithLabelValues(ip).Add(1)

	identityAllocationMode := config.IdentityAllocationMode
	m.DPIdentityAllocation.WithLabelValues(identityAllocationMode).Add(1)

	if config.EnableCiliumEndpointSlice {
		m.DPCiliumEndpointSlicesEnabled.Add(1)
	}

	deviceMode := config.DatapathMode
	m.DPDeviceMode.WithLabelValues(deviceMode).Add(1)
}
