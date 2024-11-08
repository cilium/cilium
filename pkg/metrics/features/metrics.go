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
	"github.com/cilium/cilium/pkg/policy/api"
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

	NPHostFirewallEnabled        metric.Gauge
	NPLocalRedirectPolicyEnabled metric.Gauge
	NPMutualAuthEnabled          metric.Gauge
	NPCIDRPoliciesToNodes        metric.Vec[metric.Gauge]

	ACLBTransparentEncryption       metric.Vec[metric.Gauge]
	ACLBKubeProxyReplacementEnabled metric.Gauge
	ACLBNodePortConfig              metric.Vec[metric.Gauge]
	ACLBBGPEnabled                  metric.Gauge
	ACLBEgressGatewayEnabled        metric.Gauge
	ACLBBandwidthManagerEnabled     metric.Gauge
	ACLBSCTPEnabled                 metric.Gauge
	ACLBVTEPEnabled                 metric.Gauge
}

const (
	subsystemDP   = "feature_datapath"
	subsystemNP   = "feature_network_policies"
	subsystemACLB = "feature_adv_connect_and_lb"
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

	advConnNetEncIPSec     = "ipsec"
	advConnNetEncWireGuard = "wireguard"
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
	}

	defaultDeviceModes = []string{
		datapathOption.DatapathModeVeth,
		datapathOption.DatapathModeLBOnly,
	}

	defaultCIDRPolicies = []string{
		string(api.EntityWorld),
		string(api.EntityRemoteNode),
	}

	defaultEncryptionModes = []string{
		advConnNetEncIPSec,
		advConnNetEncWireGuard,
	}

	defaultNodePortModes = []string{
		option.NodePortModeSNAT,
		option.NodePortModeDSR,
		option.NodePortModeHybrid,
	}

	defaultNodePortModeAlgorithms = []string{
		option.NodePortAlgMaglev,
		option.NodePortAlgRandom,
	}

	defaultNodePortModeAccelerations = []string{
		option.NodePortAccelerationDisabled,
		option.NodePortAccelerationGeneric,
		option.NodePortAccelerationBestEffort,
		option.NodePortAccelerationNative,
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

		NPHostFirewallEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Host firewall enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "host_firewall_enabled",
		}),

		NPLocalRedirectPolicyEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Local Redirect Policy enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "local_redirect_policy_enabled",
		}),

		NPMutualAuthEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Mutual Auth enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "mutual_auth_enabled",
		}),

		NPCIDRPoliciesToNodes: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Mode to apply CIDR Policies to Nodes",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "cidr_policies",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultCIDRPolicies...,
					)
				}(),
			},
		}),

		ACLBTransparentEncryption: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Encryption mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "transparent_encryption",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultEncryptionModes...,
					)
				}(),
			},
			{
				Name: "node2node_enabled", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						"true",
						"false",
					)
				}(),
			},
		}),

		ACLBKubeProxyReplacementEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "KubeProxyReplacement enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "kube_proxy_replacement_enabled",
		}),

		ACLBNodePortConfig: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Node Port configuration enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "node_port_configuration",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultNodePortModes...,
					)
				}(),
			},
			{
				Name: "algorithm", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultNodePortModeAlgorithms...,
					)
				}(),
			},
			{
				Name: "acceleration", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultNodePortModeAccelerations...,
					)
				}(),
			},
		}),

		ACLBBGPEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "BGP Advertisement enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "bgp_advertisement_enabled",
		}),

		ACLBEgressGatewayEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Egress Gateway enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "egress_gateway_enabled",
		}),

		ACLBBandwidthManagerEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Bandwidth Manager enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "bandwidth_manager_enabled",
		}),

		ACLBSCTPEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "SCTP enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "sctp_enabled",
		}),

		ACLBVTEPEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "VTEP enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "vtep_enabled",
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

	if config.EnableHostFirewall {
		m.NPHostFirewallEnabled.Add(1)
	}

	if config.EnableLocalRedirectPolicy {
		m.NPLocalRedirectPolicyEnabled.Add(1)
	}

	if params.IsMutualAuthEnabled() {
		m.NPMutualAuthEnabled.Add(1)
	}

	for _, mode := range config.PolicyCIDRMatchMode {
		m.NPCIDRPoliciesToNodes.WithLabelValues(mode).Add(1)
	}

	if config.EnableIPSec {
		if config.EncryptNode {
			m.ACLBTransparentEncryption.WithLabelValues(advConnNetEncIPSec, "true").Add(1)
		} else {
			m.ACLBTransparentEncryption.WithLabelValues(advConnNetEncIPSec, "false").Add(1)
		}
	}
	if config.EnableWireguard {
		if config.EncryptNode {
			m.ACLBTransparentEncryption.WithLabelValues(advConnNetEncWireGuard, "true").Add(1)
		} else {
			m.ACLBTransparentEncryption.WithLabelValues(advConnNetEncWireGuard, "false").Add(1)
		}
	}

	if config.KubeProxyReplacement == option.KubeProxyReplacementTrue {
		m.ACLBKubeProxyReplacementEnabled.Add(1)
	}

	m.ACLBNodePortConfig.WithLabelValues(config.NodePortMode, config.NodePortAlg, config.NodePortAcceleration).Add(1)

	if config.BGPAnnouncePodCIDR || config.BGPAnnounceLBIP || config.EnableBGPControlPlane {
		m.ACLBBGPEnabled.Add(1)
	}

	if config.EnableIPv4EgressGateway {
		m.ACLBEgressGatewayEnabled.Add(1)
	}

	if params.IsBandwidthManagerEnabled() {
		m.ACLBBandwidthManagerEnabled.Add(1)
	}

	if config.EnableSCTP {
		m.ACLBSCTPEnabled.Add(1)
	}

	if config.EnableVTEP {
		m.ACLBVTEPEnabled.Add(1)
	}
}
