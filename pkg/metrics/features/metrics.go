// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Metrics represents a collection of metrics related to a specific feature.
// Each field is named according to the specific feature that it tracks.
type Metrics struct {
	CPIPAM                        metric.Vec[metric.Gauge]
	CPIdentityAllocation          metric.Vec[metric.Gauge]
	CPCiliumEndpointSlicesEnabled metric.Gauge

	DPMode         metric.Vec[metric.Gauge]
	DPChaining     metric.Vec[metric.Gauge]
	DPIP           metric.Vec[metric.Gauge]
	DPDeviceConfig metric.Vec[metric.Gauge]

	NPHostFirewallEnabled        metric.Gauge
	NPLocalRedirectPolicyEnabled metric.Gauge
	NPMutualAuthEnabled          metric.Gauge
	NPNonDefaultDenyEnabled      metric.Gauge
	NPCIDRPoliciesToNodes        metric.Vec[metric.Gauge]

	ACLBTransparentEncryption        metric.Vec[metric.Gauge]
	ACLBKubeProxyReplacementEnabled  metric.Gauge
	ACLBNodePortConfig               metric.Vec[metric.Gauge]
	ACLBBGPEnabled                   metric.Gauge
	ACLBEgressGatewayEnabled         metric.Gauge
	ACLBBandwidthManagerEnabled      metric.Gauge
	ACLBSCTPEnabled                  metric.Gauge
	ACLBInternalTrafficPolicyEnabled metric.Gauge
	ACLBVTEPEnabled                  metric.Gauge
	ACLBCiliumEnvoyConfigEnabled     metric.Gauge
	ACLBBigTCPEnabled                metric.Vec[metric.Gauge]
	ACLBL2LBEnabled                  metric.Gauge
	ACLBL2PodAnnouncementEnabled     metric.Gauge
	ACLBExternalEnvoyProxyEnabled    metric.Vec[metric.Gauge]
	ACLBCiliumNodeConfigEnabled      metric.Gauge

	NPL3Ingested                metric.Vec[metric.Counter]
	NPHostNPIngested            metric.Vec[metric.Counter]
	NPDNSIngested               metric.Vec[metric.Counter]
	NPToFQDNsIngested           metric.Vec[metric.Counter]
	NPHTTPIngested              metric.Vec[metric.Counter]
	NPHTTPHeaderMatchesIngested metric.Vec[metric.Counter]
	NPOtherL7Ingested           metric.Vec[metric.Counter]
	NPDenyPoliciesIngested      metric.Vec[metric.Counter]
	NPIngressCIDRGroupIngested  metric.Vec[metric.Counter]
	NPMutualAuthIngested        metric.Vec[metric.Counter]
	NPTLSInspectionIngested     metric.Vec[metric.Counter]
	NPSNIAllowListIngested      metric.Vec[metric.Counter]
	NPNonDefaultDenyIngested    metric.Vec[metric.Counter]
	NPLRPIngested               metric.Vec[metric.Counter]
	NPCNPIngested               metric.Vec[metric.Counter]
	NPCCNPIngested              metric.Vec[metric.Counter]

	ACLBInternalTrafficPolicyIngested        metric.Vec[metric.Counter]
	ACLBCiliumEnvoyConfigIngested            metric.Vec[metric.Counter]
	ACLBCiliumClusterwideEnvoyConfigIngested metric.Vec[metric.Counter]

	ACLBClusterMeshEnabled metric.Vec[metric.Gauge]
}

const (
	subsystemCP   = "feature_controlplane"
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
	networkChainingModePortmap     = "portmap"

	networkIPv4      = "ipv4-only"
	networkIPv6      = "ipv6-only"
	networkDualStack = "ipv4-ipv6-dual-stack"

	advConnNetEncIPSec     = "ipsec"
	advConnNetEncWireGuard = "wireguard"

	advConnBigTCPIPv4      = "ipv4-only"
	advConnBigTCPIPv6      = "ipv6-only"
	advConnBigTCPDualStack = "ipv4-ipv6-dual-stack"

	advConnExtEnvoyProxyStandalone = "standalone"
	advConnExtEnvoyProxyEmbedded   = "embedded"
	actionAdd                      = "add"
	actionDel                      = "delete"

	advConnClusterMeshMaxConnectedClusters255 = defaults.MaxConnectedClusters
	advConnClusterMeshMaxConnectedClusters511 = types.ClusterIDExt511

	advConnClusterMeshModeAPIServer       = clustermesh.ClusterMeshModeClusterMeshAPIServer
	advConnClusterMeshModeETCD            = clustermesh.ClusterMeshModeETCD
	advConnClusterMeshModeKVStoreMesh     = clustermesh.ClusterMeshModeKVStoreMesh
	advConnClusterMeshModeAPIServerOrETCD = clustermesh.ClusterMeshModeClusterMeshAPIServerOrETCD
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
		networkChainingModePortmap,
	}

	defaultIPAddressFamilies = []string{
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
		loadbalancer.LBModeSNAT,
		loadbalancer.LBModeDSR,
		loadbalancer.LBModeHybrid,
	}

	defaultNodePortModeAlgorithms = []string{
		loadbalancer.LBAlgorithmMaglev,
		loadbalancer.LBAlgorithmRandom,
	}

	defaultNodePortModeAccelerations = []string{
		option.NodePortAccelerationDisabled,
		option.NodePortAccelerationGeneric,
		option.NodePortAccelerationBestEffort,
		option.NodePortAccelerationNative,
	}

	defaultBigTCPAddressFamilies = []string{
		advConnBigTCPIPv4,
		advConnBigTCPIPv6,
		advConnBigTCPDualStack,
	}

	defaultExternalEnvoyProxyModes = []string{
		advConnExtEnvoyProxyStandalone,
		advConnExtEnvoyProxyEmbedded,
	}
	defaultActions = []string{
		actionAdd,
		actionDel,
	}

	defaultClusterMeshMode = []string{
		advConnClusterMeshModeAPIServer,
		advConnClusterMeshModeETCD,
		advConnClusterMeshModeKVStoreMesh,
		advConnClusterMeshModeAPIServerOrETCD,
	}

	defaultClusterMeshMaxConnectedClusters = []string{
		fmt.Sprintf("%d", advConnClusterMeshMaxConnectedClusters255),
		fmt.Sprintf("%d", advConnClusterMeshMaxConnectedClusters511),
	}
)

// NewMetrics returns all feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewMetrics(withDefaults bool) Metrics {
	return Metrics{
		CPIPAM: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "IPAM mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemCP,
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

		CPIdentityAllocation: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Identity Allocation mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemCP,
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

		CPCiliumEndpointSlicesEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium Endpoint Slices enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemCP,
			Name:      "cilium_endpoint_slices_enabled",
		}),

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
				Name: "address_family", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultIPAddressFamilies...,
					)
				}(),
			},
		}),

		DPDeviceConfig: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Datapath config mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemDP,
			Name:      "config",
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

		NPNonDefaultDenyEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Non DefaultDeny Policies is enabled in the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "non_defaultdeny_policies_enabled",
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
			Help:      "BGP enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "bgp_enabled",
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

		ACLBInternalTrafficPolicyEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "K8s Internal Traffic Policy enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "k8s_internal_traffic_policy_enabled",
		}),

		ACLBVTEPEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "VTEP enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "vtep_enabled",
		}),

		ACLBCiliumEnvoyConfigEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium Envoy Config enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "cilium_envoy_config_enabled",
		}),

		ACLBBigTCPEnabled: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Big TCP enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "big_tcp_enabled",
		}, metric.Labels{
			{
				Name: "address_family", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultBigTCPAddressFamilies...,
					)
				}(),
			},
		}),

		ACLBL2LBEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "L2 LB announcement enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "l2_lb_enabled",
		}),

		ACLBL2PodAnnouncementEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "L2 pod announcement enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "l2_pod_announcement_enabled",
		}),

		ACLBExternalEnvoyProxyEnabled: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Envoy Proxy mode enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "envoy_proxy_enabled",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultExternalEnvoyProxyModes...,
					)
				}(),
			},
		}),

		ACLBCiliumNodeConfigEnabled: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium Node Config enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "cilium_node_config_enabled",
		}),

		NPL3Ingested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Layer 3 and Layer 4 policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "l3_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPHostNPIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Host Network Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "host_network_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPDNSIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "DNS Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "dns_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPToFQDNsIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "ToFQDNs Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "fqdn_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPHTTPIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "HTTP/GRPC Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "http_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPHTTPHeaderMatchesIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "HTTP HeaderMatches Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "http_header_matches_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPOtherL7Ingested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Other L7 Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "other_l7_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPDenyPoliciesIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Deny Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "deny_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPIngressCIDRGroupIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Ingress CIDR Group Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "ingress_cidr_group_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPMutualAuthIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Mutual Auth Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "mutual_auth_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPTLSInspectionIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "TLS Inspection Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "tls_inspection_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPSNIAllowListIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "SNI Allow List Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "sni_allow_list_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPNonDefaultDenyIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Non DefaultDeny Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "non_defaultdeny_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPLRPIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Local Redirect Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "local_redirect_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		ACLBInternalTrafficPolicyIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "K8s Services with Internal Traffic Policy have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "internal_traffic_policy_services_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPCNPIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Cilium Network Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "cilium_network_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		NPCCNPIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Cilium Clusterwide Network Policies have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "cilium_clusterwide_network_policies_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		ACLBCiliumEnvoyConfigIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Cilium Envoy Config have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "cilium_envoy_config_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		ACLBCiliumClusterwideEnvoyConfigIngested: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Help:      "Cilium Clusterwide Envoy Config have been ingested since the agent started",
			Namespace: metrics.Namespace,
			Subsystem: subsystemNP,
			Name:      "cilium_clusterwide_envoy_config_total",
		}, metric.Labels{
			{
				Name: "action", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultActions...,
					)
				}(),
			},
		}),

		ACLBClusterMeshEnabled: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Mode of the active Cluster Mesh connections/peers",
			Namespace: metrics.Namespace,
			Subsystem: subsystemACLB,
			Name:      "clustermesh_enabled",
		}, metric.Labels{
			{
				Name: "mode", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultClusterMeshMode...,
					)
				}(),
			},
			{
				Name: "max_connected_clusters", Values: func() metric.Values {
					if !withDefaults {
						return nil
					}
					return metric.NewValues(
						defaultClusterMeshMaxConnectedClusters...,
					)
				}(),
			},
		}),
	}
}

type featureMetrics interface {
	update(params enabledFeatures, config *option.DaemonConfig, lbConfig loadbalancer.Config)
}

func (m Metrics) update(params enabledFeatures, config *option.DaemonConfig, lbConfig loadbalancer.Config) {
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
	m.CPIPAM.WithLabelValues(ipamMode).Add(1)

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
	m.CPIdentityAllocation.WithLabelValues(identityAllocationMode).Add(1)

	if config.EnableCiliumEndpointSlice {
		m.CPCiliumEndpointSlicesEnabled.Add(1)
	}

	deviceMode := config.DatapathMode
	m.DPDeviceConfig.WithLabelValues(deviceMode).Add(1)

	if config.EnableHostFirewall {
		m.NPHostFirewallEnabled.Add(1)
	}

	if config.EnableLocalRedirectPolicy {
		m.NPLocalRedirectPolicyEnabled.Add(1)
	}

	if params.IsMutualAuthEnabled() {
		m.NPMutualAuthEnabled.Add(1)
	}

	if config.EnableNonDefaultDenyPolicies {
		m.NPNonDefaultDenyEnabled.Add(1)
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

	m.ACLBNodePortConfig.WithLabelValues(lbConfig.LBMode, lbConfig.LBAlgorithm, config.NodePortAcceleration).Add(1)

	if config.EnableBGPControlPlane {
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

	if config.EnableInternalTrafficPolicy {
		m.ACLBInternalTrafficPolicyEnabled.Add(1)
	}

	if config.EnableVTEP {
		m.ACLBVTEPEnabled.Add(1)
	}

	if config.EnableEnvoyConfig {
		m.ACLBCiliumEnvoyConfigEnabled.Add(1)
	}

	var bigTCPProto string
	switch {
	case params.BigTCPConfig().IsIPv4Enabled() && params.BigTCPConfig().IsIPv6Enabled():
		bigTCPProto = advConnBigTCPDualStack
	case params.BigTCPConfig().IsIPv4Enabled():
		bigTCPProto = advConnBigTCPIPv4
	case params.BigTCPConfig().IsIPv6Enabled():
		bigTCPProto = advConnBigTCPIPv6
	}

	if bigTCPProto != "" {
		m.ACLBBigTCPEnabled.WithLabelValues(bigTCPProto).Add(1)
	}

	if config.EnableL2Announcements {
		m.ACLBL2LBEnabled.Add(1)
	}

	if params.IsL2PodAnnouncementEnabled() {
		m.ACLBL2PodAnnouncementEnabled.Add(1)
	}

	if config.ExternalEnvoyProxy {
		m.ACLBExternalEnvoyProxyEnabled.WithLabelValues(advConnExtEnvoyProxyStandalone).Add(1)
	} else {
		m.ACLBExternalEnvoyProxyEnabled.WithLabelValues(advConnExtEnvoyProxyEmbedded).Add(1)
	}

	if params.IsDynamicConfigSourceKindNodeConfig() {
		m.ACLBCiliumNodeConfigEnabled.Add(1)
	}
}
