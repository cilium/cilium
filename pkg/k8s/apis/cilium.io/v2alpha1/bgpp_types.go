// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	// DefaultBGPExportPodCIDR defines the default value for ExportPodCIDR determining whether to export the Node's private CIDR block.
	DefaultBGPExportPodCIDR = false
	// DefaultBGPPeerLocalPort defines the default value for the local port over which to connect to the peer.
	// By default, BGP control plane will not set this value, and the kernel will pick a random port source port.
	DefaultBGPPeerLocalPort = 0
	// DefaultBGPPeerPort defines the TCP port number of a CiliumBGPNeighbor when PeerPort is unspecified.
	DefaultBGPPeerPort = 179
	// DefaultBGPEBGPMultihopTTL defines the default value for the TTL value used in BGP packets sent to the eBGP neighbors.
	DefaultBGPEBGPMultihopTTL = 1
	// DefaultBGPConnectRetryTimeSeconds defines the default initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	DefaultBGPConnectRetryTimeSeconds = 120
	// DefaultBGPHoldTimeSeconds defines the default initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	DefaultBGPHoldTimeSeconds = 90
	// DefaultBGPKeepAliveTimeSeconds defines the default initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	DefaultBGPKeepAliveTimeSeconds = 30
	// DefaultBGPGRRestartTimeSeconds defines default Restart Time for graceful restart (RFC 4724, section 4.2)
	DefaultBGPGRRestartTimeSeconds = 120
	// BGPLoadBalancerClass defines the BGP Control Plane load balancer class for Services.
	BGPLoadBalancerClass = "io.cilium/bgp-control-plane"
	// PodCIDRSelectorName defines the name for a selector matching Pod CIDRs
	// (standard cluster scope / Kubernetes IPAM CIDRs, not Multi-Pool IPAM CIDRs).
	PodCIDRSelectorName = "PodCIDR"
	// CiliumLoadBalancerIPPoolSelectorName defines the name for a selector matching CiliumLoadBalancerIPPool resources.
	CiliumLoadBalancerIPPoolSelectorName = "CiliumLoadBalancerIPPool"
	// CiliumPodIPPoolSelectorName defines the name for a selector matching CiliumPodIPPool resources.
	CiliumPodIPPoolSelectorName = CPIPKindDefinition
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgppeeringpolicy",path="ciliumbgppeeringpolicies",scope="Cluster",shortName={bgpp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumBGPPeeringPolicy is a Kubernetes third-party resource for instructing
// Cilium's BGP control plane to create virtual BGP routers.
type CiliumBGPPeeringPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human readable description of a BGP peering policy
	//
	// +kubebuilder:validation:Optional
	Spec CiliumBGPPeeringPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPPeeringPolicyList is a list of
// CiliumBGPPeeringPolicy objects.
type CiliumBGPPeeringPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeeringPolicies.
	Items []CiliumBGPPeeringPolicy `json:"items"`
}

// CiliumBGPPeeringPolicySpec specifies one or more CiliumBGPVirtualRouter(s)
// to apply to nodes matching it's label selector.
type CiliumBGPPeeringPolicySpec struct {
	// NodeSelector selects a group of nodes where this BGP Peering
	// Policy applies.
	//
	// If empty / nil this policy applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`
	// A list of CiliumBGPVirtualRouter(s) which instructs
	// the BGP control plane how to instantiate virtual BGP routers.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	VirtualRouters []CiliumBGPVirtualRouter `json:"virtualRouters"`
}

type CiliumBGPNeighborGracefulRestart struct {
	// Enabled flag, when set enables graceful restart capability.
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`
	// RestartTimeSeconds is the estimated time it will take for the BGP
	// session to be re-established with peer after a restart.
	// After this period, peer will remove stale routes. This is
	// described RFC 4724 section 4.2.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4095
	// +kubebuilder:default=120
	RestartTimeSeconds *int32 `json:"restartTimeSeconds,omitempty"`
}

func (gr *CiliumBGPNeighborGracefulRestart) SetDefaults() {
	if gr.RestartTimeSeconds == nil || *gr.RestartTimeSeconds == 0 {
		gr.RestartTimeSeconds = pointer.Int32(DefaultBGPGRRestartTimeSeconds)
	}
}

// BGPStandardCommunity type represents a value of the "standard" 32-bit BGP Communities Attribute (RFC 1997)
// as a 4-byte decimal number or two 2-byte decimal numbers separated by a colon (<0-65535>:<0-65535>).
// For example, no-export community value is 65553:65281.
// +kubebuilder:validation:Pattern=`^([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5])$|^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]):([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`
type BGPStandardCommunity string

// BGPWellKnownCommunity type represents a value of the "standard" 32-bit BGP Communities Attribute (RFC 1997)
// as a well-known string alias to its numeric value. Allowed values and their mapping to the numeric values:
//
//	internet                   = 0x00000000 (0:0)
//	planned-shut               = 0xffff0000 (65535:0)
//	accept-own                 = 0xffff0001 (65535:1)
//	route-filter-translated-v4 = 0xffff0002 (65535:2)
//	route-filter-v4            = 0xffff0003 (65535:3)
//	route-filter-translated-v6 = 0xffff0004 (65535:4)
//	route-filter-v6            = 0xffff0005 (65535:5)
//	llgr-stale                 = 0xffff0006 (65535:6)
//	no-llgr                    = 0xffff0007 (65535:7)
//	blackhole                  = 0xffff029a (65535:666)
//	no-export                  = 0xffffff01	(65535:65281)
//	no-advertise               = 0xffffff02 (65535:65282)
//	no-export-subconfed        = 0xffffff03 (65535:65283)
//	no-peer                    = 0xffffff04 (65535:65284)
//
// +kubebuilder:validation:Enum=internet;planned-shut;accept-own;route-filter-translated-v4;route-filter-v4;route-filter-translated-v6;route-filter-v6;llgr-stale;no-llgr;blackhole;no-export;no-advertise;no-export-subconfed;no-peer
type BGPWellKnownCommunity string

// BGPLargeCommunity type represents a value of the BGP Large Communities Attribute (RFC 8092),
// as three 4-byte decimal numbers separated by colons.
// +kubebuilder:validation:Pattern=`^([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5]):([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5]):([0-9]|[1-9][0-9]{1,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5])$`
type BGPLargeCommunity string

// BGPCommunities holds community values of the supported BGP community path attributes.
type BGPCommunities struct {
	// Standard holds a list of "standard" 32-bit BGP Communities Attribute (RFC 1997) values defined as numeric values.
	//
	// +kubebuilder:validation:Optional
	Standard []BGPStandardCommunity `json:"standard,omitempty"`

	// WellKnown holds a list "standard" 32-bit BGP Communities Attribute (RFC 1997) values defined as
	// well-known string aliases to their numeric values.
	//
	// +kubebuilder:validation:Optional
	WellKnown []BGPWellKnownCommunity `json:"wellKnown,omitempty"`

	// Large holds a list of the BGP Large Communities Attribute (RFC 8092) values.
	//
	// +kubebuilder:validation:Optional
	Large []BGPLargeCommunity `json:"large,omitempty"`
}

// CiliumBGPPathAttributes can be used to apply additional path attributes
// to matched routes when advertising them to a BGP peer.
type CiliumBGPPathAttributes struct {
	// SelectorType defines the object type on which the Selector applies:
	// - For "PodCIDR" the Selector matches k8s CiliumNode resources
	//   (path attributes apply to routes announced for PodCIDRs of selected CiliumNodes.
	//   Only affects routes of cluster scope / Kubernetes IPAM CIDRs, not Multi-Pool IPAM CIDRs.
	// - For "CiliumLoadBalancerIPPool" the Selector matches CiliumLoadBalancerIPPool custom resources
	//   (path attributes apply to routes announced for selected CiliumLoadBalancerIPPools).
	// - For "CiliumPodIPPool" the Selector matches CiliumPodIPPool custom resources
	//   (path attributes apply to routes announced for allocated CIDRs of selected CiliumPodIPPools).
	//
	// +kubebuilder:validation:Enum=PodCIDR;CiliumLoadBalancerIPPool;CiliumPodIPPool
	// +kubebuilder:validation:Required
	SelectorType string `json:"selectorType"`

	// Selector selects a group of objects of the SelectorType
	// resulting into routes that will be announced with the configured Attributes.
	// If nil / not set, all objects of the SelectorType are selected.
	//
	// +kubebuilder:validation:Optional
	Selector *slimv1.LabelSelector `json:"selector,omitempty"`

	// Communities defines a set of community values advertised in the supported BGP Communities path attributes.
	// If nil / not set, no BGP Communities path attribute will be advertised.
	//
	// +kubebuilder:validation:Optional
	Communities *BGPCommunities `json:"communities,omitempty"`

	// LocalPreference defines the preference value advertised in the BGP Local Preference path attribute.
	// As Local Preference is only valid for iBGP peers, this value will be ignored for eBGP peers
	// (no Local Preference path attribute will be advertised).
	// If nil / not set, the default Local Preference of 100 will be advertised in
	// the Local Preference path attribute for iBGP peers.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	LocalPreference *int64 `json:"localPreference,omitempty"`
}

// CiliumBGPNeighbor is a neighboring peer for use in a
// CiliumBGPVirtualRouter configuration.
type CiliumBGPNeighbor struct {
	// PeerAddress is the IP address of the peer.
	// This must be in CIDR notation and use a /32 to express
	// a single host.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	PeerAddress string `json:"peerAddress"`
	// PeerPort is the TCP port of the peer. 1-65535 is the range of
	// valid port numbers that can be specified. If unset, defaults to 179.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=179
	PeerPort *int32 `json:"peerPort,omitempty"`
	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN int64 `json:"peerASN"`
	// AuthSecretRef is the name of the secret to use to fetch a TCP
	// authentication password for this peer.
	// +kubebuilder:validation:Optional
	AuthSecretRef *string `json:"authSecretRef,omitempty"`
	// EBGPMultihopTTL controls the multi-hop feature for eBGP peers.
	// Its value defines the Time To Live (TTL) value used in BGP packets sent to the neighbor.
	// The value 1 implies that eBGP multi-hop feature is disabled (only a single hop is allowed).
	// This field is ignored for iBGP peers.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=1
	EBGPMultihopTTL *int32 `json:"eBGPMultihopTTL,omitempty"`
	// ConnectRetryTimeSeconds defines the initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=120
	ConnectRetryTimeSeconds *int32 `json:"connectRetryTimeSeconds,omitempty"`
	// HoldTimeSeconds defines the initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	// Updating this value will cause a session reset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=90
	HoldTimeSeconds *int32 `json:"holdTimeSeconds,omitempty"`
	// KeepaliveTimeSeconds defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	// It can not be larger than HoldTimeSeconds. Updating this value will cause a session reset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=30
	KeepAliveTimeSeconds *int32 `json:"keepAliveTimeSeconds,omitempty"`
	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this neighbor. If empty / nil, the graceful restart capability is disabled.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart *CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`
	// Families, if provided, defines a set of AFI/SAFIs the speaker will
	// negotiate with it's peer.
	//
	// If this slice is not provided the default families of IPv6 and IPv4 will
	// be provided.
	//
	// +kubebuilder:validation:Optional
	Families []CiliumBGPFamily `json:"families"`
	// AdvertisedPathAttributes can be used to apply additional path attributes
	// to selected routes when advertising them to the peer.
	// If empty / nil, no additional path attributes are advertised.
	//
	// +kubebuilder:validation:Optional
	AdvertisedPathAttributes []CiliumBGPPathAttributes `json:"advertisedPathAttributes,omitempty"`
}

// CiliumBGPVirtualRouter defines a discrete BGP virtual router configuration.
type CiliumBGPVirtualRouter struct {
	// LocalASN is the ASN of this virtual router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN int64 `json:"localASN"`
	// ExportPodCIDR determines whether to export the Node's private CIDR block
	// to the configured neighbors.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	ExportPodCIDR *bool `json:"exportPodCIDR,omitempty"`
	// PodIPPoolSelector selects CiliumPodIPPools based on labels. The virtual
	// router will announce allocated CIDRs of matching CiliumPodIPPools.
	//
	// If empty / nil no CiliumPodIPPools will be announced.
	//
	// +kubebuilder:validation:Optional
	PodIPPoolSelector *slimv1.LabelSelector `json:"podIPPoolSelector,omitempty"`
	// ServiceSelector selects a group of load balancer services which this
	// virtual router will announce. The loadBalancerClass for a service must
	// be nil or specify a class supported by Cilium, e.g. "io.cilium/bgp-control-plane".
	// Refer to the following document for additional details regarding load balancer
	// classes:
	//
	//   https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class
	//
	// If empty / nil no services will be announced.
	//
	// +kubebuilder:validation:Optional
	ServiceSelector *slimv1.LabelSelector `json:"serviceSelector,omitempty"`
	// ServiceAdvertisements selects a group of BGP Advertisement(s) to advertise
	// for the selected services.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default={LoadBalancerIP}
	ServiceAdvertisements []BGPServiceAddressType `json:"serviceAdvertisements,omitempty"`
	// Neighbors is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Neighbors []CiliumBGPNeighbor `json:"neighbors"`
}

// SetDefaults applies default values on the CiliumBGPPeeringPolicy.
// This is normally done by kube-apiserver for fields with explicit static defaults,
// the main use of this method is to avoid the need for nil-checks in the controller code.
func (p *CiliumBGPPeeringPolicy) SetDefaults() {
	for i := range p.Spec.VirtualRouters {
		p.Spec.VirtualRouters[i].SetDefaults()
	}
}

// SetDefaults applies default values on the CiliumBGPVirtualRouter.
// This is normally done by kube-apiserver for fields with explicit static defaults,
// the main use of this method is to avoid the need for nil-checks in the controller code.
func (r *CiliumBGPVirtualRouter) SetDefaults() {
	if r.ExportPodCIDR == nil {
		r.ExportPodCIDR = pointer.Bool(DefaultBGPExportPodCIDR)
	}
	for i := range r.Neighbors {
		r.Neighbors[i].SetDefaults()
	}

	if r.ServiceAdvertisements == nil {
		r.ServiceAdvertisements = []BGPServiceAddressType{BGPLoadBalancerIPAddr}
	}
}

// SetDefaults applies default values on the CiliumBGPNeighbor.
// This is normally done by kube-apiserver for fields with explicit static defaults,
// the main use of this method is to avoid the need for nil-checks in the controller code.
func (n *CiliumBGPNeighbor) SetDefaults() {
	if n.PeerPort == nil || *n.PeerPort == 0 {
		n.PeerPort = pointer.Int32(DefaultBGPPeerPort)
	}
	if n.EBGPMultihopTTL == nil {
		n.EBGPMultihopTTL = pointer.Int32(DefaultBGPEBGPMultihopTTL)
	}
	if n.ConnectRetryTimeSeconds == nil || *n.ConnectRetryTimeSeconds == 0 {
		n.ConnectRetryTimeSeconds = pointer.Int32(DefaultBGPConnectRetryTimeSeconds)
	}
	if n.HoldTimeSeconds == nil || *n.HoldTimeSeconds == 0 {
		n.HoldTimeSeconds = pointer.Int32(DefaultBGPHoldTimeSeconds)
	}
	if n.KeepAliveTimeSeconds == nil || *n.KeepAliveTimeSeconds == 0 {
		n.KeepAliveTimeSeconds = pointer.Int32(DefaultBGPKeepAliveTimeSeconds)
	}
	if n.GracefulRestart != nil && n.GracefulRestart.Enabled &&
		(n.GracefulRestart.RestartTimeSeconds == nil || *n.GracefulRestart.RestartTimeSeconds == 0) {
		n.GracefulRestart.RestartTimeSeconds = pointer.Int32(DefaultBGPGRRestartTimeSeconds)
	}
	if len(n.Families) == 0 {
		n.Families = []CiliumBGPFamily{
			{
				Afi:  "ipv4",
				Safi: "unicast",
			},
			{
				Afi:  "ipv6",
				Safi: "unicast",
			},
		}
	}
}

// Validate validates CiliumBGPNeighbor's configuration constraints
// that can not be expressed using the kubebuilder validation markers.
func (n *CiliumBGPNeighbor) Validate() error {
	keepAliveTime := pointer.Int32Deref(n.KeepAliveTimeSeconds, DefaultBGPKeepAliveTimeSeconds)
	holdTime := pointer.Int32Deref(n.HoldTimeSeconds, DefaultBGPHoldTimeSeconds)
	if keepAliveTime > holdTime {
		return fmt.Errorf("KeepAliveTimeSeconds larger than HoldTimeSeconds for peer ASN:%d IP:%s", n.PeerASN, n.PeerAddress)
	}
	return nil
}
