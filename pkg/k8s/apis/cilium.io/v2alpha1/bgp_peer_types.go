// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPPeerConfigList is a list of CiliumBGPPeer objects.
type CiliumBGPPeerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeer.
	Items []CiliumBGPPeerConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgppeerconfig",path="ciliumbgppeerconfigs",scope="Cluster",shortName={cbgppeer}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumBGPPeerConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the CiliumBGPPeerConfig.
	Spec CiliumBGPPeerConfigSpec `json:"spec"`
}

type CiliumBGPPeerConfigSpec struct {
	// Transport defines the BGP transport parameters for the peer.
	//
	// If not specified, the default transport parameters are used.
	//
	// +kubebuilder:validation:Optional
	Transport *CiliumBGPTransport `json:"transport,omitempty"`

	// Timers defines the BGP timers for the peer.
	//
	// If not specified, the default timers are used.
	//
	// +kubebuilder:validation:Optional
	Timers *CiliumBGPTimers `json:"timers,omitempty"`

	// AuthSecretRef is the name of the secret to use to fetch a TCP
	// authentication password for this peer.
	//
	// If not specified, no authentication is used.
	//
	// +kubebuilder:validation:Optional
	AuthSecretRef *string `json:"authSecretRef,omitempty"`

	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this peer.
	//
	// If not specified, the graceful restart capability is disabled.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart *CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`

	// EBGPMultihopTTL controls the multi-hop feature for eBGP peers.
	// Its value defines the Time To Live (TTL) value used in BGP
	// packets sent to the peer.
	//
	// If not specified, EBGP multihop is disabled. This field is ignored for iBGP neighbors.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=1
	EBGPMultihop *int32 `json:"ebgpMultihop,omitempty"`

	// Families, if provided, defines a set of AFI/SAFIs the speaker will
	// negotiate with it's peer.
	//
	// If not specified, the default families of IPv6/unicast and IPv4/unicast will be created.
	//
	// +kubebuilder:validation:Optional
	Families []CiliumBGPFamilyWithAdverts `json:"families,omitempty"`
}

// CiliumBGPFamily represents a AFI/SAFI address family pair.
type CiliumBGPFamily struct {
	// Afi is the Address Family Identifier (AFI) of the family.
	//
	// +kubebuilder:validation:Enum=ipv4;ipv6;l2vpn;ls;opaque
	// +kubebuilder:validation:Required
	Afi string `json:"afi"`

	// Safi is the Subsequent Address Family Identifier (SAFI) of the family.
	//
	// +kubebuilder:validation:Enum=unicast;multicast;mpls_label;encapsulation;vpls;evpn;ls;sr_policy;mup;mpls_vpn;mpls_vpn_multicast;route_target_constraints;flowspec_unicast;flowspec_vpn;key_value
	// +kubebuilder:validation:Required
	Safi string `json:"safi"`
}

// CiliumBGPFamilyWithAdverts represents a AFI/SAFI address family pair along with reference to BGP Advertisements.
type CiliumBGPFamilyWithAdverts struct {
	CiliumBGPFamily `json:",inline"`

	// Advertisements selects group of BGP Advertisement(s) to advertise for this family.
	//
	// If not specified, no advertisements are sent for this family.
	//
	// This field is ignored in CiliumBGPNeighbor which is used in CiliumBGPPeeringPolicy.
	// Use CiliumBGPPeeringPolicy advertisement options instead.
	//
	// +kubebuilder:validation:Optional
	Advertisements *slimv1.LabelSelector `json:"advertisements,omitempty"`
}

// CiliumBGPTransport defines the BGP transport parameters for the peer.
type CiliumBGPTransport struct {
	// LocalPort is the local port to be used for the BGP session.
	//
	// If not specified, defaults to TCP port 179.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=179
	LocalPort *int32 `json:"localPort,omitempty"`

	// PeerPort is the peer port to be used for the BGP session.
	//
	// If not specified, defaults to TCP port 179.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=179
	PeerPort *int32 `json:"peerPort,omitempty"`
}

type CiliumBGPTimers struct {
	// ConnectRetryTimeSeconds defines the initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	//
	// If not specified, defaults to 120 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=120
	ConnectRetryTimeSeconds *int32 `json:"connectRetryTimeSeconds,omitempty"`

	// HoldTimeSeconds defines the initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	// Updating this value will cause a session reset.
	//
	// If not specified, defaults to 90 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=90
	HoldTimeSeconds *int32 `json:"holdTimeSeconds,omitempty"`

	// KeepaliveTimeSeconds defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	// It can not be larger than HoldTimeSeconds. Updating this value will cause a session reset.
	//
	// If not specified, defaults to 30 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=30
	KeepAliveTimeSeconds *int32 `json:"keepAliveTimeSeconds,omitempty"`
}
