// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
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
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type CiliumBGPPeerConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the CiliumBGPPeerConfig.
	Spec CiliumBGPPeerConfigSpec `json:"spec"`

	// Status is the running status of the CiliumBGPPeerConfig
	//
	// +kubebuilder:validation:Optional
	Status CiliumBGPPeerConfigStatus `json:"status"`
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

type CiliumBGPPeerConfigStatus struct {
	// The current conditions of the CiliumBGPPeerConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for CiliumBGPPeerConfig. When you add a new condition, don't
// forget to to update the below AllBGPPeerConfigConditions list as well.
const (
	// Referenced auth secret is missing
	BGPPeerConfigConditionMissingAuthSecret = "cilium.io/MissingAuthSecret"
)

var AllBGPPeerConfigConditions = []string{
	BGPPeerConfigConditionMissingAuthSecret,
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

func (t *CiliumBGPTransport) SetDefaults() {
	if t.PeerPort == nil || *t.PeerPort == 0 {
		t.PeerPort = ptr.To[int32](DefaultBGPPeerPort)
	}
}

// CiliumBGPTimers defines timers configuration for a BGP peer.
//
// +kubebuilder:validation:XValidation:rule="self.keepAliveTimeSeconds <= self.holdTimeSeconds", message="keepAliveTimeSeconds can not be larger than holdTimeSeconds"
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

func (t *CiliumBGPTimers) SetDefaults() {
	if t.ConnectRetryTimeSeconds == nil || *t.ConnectRetryTimeSeconds == 0 {
		t.ConnectRetryTimeSeconds = ptr.To[int32](DefaultBGPConnectRetryTimeSeconds)
	}

	if t.HoldTimeSeconds == nil || *t.HoldTimeSeconds == 0 {
		t.HoldTimeSeconds = ptr.To[int32](DefaultBGPHoldTimeSeconds)
	}

	if t.KeepAliveTimeSeconds == nil || *t.KeepAliveTimeSeconds == 0 {
		t.KeepAliveTimeSeconds = ptr.To[int32](DefaultBGPKeepAliveTimeSeconds)
	}
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
		gr.RestartTimeSeconds = ptr.To[int32](DefaultBGPGRRestartTimeSeconds)
	}
}

func (p *CiliumBGPPeerConfigSpec) SetDefaults() {
	if p == nil {
		return
	}

	if p.Transport == nil {
		p.Transport = &CiliumBGPTransport{}
	}
	p.Transport.SetDefaults()

	if p.Timers == nil {
		p.Timers = &CiliumBGPTimers{}
	}
	p.Timers.SetDefaults()

	if p.EBGPMultihop == nil {
		p.EBGPMultihop = ptr.To[int32](DefaultBGPEBGPMultihopTTL)
	}

	if p.GracefulRestart == nil {
		p.GracefulRestart = &CiliumBGPNeighborGracefulRestart{}
	}
	p.GracefulRestart.SetDefaults()

	if len(p.Families) == 0 {
		p.Families = []CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
			},
			{
				CiliumBGPFamily: CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
			},
		}
	}
}
