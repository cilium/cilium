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
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=120
	RestartTimeSeconds *int32 `json:"restartTimeSeconds,omitempty"`
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
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=90
	HoldTimeSeconds *int32 `json:"holdTimeSeconds,omitempty"`
	// KeepaliveTimeSeconds defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	// It can not be larger than HoldTimeSeconds. Updating this value will cause a session reset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=30
	KeepAliveTimeSeconds *int32 `json:"keepAliveTimeSeconds,omitempty"`
	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this neighbor. If empty / nil, the graceful restart capability is disabled.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart *CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`
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
	// ServiceSelector selects a group of load balancer services which this
	// virtual router will announce.
	//
	// If empty / nil no services will be announced.
	//
	// +kubebuilder:validation:Optional
	ServiceSelector *slimv1.LabelSelector `json:"serviceSelector,omitempty"`
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
