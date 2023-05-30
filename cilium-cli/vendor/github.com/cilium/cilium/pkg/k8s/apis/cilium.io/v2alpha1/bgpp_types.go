// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
	// If nil this policy applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector"`
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
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled"`
	// RestartTime is the estimated time it will take for the BGP
	// session to be re-established with peer after a restart.
	// After this period, peer will remove stale routes. This is
	// described RFC 4724 section 4.2.
	//
	// Default is 120s if empty or zero.
	// Rounded internally to the nearest whole second.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=duration
	RestartTime metav1.Duration `json:"restartTime"`
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
	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN int `json:"peerASN"`
	// ConnectRetryTime defines the initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	// The default value for the ConnectRetryTime (if empty or zero) is 120 seconds.
	// Rounded internally to the nearest whole second.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=duration
	ConnectRetryTime metav1.Duration `json:"connectRetryTime,omitempty"`
	// HoldTime defines the initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	// The default value for the HoldTime (if empty or zero) is 90 seconds.
	// Rounded internally to the nearest whole second. Updating this value will cause a session reset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=duration
	HoldTime metav1.Duration `json:"holdTime,omitempty"`
	// KeepaliveTime defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	// The default value for the KeepaliveTime (if empty or zero) is 1/3 of the HoldTime.
	// Rounded internally to the nearest whole second. Updating this value will cause a session reset.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=duration
	KeepAliveTime metav1.Duration `json:"keepAliveTime,omitempty"`
	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this neighbor.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`
}

// CiliumBGPVirtualRouter defines a discrete BGP virtual router configuration.
type CiliumBGPVirtualRouter struct {
	// LocalASN is the ASN of this virtual router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN int `json:"localASN"`
	// ExportPodCIDR determines whether to export the Node's private CIDR block
	// to the configured neighbors.
	//
	// +kubebuilder:validation:Optional
	ExportPodCIDR bool `json:"exportPodCIDR"`
	// ServiceSelector selects a group of load balancer services which this
	// virtual router will announce.
	//
	// If nil no services will be announced.
	//
	// +kubebuilder:validation:Optional
	ServiceSelector *slimv1.LabelSelector `json:"serviceSelector"`
	// Neighbors is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Neighbors []CiliumBGPNeighbor `json:"neighbors"`
}
