// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	gobgp "github.com/osrg/gobgp/v3/api"
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
	// AdditionalRoutes is a list of BGP Routes to be announced for this virtual router
	//
	// +kubebuilder:validation:Optional
	AdditionalRoutes []CiliumBGPAdditionalRoutes `json:"additionalRoutes,omitempty"`
}

// these should likely be merged with gobgp.GoBGPIPv{4,6}Family
// but are used slightly differently for CiliumBGPAdditionalRoutes
var (
	FamilyAfiMap = map[string]gobgp.Family_Afi{
		"ipv4": gobgp.Family_AFI_IP,
		"ipv6": gobgp.Family_AFI_IP6,
	}

	FamilySafiMap = map[string]gobgp.Family_Safi{
		"unicast": gobgp.Family_SAFI_UNICAST,
	}
)

// CiliumBGPAdditionalRoutes defines a manually injected route
type CiliumBGPAdditionalRoutes struct {
	// AFI is the Address Family Indicator, one of 'ipv4' or 'ipv6'
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ipv4;ipv6
	AFI string `json:"afi"`

	// SAFI is the Subsequent Address Family Indicator, currently only 'unicast' is supported
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=unicast
	SAFI string `json:"safi"`

	// CIDRs is a list of Routes to be advertised
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	// +kubebuilder:validation:MinItems=1
	CIDRs []string `json:"cidrs"`
}
