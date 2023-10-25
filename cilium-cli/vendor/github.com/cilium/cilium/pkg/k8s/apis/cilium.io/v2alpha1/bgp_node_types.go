// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgpnodeconfig",path="ciliumbgpnodeconfigs",scope="Cluster",shortName={cbgpnode}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumBGPNodeConfig is node local configuration for BGP agent. Name of the object should be node name.
// This resource will be created by Cilium operator and is read-only for the users.
type CiliumBGPNodeConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the CiliumBGPNodeConfig.
	Spec CiliumBGPNodeSpec `json:"spec"`

	// Status is the most recently observed status of the CiliumBGPNodeConfig.
	Status CiliumBGPNodeStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPNodeConfigList is a list of CiliumBGPNodeConfig objects.
type CiliumBGPNodeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPNodeConfig.
	Items []CiliumBGPNodeConfig `json:"items"`
}

type CiliumBGPNodeSpec struct {
	// BGPInstances is a list of BGP router instances on the node.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []CiliumBGPNodeInstance `json:"bgpInstances"`
}

// CiliumBGPNodeInstance is a single BGP router instance configuration on the node.
type CiliumBGPNodeInstance struct {
	// Name is the name of the BGP instance. This name is used to identify the BGP instance on the node.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this virtual router.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// RouterID is the BGP router ID of this virtual router.
	// This configuration is derived from CiliumBGPNodeConfigOverride resource.
	//
	// If not specified, the router ID will be derived from the node local address.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	RouterID *string `json:"routerID,omitempty"`

	// LocalPort is the port on which the BGP daemon listens for incoming connections.
	//
	// If not specified, BGP instance will not listen for incoming connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	LocalPort *int32 `json:"localPort,omitempty"`

	// Peers is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []CiliumBGPNodePeer `json:"peers,omitempty"`
}

type CiliumBGPNodePeer struct {
	// Name is the name of the BGP peer. This name is used to identify the BGP peer for the BGP instance.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN *int64 `json:"peerASN,omitempty"`

	// LocalAddress is the IP address of the local interface to use for the peering session.
	// This configuration is derived from CiliumBGPNodeConfigOverride resource. If not specified, the local address will be used for setting up peering.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	LocalAddress *string `json:"localAddress,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`
}

// CiliumBGPNodeStatus is the status of the CiliumBGPNodeConfig.
type CiliumBGPNodeStatus struct {
	// BGPInstances is the status of the BGP instances on the node.
	//
	// +kubebuilder:validation:Required
	// +listType=map
	// +listMapKey=name
	BGPInstances []CiliumBGPNodeInstanceStatus `json:"bgpInstances"`
}

type CiliumBGPNodeInstanceStatus struct {
	// Name is the name of the BGP instance. This name is used to identify the BGP instance on the node.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// LocalASN is the ASN of this BGP instance.
	//
	// +kubebuilder:validation:Optional
	LocalASN *int64 `json:"localASN,omitempty"`

	// PeerStatuses is the state of the BGP peers for this BGP instance.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	PeerStatuses []CiliumBGPNodePeerStatus `json:"peers,omitempty"`
}

// CiliumBGPNodePeerStatus is the status of a BGP peer.
type CiliumBGPNodePeerStatus struct {
	// Name is the name of the BGP peer.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	//
	// +kubebuilder:validation:Required
	PeerAddress string `json:"peerAddress"`

	// PeerASN is the ASN of the neighbor.
	//
	// +kubebuilder:validation:Optional
	PeerASN *int64 `json:"peerASN,omitempty"`

	// PeeringState is last known state of the peering session.
	//
	// +kubebuilder:validation:Optional
	PeeringState *string `json:"peeringState,omitempty"`

	// Timers is the state of the negotiated BGP timers for this peer.
	//
	// +kubebuilder:validation:Optional
	Timers *CiliumBGPTimersState `json:"timers,omitempty"`

	// Uptime is the time since the last peering session was established.
	//
	// +kubebuilder:validation:Optional
	Uptime *string `json:"uptime,omitempty"`

	// RoutesReceived is the number of routes received from this peer.
	//
	// +kubebuilder:validation:Optional
	RoutesReceived *int32 `json:"routesReceived,omitempty"`

	// RoutesAdvertised is the number of routes advertised to this peer.
	//
	// +kubebuilder:validation:Optional
	RoutesAdvertised *int32 `json:"routesAdvertised,omitempty"`
}

// CiliumBGPTimersState is the state of the negotiated BGP timers for a peer.
type CiliumBGPTimersState struct {
	// AppliedHoldTimeSeconds is the negotiated hold time for this peer.
	//
	// +kubebuilder:validation:Optional
	AppliedHoldTimeSeconds *int32 `json:"appliedHoldTimeSeconds,omitempty"`

	// AppliedKeepaliveSeconds is the negotiated keepalive time for this peer.
	//
	// +kubebuilder:validation:Optional
	AppliedKeepaliveSeconds *int32 `json:"appliedKeepaliveSeconds,omitempty"`
}
