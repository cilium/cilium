// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgpclusterconfig",path="ciliumbgpclusterconfigs",scope="Cluster",shortName={cbgpcluster}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumBGPClusterConfig is the Schema for the CiliumBGPClusterConfig API
type CiliumBGPClusterConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired cluster configuration of the BGP control plane.
	Spec CiliumBGPClusterConfigSpec `json:"spec"`

	// Status is a running status of the cluster configuration
	//
	// +kubebuilder:validation:Optional
	Status CiliumBGPClusterConfigStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPClusterConfigList is a list of CiliumBGPClusterConfig objects.
type CiliumBGPClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPClusterConfig.
	Items []CiliumBGPClusterConfig `json:"items"`
}

type CiliumBGPClusterConfigSpec struct {
	// NodeSelector selects a group of nodes where this BGP Cluster
	// config applies.
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// A list of CiliumBGPInstance(s) which instructs
	// the BGP control plane how to instantiate virtual BGP routers.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []CiliumBGPInstance `json:"bgpInstances"`
}

type CiliumBGPInstance struct {
	// Name is the name of the BGP instance. It is a unique identifier for the BGP instance
	// within the cluster configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this BGP instance.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

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
	Peers []CiliumBGPPeer `json:"peers,omitempty"`
}

type CiliumBGPPeer struct {
	// Name is the name of the BGP peer. It is a unique identifier for the peer within the BGP instance.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs.
	//
	// If peerASN is 0, the BGP OPEN message validation of ASN will be disabled and
	// ASN will be determined based on peer's OPEN message.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:default=0
	PeerASN *int64 `json:"peerASN,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`
}

// PeerConfigReference is a reference to a peer configuration resource.
type PeerConfigReference struct {
	// Name is the name of the peer config resource.
	// Name refers to the name of a Kubernetes object (typically a CiliumBGPPeerConfig).
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type CiliumBGPClusterConfigStatus struct {
	// The current conditions of the CiliumBGPClusterConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for CiliumBGPClusterConfig. When you add a new condition, don't
// forget to update the AllBGPClusterConfigConditions list as well.
const (
	// Node selector selects nothing
	BGPClusterConfigConditionNoMatchingNode = "cilium.io/NoMatchingNode"
	// Referenced peer configs are missing
	BGPClusterConfigConditionMissingPeerConfigs = "cilium.io/MissingPeerConfigs"
	// ClusterConfig with conflicting nodeSelector present
	BGPClusterConfigConditionConflictingClusterConfigs = "cilium.io/ConflictingClusterConfig"
)

var AllBGPClusterConfigConditions = []string{
	BGPClusterConfigConditionNoMatchingNode,
	BGPClusterConfigConditionMissingPeerConfigs,
	BGPClusterConfigConditionConflictingClusterConfigs,
}
