// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgpnodeconfigoverride",path="ciliumbgpnodeconfigoverrides",scope="Cluster",shortName={cbgpnodeoverride}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumBGPNodeConfigOverride specifies configuration overrides for a CiliumBGPNodeConfig.
// It allows fine-tuning of BGP behavior on a per-node basis. For the override to be effective,
// the names in CiliumBGPNodeConfigOverride and CiliumBGPNodeConfig must match exactly. This
// matching ensures that specific node configurations are applied correctly and only where intended.
type CiliumBGPNodeConfigOverride struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the CiliumBGPNodeConfigOverride.
	Spec CiliumBGPNodeConfigOverrideSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPNodeConfigOverrideList is a list of CiliumBGPNodeConfigOverride objects.
type CiliumBGPNodeConfigOverrideList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPNodeConfigOverride.
	Items []CiliumBGPNodeConfigOverride `json:"items"`
}

type CiliumBGPNodeConfigOverrideSpec struct {
	// BGPInstances is a list of BGP instances to override.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	BGPInstances []CiliumBGPNodeConfigInstanceOverride `json:"bgpInstances"`
}

// CiliumBGPNodeConfigInstanceOverride defines configuration options which can be overridden for a specific BGP instance.
type CiliumBGPNodeConfigInstanceOverride struct {
	// Name is the name of the BGP instance for which the configuration is overridden.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// RouterID is BGP router id to use for this instance. It must be unique across all BGP instances.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	RouterID *string `json:"routerID,omitempty"`

	// LocalPort is port to use for this BGP instance.
	//
	// +kubebuilder:validation:Optional
	LocalPort *int32 `json:"localPort,omitempty"`

	// Peers is a list of peer configurations to override.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []CiliumBGPNodeConfigPeerOverride `json:"peers,omitempty"`
}

// CiliumBGPNodeConfigPeerOverride defines configuration options which can be overridden for a specific peer.
type CiliumBGPNodeConfigPeerOverride struct {
	// Name is the name of the peer for which the configuration is overridden.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalAddress is the IP address to use for connecting to this peer.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	LocalAddress *string `json:"localAddress,omitempty"`

	// LocalPort is source port to use for connecting to this peer.
	//
	// +kubebuilder:validation:Optional
	LocalPort *int32 `json:"localPort,omitempty"`
}
