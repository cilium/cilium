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
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumvteppolicy",path="ciliumvteppolicies",scope="Cluster",shortName={vtep-policy}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumVtepPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumVtepPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumVtepPolicyList is a list of CiliumVtepPolicy objects.
type CiliumVtepPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumVtepPolicy.
	Items []CiliumVtepPolicy `json:"items"`
}

// +kubebuilder:validation:Format=cidr
type CIDR string

// +kubebuilder:validation:Pattern=`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
// regex source: https://uibakery.io/regex-library/mac-address
type MAC string

type CiliumVtepPolicySpec struct {
	// +kubebuilder:validation:MaxItems=30
	// CiliumVtepPolicyRules represents a list of rules by which traffic is
	// selected from/to the pods.
	Selectors []CiliumVtepPolicyRules `json:"selectors,omitempty"`

	// +kubebuilder:validation:MaxItems=30
	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs,omitempty"`

	// ExternalVTEP is the remote VTEP outside Cilium network.
	ExternalVTEP *ExternalVTEP `json:"externalVTEP,omitempty"`
}

// External VTEP identifies the node outside cilium network that should act
// as a gateway for traffic matching the vtep policy
type ExternalVTEP struct {
	// IP is the VTEP IP (remote node terminating VXLAN tunnel)
	//
	// Example:
	// When set to "192.168.1.100", matching traffic will be
	// redirected to the VXLAN tunnel towards IP address 192.168.1.100.
	//
	// +kubebuilder:validation:Format=ipv4
	IP string `json:"ip,omitempty"`

	// MAC is a remote MAC address on the other side of VXLAN tunnel. This is
	// needed to build l2 and avoid ARP.
	//
	// Example:
	// 00:11:22:33:44:55 that belongs to VXLAN tunnel interface on the remote side
	MAC MAC `json:"mac,omitempty"`
}

type CiliumVtepPolicyRules struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// This is a label selector which selects Pods by Node. This field follows standard label
	// selector semantics; if present but empty, it selects all nodes.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`
}
