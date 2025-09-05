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

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))$`
// + The regex for the IPv6 CIDR range (second part of the OR) was taken from
// + https://blog.markhatton.co.uk/2011/03/15/regular-expressions-for-ip-addresses-cidr-ranges-and-hostnames/`
type CIDR string

// +kubebuilder:vaildation:Pattern=`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
// + The regex for the MAC address was taken from
// + https://uibakery.io/regex-library/mac-address
type MAC string

type CiliumVtepPolicySpec struct {
	// CiliumVtepPolicyRules represents a list of rules by which traffic is
	// selected from/to the pods.
	Selectors []CiliumVtepPolicyRules `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []CIDR `json:"destinationCIDRs"`

	// ExternalVTEP is the remote VTEP outside Cilium network.
	ExternalVTEP *ExternalVTEP `json:"externalVTEP"`
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

	// RMAC is a remote MAC address on the other side of VXLAN tunnel. This is
	// needed to build l2
	//
	// Example:
	// 00:11:22:33:44:55 that belongs to VXLAN tunnel interface on the remote side
	RMAC MAC `json:"rmac,omitempty"`
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
