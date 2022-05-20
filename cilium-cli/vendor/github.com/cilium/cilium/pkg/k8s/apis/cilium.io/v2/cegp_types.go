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
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumegressgatewaypolicy",path="ciliumegressgatewaypolicies",scope="Cluster",shortName={cegp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumEgressGatewayPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumEgressGatewayPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEgressGatewayPolicyList is a list of CiliumEgressGatewayPolicy objects.
type CiliumEgressGatewayPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEgressGatewayPolicy.
	Items []CiliumEgressGatewayPolicy `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
type IPv4CIDR string

type CiliumEgressGatewayPolicySpec struct {
	// Egress represents a list of rules by which egress traffic is
	// filtered from the source pods.
	Selectors []EgressRule `json:"selectors"`

	// DestinationCIDRs is a list of destination CIDRs for destination IP addresses.
	// If a destination IP matches any one CIDR, it will be selected.
	DestinationCIDRs []IPv4CIDR `json:"destinationCIDRs"`

	// EgressGateway is the gateway node responsible for SNATing traffic.
	EgressGateway *EgressGateway `json:"egressGateway"`
}

// EgressGateway identifies the node that should act as egress gateway for a
// given egress Gateway policy. In addition to that it also specifies the
// configuration of said node (which egress IP or network interface should be
// used to SNAT traffic).
type EgressGateway struct {
	// This is a label selector which selects the node that should act as
	// egress gateway for the given policy.
	// In case multiple nodes are selected, only the first one in the
	// lexical ordering over the node names will be used.
	// This field follows standard label selector semantics.
	//
	// +kubebuilder:validation:Required
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector"`

	// Interface is the network interface to which the egress IP address
	// that the traffic is SNATed with is assigned.
	//
	// Example:
	// When set to "eth1", matching egress traffic will be redirected to the
	// node matching the NodeSelector field and SNATed with the first IPv4
	// address assigned to the eth1 interface.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	Interface string `json:"interface,omitempty"`

	// EgressIP is the source IP address that the egress traffic is SNATed
	// with.
	//
	// Example:
	// When set to "192.168.1.100", matching egress traffic will be
	// redirected to the node matching the NodeSelector field and SNATed
	// with IP address 192.168.1.100.
	//
	// When none of the Interface or EgressIP fields is specified, the
	// policy will use the first IPv4 assigned to the interface with the
	// default route.
	//
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	EgressIP string `json:"egressIP,omitempty"`
}

type EgressRule struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}
