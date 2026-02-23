/*
Copyright 2022.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// All fields in this package are required unless Explicitly marked optional
// +kubebuilder:validation:Required
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=banp,scope=Cluster
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="Only one baseline admin network policy with metadata.name=\"default\" can be created in the cluster"
// BaselineAdminNetworkPolicy is a cluster level resource that is part of the
// AdminNetworkPolicy API.
type BaselineAdminNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Specification of the desired behavior of BaselineAdminNetworkPolicy.
	Spec BaselineAdminNetworkPolicySpec `json:"spec"`

	// Status is the status to be reported by the implementation.
	// +optional
	Status BaselineAdminNetworkPolicyStatus `json:"status,omitempty"`
}

// BaselineAdminNetworkPolicyStatus defines the observed state of
// BaselineAdminNetworkPolicy.
type BaselineAdminNetworkPolicyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions" patchStrategy:"merge" patchMergeKey:"type"`
}

// BaselineAdminNetworkPolicySpec defines the desired state of
// BaselineAdminNetworkPolicy.
type BaselineAdminNetworkPolicySpec struct {
	// Subject defines the pods to which this BaselineAdminNetworkPolicy applies.
	// Note that host-networked pods are not included in subject selection.
	//
	Subject AdminNetworkPolicySubject `json:"subject"`

	// Ingress is the list of Ingress rules to be applied to the selected pods
	// if they are not matched by any AdminNetworkPolicy or NetworkPolicy rules.
	// A total of 100 Ingress rules will be allowed in each BANP instance.
	// The relative precedence of ingress rules within a single BANP object
	// will be determined by the order in which the rule is written.
	// Thus, a rule that appears at the top of the ingress rules
	// would take the highest precedence.
	// BANPs with no ingress rules do not affect ingress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Ingress []BaselineAdminNetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress is the list of Egress rules to be applied to the selected pods if
	// they are not matched by any AdminNetworkPolicy or NetworkPolicy rules.
	// A total of 100 Egress rules will be allowed in each BANP instance.
	// The relative precedence of egress rules within a single BANP object
	// will be determined by the order in which the rule is written.
	// Thus, a rule that appears at the top of the egress rules
	// would take the highest precedence.
	// BANPs with no egress rules do not affect egress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Egress []BaselineAdminNetworkPolicyEgressRule `json:"egress,omitempty"`
}

// BaselineAdminNetworkPolicyIngressRule describes an action to take on a particular
// set of traffic destined for pods selected by a BaselineAdminNetworkPolicy's
// Subject field.
type BaselineAdminNetworkPolicyIngressRule struct {
	// Name is an identifier for this rule, that may be no more than 100 characters
	// in length. This field should be used by the implementation to help
	// improve observability, readability and error-reporting for any applied
	// BaselineAdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	// Currently the following actions are supported:
	// Allow: allows the selected traffic
	// Deny: denies the selected traffic
	//
	Action BaselineAdminNetworkPolicyRuleAction `json:"action"`

	// From is the list of sources whose traffic this rule applies to.
	// If any element matches the source of incoming
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	From []AdminNetworkPolicyIngressPeer `json:"from"`

	// Ports allows for matching traffic based on port and protocols.
	// This field is a list of ports which should be matched on
	// the pods selected for this policy i.e the subject of the policy.
	// So it matches on the destination port for the ingress traffic.
	// If Ports is not set then the rule does not filter traffic via port.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Ports *[]AdminNetworkPolicyPort `json:"ports,omitempty"`
}

// BaselineAdminNetworkPolicyEgressRule describes an action to take on a particular
// set of traffic originating from pods selected by a BaselineAdminNetworkPolicy's
// Subject field.
// <network-policy-api:experimental:validation>
// +kubebuilder:validation:XValidation:rule="!(self.to.exists(peer, has(peer.networks) || has(peer.nodes)) && has(self.ports) && self.ports.exists(port, has(port.namedPort)))",message="networks/nodes peer cannot be set with namedPorts since there are no namedPorts for networks/nodes"
type BaselineAdminNetworkPolicyEgressRule struct {
	// Name is an identifier for this rule, that may be no more than 100 characters
	// in length. This field should be used by the implementation to help
	// improve observability, readability and error-reporting for any applied
	// BaselineAdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	// Currently the following actions are supported:
	// Allow: allows the selected traffic
	// Deny: denies the selected traffic
	//
	Action BaselineAdminNetworkPolicyRuleAction `json:"action"`

	// To is the list of destinations whose traffic this rule applies to.
	// If any element matches the destination of outgoing
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	//
	To []BaselineAdminNetworkPolicyEgressPeer `json:"to"`

	// Ports allows for matching traffic based on port and protocols.
	// This field is a list of destination ports for the outgoing egress traffic.
	// If Ports is not set then the rule does not filter traffic via port.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Ports *[]AdminNetworkPolicyPort `json:"ports,omitempty"`
}

// BaselineAdminNetworkPolicyRuleAction string describes the BaselineAdminNetworkPolicy
// action type.
//
// +enum
// +kubebuilder:validation:Enum={"Allow", "Deny"}
type BaselineAdminNetworkPolicyRuleAction string

// BaselineAdminNetworkPolicyEgressPeer defines a peer to allow traffic to.
//
// Exactly one of the fields must be set for a given peer and this is enforced
// by the validation rules on the CRD. If an implementation sees no fields are
// set then it can infer that the deployed CRD is of an incompatible version
// with an unknown field.  In that case it should fail closed.
//
// For "Allow" rules, "fail closed" means: "treat the rule as matching no
// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
// as a 'Deny all' rule".
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type BaselineAdminNetworkPolicyEgressPeer struct {
	// Namespaces defines a way to select all pods within a set of Namespaces.
	// Note that host-networked pods are not included in this type of peer.
	//
	// +optional
	Namespaces *metav1.LabelSelector `json:"namespaces,omitempty"`
	// Pods defines a way to select a set of pods in
	// a set of namespaces. Note that host-networked pods
	// are not included in this type of peer.
	//
	// +optional
	Pods *NamespacedPod `json:"pods,omitempty"`
	// Nodes defines a way to select a set of nodes in
	// the cluster (based on the node's labels). It selects
	// the nodeIPs as the peer type by matching on the IPs
	// present in the node.Status.Addresses field of the node.
	// This field follows standard label selector
	// semantics; if present but empty, it selects all Nodes.
	//
	// <network-policy-api:experimental>
	// +optional
	Nodes *metav1.LabelSelector `json:"nodes,omitempty"`
	// Networks defines a way to select peers via CIDR blocks.
	// This is intended for representing entities that live outside the cluster,
	// which can't be selected by pods, namespaces and nodes peers, but note
	// that cluster-internal traffic will be checked against the rule as
	// well. So if you Allow or Deny traffic to `"0.0.0.0/0"`, that will allow
	// or deny all IPv4 pod-to-pod traffic as well. If you don't want that,
	// add a rule that Passes all pod traffic before the Networks rule.
	//
	// Each item in Networks should be provided in the CIDR format and should be
	// IPv4 or IPv6, for example "10.0.0.0/8" or "fd00::/8".
	//
	// Networks can have upto 25 CIDRs specified.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	Networks []CIDR `json:"networks,omitempty"`
}

const (
	// BaselineAdminNetworkPolicyRuleActionDeny enables admins to deny traffic.
	BaselineAdminNetworkPolicyRuleActionDeny BaselineAdminNetworkPolicyRuleAction = "Deny"
	// BaselineAdminNetworkPolicyRuleActionAllow enables admins to allow certain traffic.
	BaselineAdminNetworkPolicyRuleActionAllow BaselineAdminNetworkPolicyRuleAction = "Allow"
)

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BaselineAdminNetworkPolicyList contains a list of BaselineAdminNetworkPolicy
type BaselineAdminNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BaselineAdminNetworkPolicy `json:"items"`
}
