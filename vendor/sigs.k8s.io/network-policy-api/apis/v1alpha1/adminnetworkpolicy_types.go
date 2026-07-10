/*
Copyright 2020 The Kubernetes Authors.

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
// +kubebuilder:resource:shortName=anp,scope=Cluster
// +kubebuilder:printcolumn:name="Priority",type=string,JSONPath=".spec.priority"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AdminNetworkPolicy is  a cluster level resource that is part of the
// AdminNetworkPolicy API.
type AdminNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Specification of the desired behavior of AdminNetworkPolicy.
	Spec AdminNetworkPolicySpec `json:"spec"`

	// Status is the status to be reported by the implementation.
	// +optional
	Status AdminNetworkPolicyStatus `json:"status,omitempty"`
}

// AdminNetworkPolicyStatus defines the observed state of AdminNetworkPolicy.
type AdminNetworkPolicyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions" patchStrategy:"merge" patchMergeKey:"type"`
}

// AdminNetworkPolicySpec defines the desired state of AdminNetworkPolicy.
type AdminNetworkPolicySpec struct {
	// Priority is a value from 0 to 1000. Policies with lower priority values have
	// higher precedence, and are checked before policies with higher priority values.
	// All AdminNetworkPolicy rules have higher precedence than NetworkPolicy or
	// BaselineAdminNetworkPolicy rules.
	// If two (or more) policies with the same priority could both match a connection,
	// then the implementation can apply any of the matching policies to the
	// connection, and there is no way for the user to reliably determine which one it
	// will choose. Administrators must be careful about assigning the priorities for
	// policies with rules that will match many connections, and ensure that policies
	// have unique priority values in cases where ambiguity would be unacceptable.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Subject defines the pods to which this AdminNetworkPolicy applies.
	// Note that host-networked pods are not included in subject selection.
	//
	Subject AdminNetworkPolicySubject `json:"subject"`

	// Ingress is the list of Ingress rules to be applied to the selected pods.
	// A total of 100 rules will be allowed in each ANP instance.
	// The relative precedence of ingress rules within a single ANP object (all of
	// which share the priority) will be determined by the order in which the rule
	// is written. Thus, a rule that appears at the top of the ingress rules
	// would take the highest precedence.
	// ANPs with no ingress rules do not affect ingress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Ingress []AdminNetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress is the list of Egress rules to be applied to the selected pods.
	// A total of 100 rules will be allowed in each ANP instance.
	// The relative precedence of egress rules within a single ANP object (all of
	// which share the priority) will be determined by the order in which the rule
	// is written. Thus, a rule that appears at the top of the egress rules
	// would take the highest precedence.
	// ANPs with no egress rules do not affect egress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Egress []AdminNetworkPolicyEgressRule `json:"egress,omitempty"`
}

// AdminNetworkPolicyIngressRule describes an action to take on a particular
// set of traffic destined for pods selected by an AdminNetworkPolicy's
// Subject field.
type AdminNetworkPolicyIngressRule struct {
	// Name is an identifier for this rule, that may be no more than 100 characters
	// in length. This field should be used by the implementation to help
	// improve observability, readability and error-reporting for any applied
	// AdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	// Currently the following actions are supported:
	// Allow: allows the selected traffic (even if it would otherwise have been denied by NetworkPolicy)
	// Deny: denies the selected traffic
	// Pass: instructs the selected traffic to skip any remaining ANP rules, and
	// then pass execution to any NetworkPolicies that select the pod.
	// If the pod is not selected by any NetworkPolicies then execution
	// is passed to any BaselineAdminNetworkPolicies that select the pod.
	//
	Action AdminNetworkPolicyRuleAction `json:"action"`

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

// AdminNetworkPolicyEgressRule describes an action to take on a particular
// set of traffic originating from pods selected by a AdminNetworkPolicy's
// Subject field.
// <network-policy-api:experimental:validation>
// +kubebuilder:validation:XValidation:rule="!(self.to.exists(peer, has(peer.networks) || has(peer.nodes) || has(peer.domainNames)) && has(self.ports) && self.ports.exists(port, has(port.namedPort)))",message="networks/nodes/domainNames peer cannot be set with namedPorts since there are no namedPorts for networks/nodes/domainNames"
type AdminNetworkPolicyEgressRule struct {
	// Name is an identifier for this rule, that may be no more than 100 characters
	// in length. This field should be used by the implementation to help
	// improve observability, readability and error-reporting for any applied
	// AdminNetworkPolicies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching traffic.
	// Currently the following actions are supported:
	// Allow: allows the selected traffic (even if it would otherwise have been denied by NetworkPolicy)
	// Deny: denies the selected traffic
	// Pass: instructs the selected traffic to skip any remaining ANP rules, and
	// then pass execution to any NetworkPolicies that select the pod.
	// If the pod is not selected by any NetworkPolicies then execution
	// is passed to any BaselineAdminNetworkPolicies that select the pod.
	//
	Action AdminNetworkPolicyRuleAction `json:"action"`

	// To is the List of destinations whose traffic this rule applies to.
	// If any element matches the destination of outgoing
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	To []AdminNetworkPolicyEgressPeer `json:"to"`

	// Ports allows for matching traffic based on port and protocols.
	// This field is a list of destination ports for the outgoing egress traffic.
	// If Ports is not set then the rule does not filter traffic via port.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Ports *[]AdminNetworkPolicyPort `json:"ports,omitempty"`
}

// AdminNetworkPolicyRuleAction string describes the AdminNetworkPolicy action type.
//
// +enum
// +kubebuilder:validation:Enum={"Allow", "Deny", "Pass"}
type AdminNetworkPolicyRuleAction string

// AdminNetworkPolicyEgressPeer defines a peer to allow traffic to.
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
type AdminNetworkPolicyEgressPeer struct {
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

	// DomainNames provides a way to specify domain names as peers.
	//
	// DomainNames is only supported for ALLOW rules. In order to control
	// access, DomainNames Allow rules should be used with a lower priority
	// egress deny -- this allows the admin to maintain an explicit "allowlist"
	// of reachable domains.
	//
	// DomainNames can have up to 25 domain names specified in one rule.
	//
	// <network-policy-api:experimental>
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	DomainNames []DomainName `json:"domainNames,omitempty"`
}

// DomainName describes one or more domain names to be used as a peer.
//
// DomainName can be an exact match, or use the wildcard specifier '*' to match
// one or more labels.
//
// '*', the wildcard specifier, matches one or more entire labels. It does not
// support partial matches. '*' may only be specified as a prefix.
//
// Examples:
//   - `kubernetes.io` matches only `kubernetes.io`.
//     It does not match "www.kubernetes.io", "blog.kubernetes.io",
//     "my-kubernetes.io", or "wikipedia.org".
//   - `blog.kubernetes.io` matches only "blog.kubernetes.io".
//     It does not match "www.kubernetes.io" or "kubernetes.io".
//   - `*.kubernetes.io` matches subdomains of kubernetes.io.
//     "www.kubernetes.io", "blog.kubernetes.io", and
//     "latest.blog.kubernetes.io" match, however "kubernetes.io", and
//     "wikipedia.org" do not.
//
// +kubebuilder:validation:Pattern=`^(\*\.)?([a-zA-z0-9]([-a-zA-Z0-9_]*[a-zA-Z0-9])?\.)+[a-zA-z0-9]([-a-zA-Z0-9_]*[a-zA-Z0-9])?\.?$`
type DomainName string

const (
	// AdminNetworkPolicyRuleActionAllow indicates that matching traffic will be
	// allowed regardless of NetworkPolicy and BaselineAdminNetworkPolicy
	// rules. Users cannot block traffic which has been matched by an "Allow"
	// rule in an AdminNetworkPolicy.
	AdminNetworkPolicyRuleActionAllow AdminNetworkPolicyRuleAction = "Allow"
	// AdminNetworkPolicyRuleActionDeny indicates that matching traffic will be
	// denied before being checked against NetworkPolicy or
	// BaselineAdminNetworkPolicy rules. Pods will never receive traffic which
	// has been matched by a "Deny" rule in an AdminNetworkPolicy.
	AdminNetworkPolicyRuleActionDeny AdminNetworkPolicyRuleAction = "Deny"
	// AdminNetworkPolicyRuleActionPass indicates that matching traffic will
	// bypass further AdminNetworkPolicy processing (ignoring rules with lower
	// precedence) and be allowed or denied based on NetworkPolicy and
	// BaselineAdminNetworkPolicy rules.
	AdminNetworkPolicyRuleActionPass AdminNetworkPolicyRuleAction = "Pass"
)

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdminNetworkPolicyList contains a list of AdminNetworkPolicy
type AdminNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdminNetworkPolicy `json:"items"`
}
