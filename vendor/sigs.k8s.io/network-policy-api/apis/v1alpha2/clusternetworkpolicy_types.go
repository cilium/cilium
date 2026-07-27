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
package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterNetworkPolicy is a cluster-wide network policy resource.
//
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cnp,scope=Cluster
// +kubebuilder:printcolumn:name="Tier",type=string,JSONPath=".spec.tier"
// +kubebuilder:printcolumn:name="Priority",type=string,JSONPath=".spec.priority"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired behavior of ClusterNetworkPolicy.
	Spec ClusterNetworkPolicySpec `json:"spec"`

	// Status is the status to be reported by the implementation.
	//
	// +optional
	Status ClusterNetworkPolicyStatus `json:"status,omitempty"`
}

// ClusterNetworkPolicyList contains a list of ClusterNetworkPolicy
//
// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ClusterNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterNetworkPolicy `json:"items"`
}

// ClusterNetworkPolicySpec defines the desired state of ClusterNetworkPolicy.
type ClusterNetworkPolicySpec struct {
	// Tier is used as the top-level grouping for network policy prioritization.
	//
	// Policy tiers are evaluated in the following order:
	// * Admin tier
	// * NetworkPolicy tier
	// * Baseline tier
	//
	// ClusterNetworkPolicy can use 2 of these tiers: Admin and Baseline.
	//
	// The Admin tier takes precedence over all other policies. Policies
	// defined in this tier are used to set cluster-wide security rules
	// that cannot be overridden in the other tiers. If Admin tier has
	// made a final decision (Accept or Deny) on a connection, then no
	// further evaluation is done.
	//
	// NetworkPolicy tier is the tier for the namespaced v1.NetworkPolicy.
	// These policies are intended for the application developer to describe
	// the security policy associated with their deployments inside their
	// namespace. v1.NetworkPolicy always makes a final decision for selected
	// pods. Further evaluation only happens for Pods not selected by a
	// v1.NetworkPolicy.
	//
	// Baseline tier is a cluster-wide policy that can be overridden by the
	// v1.NetworkPolicy. If Baseline tier has made a final decision (Accept or
	// Deny) on a connection, then no further evaluation is done.
	//
	// If a given connection wasn't allowed or denied by any of the tiers,
	// the default kubernetes policy is applied, which says that
	// all pods can communicate with each other.
	Tier Tier `json:"tier"`

	// Priority is a value from 0 to 1000 indicating the precedence of
	// the policy within its tier. Policies with lower priority values have
	// higher precedence, and are checked before policies with higher priority
	// values in the same tier. All Admin tier rules have higher precedence than
	// NetworkPolicy or Baseline tier rules.
	// If two (or more) policies in the same tier with the same priority
	// could match a connection, then the implementation can apply any of the
	// matching policies to the connection, and there is no way for the user to
	// reliably determine which one it will choose. Administrators must be
	// careful about assigning the priorities for policies with rules that will
	// match many connections, and ensure that policies have unique priority
	// values in cases where ambiguity would be unacceptable.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Subject defines the pods to which this ClusterNetworkPolicy applies.
	Subject ClusterNetworkPolicySubject `json:"subject"`

	// Ingress is the list of Ingress rules to be applied to the selected pods.
	//
	// A maximum of 25 rules is allowed in this block.
	//
	// The relative precedence of ingress rules within a single CNP object
	// (all of which share the priority) will be determined by the order
	// in which the rule is written.
	// Thus, a rule that appears at the top of the ingress rules
	// would take the highest precedence.
	// CNPs with no ingress rules do not affect ingress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=25
	Ingress []ClusterNetworkPolicyIngressRule `json:"ingress,omitempty"`

	// Egress is the list of Egress rules to be applied to the selected pods.
	//
	// A maximum of 25 rules is allowed in this block.
	//
	// The relative precedence of egress rules within a single CNP object
	// (all of which share the priority) will be determined by the order
	// in which the rule is written.
	// Thus, a rule that appears at the top of the egress rules
	// would take the highest precedence.
	// CNPs with no egress rules do not affect egress traffic.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=25
	Egress []ClusterNetworkPolicyEgressRule `json:"egress,omitempty"`
}

// +kubebuilder:validation:Enum={"Admin", "Baseline"}
type Tier string

const (
	AdminTier    Tier = "Admin"
	BaselineTier Tier = "Baseline"
)

// ClusterNetworkPolicyStatus defines the observed state of
// ClusterNetworkPolicy.
type ClusterNetworkPolicyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions" patchStrategy:"merge" patchMergeKey:"type"`
}

// ClusterNetworkPolicySubject defines what resources the policy applies to.
// Exactly one field must be set.
// Note that host-networked pods are not included in subject selection.
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicySubject struct {
	// Namespaces is used to select pods via namespace selectors.
	// +optional
	Namespaces *metav1.LabelSelector `json:"namespaces,omitempty"`
	// Pods is used to select pods via namespace AND pod selectors.
	// +optional
	Pods *NamespacedPod `json:"pods,omitempty"`
}

// ClusterNetworkPolicyIngressRule describes an action to take on a particular
// set of traffic destined for pods selected by a ClusterNetworkPolicy's
// Subject field.
type ClusterNetworkPolicyIngressRule struct {
	// Name is an identifier for this rule, that may be no more than
	// 100 characters in length. This field should be used by the implementation
	// to help improve observability, readability and error-reporting
	// for any applied policies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching
	// traffic. Currently the following actions are supported:
	//
	// - Accept: Accepts the selected traffic, allowing it into
	//   the destination. No further ClusterNetworkPolicy or
	//   NetworkPolicy rules will be processed.
	//
	//   Note: while Accept ensures traffic is accepted by
	//   Kubernetes network policy, it is still possible that the
	//   packet is blocked in other ways: custom nftable rules,
	//   high-layers e.g. service mesh.
	//
	// - Deny: Drops the selected traffic. No further
	//   ClusterNetworkPolicy or NetworkPolicy rules will be
	//   processed.
	//
	// - Pass: Skips all further ClusterNetworkPolicy rules in the
	//   current tier for the selected traffic, and passes
	//   evaluation to the next tier.
	Action ClusterNetworkPolicyRuleAction `json:"action"`

	// From is the list of sources whose traffic this rule applies to.
	// If any element matches the source of incoming
	// traffic then the specified action is applied.
	// This field must be defined and contain at least one item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	From []ClusterNetworkPolicyIngressPeer `json:"from"`

	// Protocols allows for more fine-grain matching of traffic on
	// protocol-specific attributes such as the port. If
	// unspecified, protocol-specific attributes will not be used
	// to match traffic.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	Protocols []ClusterNetworkPolicyProtocol `json:"protocols,omitempty"`
}

// ClusterNetworkPolicyEgressRule describes an action to take on a particular
// set of traffic originating from pods selected by a ClusterNetworkPolicy's
// Subject field.
//
// <network-policy-api:experimental:validation>
// +kubebuilder:validation:XValidation:rule="!(self.to.exists(peer, has(peer.networks) || has(peer.nodes) || has(peer.domainNames)) && has(self.protocols) && self.protocols.exists(protocol, has(protocol.destinationNamedPort)))",message="networks/nodes/domainNames peer cannot be set with namedPorts since there are no namedPorts for networks/nodes/domainNames"
type ClusterNetworkPolicyEgressRule struct {
	// Name is an identifier for this rule, that may be no more than
	// 100 characters in length. This field should be used by the implementation
	// to help improve observability, readability and error-reporting
	// for any applied policies.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`

	// Action specifies the effect this rule will have on matching
	// traffic.  Currently the following actions are supported:
	//
	// - Accept: Accepts the selected traffic, allowing it to
	//   egress. No further ClusterNetworkPolicy or NetworkPolicy
	//   rules will be processed.
	//
	// - Deny: Drops the selected traffic. No further
	//   ClusterNetworkPolicy or NetworkPolicy rules will be
	//   processed.
	//
	// - Pass: Skips all further ClusterNetworkPolicy rules in the
	//   current tier for the selected traffic, and passes
	//   evaluation to the next tier.
	Action ClusterNetworkPolicyRuleAction `json:"action"`

	// To is the list of destinations whose traffic this rule applies to. If any
	// element matches the destination of outgoing traffic then the specified
	// action is applied. This field must be defined and contain at least one
	// item.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	To []ClusterNetworkPolicyEgressPeer `json:"to"`

	// Protocols allows for more fine-grain matching of traffic on
	// protocol-specific attributes such as the port. If
	// unspecified, protocol-specific attributes will not be used
	// to match traffic.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	Protocols []ClusterNetworkPolicyProtocol `json:"protocols,omitempty"`
}

// ClusterNetworkPolicyRuleAction string describes the ClusterNetworkPolicy
// action type.
//
// +enum
// +kubebuilder:validation:Enum={"Accept", "Deny", "Pass"}
type ClusterNetworkPolicyRuleAction string

const (
	// ClusterNetworkPolicyRuleActionAccept indicates that
	// matching traffic will be accepted and no further policy
	// evaluation will be done. This is a final decision.
	ClusterNetworkPolicyRuleActionAccept ClusterNetworkPolicyRuleAction = "Accept"
	// ClusterNetworkPolicyRuleActionDeny indicates that matching traffic
	// will be denied and no further policy evaluation will be done.
	// This is a final decision.
	ClusterNetworkPolicyRuleActionDeny ClusterNetworkPolicyRuleAction = "Deny"
	// ClusterNetworkPolicyRuleActionPass indicates that matching traffic
	// will jump to the next tier evaluation. That means that all the rules
	// with lower precedence at the same tier will be ignored,
	// but evaluation will continue at the next tier.
	// For example, if an Admin tier CNP uses Pass action,
	// NetworkPolicy evaluation will happen next.
	ClusterNetworkPolicyRuleActionPass ClusterNetworkPolicyRuleAction = "Pass"
)

// ClusterNetworkPolicyIngressPeer defines a peer to allow traffic from.
//
// Exactly one of the fields must be set for a given peer and this is enforced
// by the validation rules on the CRD. If an implementation sees no fields are
// set then it can infer that the deployed CRD is of an incompatible version
// with an unknown field.  In that case it should fail closed.
//
// For "Accept" rules, "fail closed" means: "treat the rule as matching no
// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
// as a 'Deny all' rule".
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyIngressPeer struct {
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
}

// ClusterNetworkPolicyEgressPeer defines a peer to allow traffic to.
//
// Exactly one of the fields must be set for a given peer and this is enforced
// by the validation rules on the CRD. If an implementation sees no fields are
// set then it can infer that the deployed CRD is of an incompatible version
// with an unknown field.  In that case it should fail closed.
//
// For "Accept" rules, "fail closed" means: "treat the rule as matching no
// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
// as a 'Deny all' rule".
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyEgressPeer struct {
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
	//
	// +optional
	Nodes *metav1.LabelSelector `json:"nodes,omitempty"`

	// Networks defines a way to select peers via CIDR blocks.
	// This is intended for representing entities that live outside the cluster,
	// which can't be selected by pods, namespaces and nodes peers, but note
	// that cluster-internal traffic will be checked against the rule as
	// well. So if you Accept or Deny traffic to `"0.0.0.0/0"`, that will allow
	// or deny all IPv4 pod-to-pod traffic as well. If you don't want that,
	// add a rule that Passes all pod traffic before the Networks rule.
	//
	// Each item in Networks should be provided in the CIDR format and should be
	// IPv4 or IPv6, for example "10.0.0.0/8" or "fd00::/8".
	//
	// Networks can have up to 25 CIDRs specified.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	Networks []CIDR `json:"networks,omitempty"`

	// DomainNames provides a way to specify domain names as peers.
	//
	// DomainNames is only supported for Accept rules. In order to control
	// access, DomainNames Accept rules should be used with a lower precedence
	// egress deny -- this allows the admin to maintain an explicit "allowlist"
	// of reachable domains.
	//
	// DomainNames can have up to 25 domain names specified in one rule.
	//
	// <network-policy-api:experimental>
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=25
	DomainNames []DomainName `json:"domainNames,omitempty"`
}

// NamespacedPod allows the user to select a given set of pod(s) in
// selected namespace(s).
type NamespacedPod struct {
	// NamespaceSelector follows standard label selector
	// semantics; if empty, it selects all Namespaces.
	//
	// +optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`

	// PodSelector is used to explicitly select pods within a namespace;
	// if empty, it selects all Pods.
	//
	// +required
	PodSelector metav1.LabelSelector `json:"podSelector"`
}

// ClusterNetworkPolicyProtocol describes additional protocol-specific match rules.
// Exactly one field must be set.
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyProtocol struct {
	// TCP specific protocol matches.
	//
	// +optional
	TCP *ClusterNetworkPolicyProtocolTCP `json:"tcp,omitempty"`

	// UDP specific protocol matches.
	//
	// +optional
	UDP *ClusterNetworkPolicyProtocolUDP `json:"udp,omitempty"`

	// SCTP specific protocol matches.
	//
	// +optional
	SCTP *ClusterNetworkPolicyProtocolSCTP `json:"sctp,omitempty"`

	// DestinationNamedPort selects a destination port on a pod based on the
	// ContainerPort name. You can't use this in a rule that targets resources
	// without named ports (e.g. Nodes or Networks).
	//
	// +optional
	DestinationNamedPort string `json:"destinationNamedPort,omitempty"`
}

// ClusterNetworkPolicyProtocolTCP are TCP attributes to be matched.
//
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyProtocolTCP struct {
	// DestinationPort for the match.
	//
	// +optional
	DestinationPort *Port `json:"destinationPort,omitempty"`
}

// ClusterNetworkPolicyProtocolUDP are UDP attributes to be matched.
//
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyProtocolUDP struct {
	// DestinationPort for the match.
	//
	// +optional
	DestinationPort *Port `json:"destinationPort,omitempty"`
}

// ClusterNetworkPolicyProtocolSCTP are SCTP attributes to be matched.
//
// +kubebuilder:validation:MinProperties=1
type ClusterNetworkPolicyProtocolSCTP struct {
	// DestinationPort for the match.
	//
	// +optional
	DestinationPort *Port `json:"destinationPort,omitempty"`
}

// Port matches on port number. You must specify either Port or Range.
//
// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type Port struct {
	// Number defines a network port value.
	//
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Number int32 `json:"number,omitempty"`

	// Range defines a contiguous range of ports.
	//
	// +optional
	Range *PortRange `json:"range,omitempty"`
}

// PortRange defines an inclusive range of ports from the assigned
// Start value to End value.
//
// +kubebuilder:validation:XValidation:rule="self.start < self.end", message="Start port must be less than End port"
type PortRange struct {
	// start defines a network port that is the start of a port
	// range, the Start value must be less than End.
	//
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// end specifies the last port in the range. It must be
	// greater than start.
	//
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// CIDR is an IP address range in CIDR notation
// (for example, "10.0.0.0/8" or "fd00::/8").
//
// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="Invalid CIDR format provided"
// +kubebuilder:validation:MaxLength=43
type CIDR string

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
