// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iputil "github.com/cilium/cilium/pkg/ip"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

// QoSMechanismType is the kind of QoS marking or scheduling a mechanism
// provides.
//
// +kubebuilder:validation:Enum=DSCP;NodePriority
type QoSMechanismType string

const (
	// QoSMechanismDSCP marks the DSCP field of the IPv4 ToS / IPv6 Traffic
	// Class header, so that the priority is carried with the packet and can
	// be honored by devices outside of the cluster.
	QoSMechanismDSCP QoSMechanismType = "DSCP"

	// QoSMechanismNodePriority sets the node-local skb priority consumed by
	// the FQ scheduler. It is not preserved once the packet leaves the node.
	QoSMechanismNodePriority QoSMechanismType = "NodePriority"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumqos},singular="ciliumqosmechanism",path="ciliumqosmechanisms",scope="Cluster",shortName={cqm}
// +kubebuilder:printcolumn:JSONPath=".spec.type",name="Type",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumQoSMechanism declares that a QoS mechanism is available for use in the
// cluster. It is owned by the cluster provider: a CiliumQoSClass may only
// reference a mechanism that has been declared here.
type CiliumQoSMechanism struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumQoSMechanismSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status CiliumQoSMechanismStatus `json:"status,omitempty"`
}

type CiliumQoSMechanismSpec struct {
	// Type is the QoS mechanism being declared.
	//
	// +kubebuilder:validation:Required
	Type QoSMechanismType `json:"type"`

	// Description is a human readable explanation of what the mechanism
	// provides in this cluster.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
}

type CiliumQoSMechanismStatus struct {
	// Conditions report whether the mechanism can be served by the running
	// datapath.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumQoSMechanismList is a list of CiliumQoSMechanism objects.
type CiliumQoSMechanismList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumQoSMechanism.
	Items []CiliumQoSMechanism `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumqos},singular="ciliumqosclass",path="ciliumqosclasses",scope="Cluster",shortName={cqc}
// +kubebuilder:printcolumn:JSONPath=".spec.mechanismRef.name",name="Mechanism",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.priority",name="Priority",type=integer
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumQoSClass is a reusable QoS profile built on top of a declared
// CiliumQoSMechanism. It is owned by the infrastructure admin, who translates
// the site's traffic classes ("voice", "guaranteed", ...) into concrete
// mechanism parameters that application developers can then reference by name.
type CiliumQoSClass struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumQoSClassSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status CiliumQoSClassStatus `json:"status,omitempty"`
}

type CiliumQoSClassSpec struct {
	// Priority breaks ties between classes that are selected for the same
	// flow by equally specific rules. The higher number wins.
	//
	// Priority is mechanism-local: it only orders classes that share the
	// same underlying mechanism, and never arbitrates between mechanisms
	// that are applied concurrently.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=0
	Priority int32 `json:"priority,omitempty"`

	// MechanismRef selects the CiliumQoSMechanism this class configures.
	//
	// +kubebuilder:validation:Required
	MechanismRef QoSMechanismReference `json:"mechanismRef"`

	// Parameters configures the referenced mechanism. Exactly one of its
	// fields must be set, and it has to be the one matching the type of the
	// referenced mechanism.
	//
	// +kubebuilder:validation:Required
	Parameters QoSClassParameters `json:"parameters"`
}

// QoSMechanismReference references a cluster-scoped CiliumQoSMechanism by name.
type QoSMechanismReference struct {
	// Name of the CiliumQoSMechanism.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// QoSClassParameters holds the per-mechanism configuration of a
// CiliumQoSClass. It is a union: the field that has to be populated is
// determined by the type of the referenced mechanism.
//
// +kubebuilder:validation:XValidation:rule="[has(self.dscp), has(self.nodePriority)].exists_one(x, x)",message="exactly one of dscp or nodePriority must be set"
type QoSClassParameters struct {
	// DSCP configures a class backed by a mechanism of type DSCP.
	//
	// +kubebuilder:validation:Optional
	DSCP *DSCPParameters `json:"dscp,omitempty"`

	// NodePriority configures a class backed by a mechanism of type
	// NodePriority.
	//
	// +kubebuilder:validation:Optional
	NodePriority *NodePriorityParameters `json:"nodePriority,omitempty"`
}

// DSCPParameters configures DSCP marking.
type DSCPParameters struct {
	// Value is the DSCP codepoint written into matching packets. The whole
	// 0-63 range is accepted: how it is divided up is a property of the
	// network the cluster runs in, not of Cilium.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63
	Value uint8 `json:"value"`
}

// NodePriorityLevel is a node-local scheduling class.
//
// +kubebuilder:validation:Enum=Guaranteed;Burstable;BestEffort
type NodePriorityLevel string

const (
	NodePriorityGuaranteed NodePriorityLevel = "Guaranteed"
	NodePriorityBurstable  NodePriorityLevel = "Burstable"
	NodePriorityBestEffort NodePriorityLevel = "BestEffort"
)

// NodePriorityParameters configures node-local prioritization.
type NodePriorityParameters struct {
	// Priority is the scheduling class matching packets are put in on the
	// node they egress from.
	//
	// +kubebuilder:validation:Required
	Priority NodePriorityLevel `json:"priority"`
}

type CiliumQoSClassStatus struct {
	// Conditions report whether the class resolves to a declared and
	// supported mechanism.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumQoSClassList is a list of CiliumQoSClass objects.
type CiliumQoSClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumQoSClass.
	Items []CiliumQoSClass `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumqos},singular="ciliumqospolicy",path="ciliumqospolicies",scope="Namespaced",shortName={cqp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumQoSPolicy applies QoS classes to the egress traffic of the pods it
// selects. It is owned by the application developer, who picks from the
// classes the infrastructure admin has published.
type CiliumQoSPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec CiliumQoSPolicySpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status CiliumQoSPolicyStatus `json:"status,omitempty"`
}

type CiliumQoSPolicySpec struct {
	// PodSelector selects the pods, within the namespace of the policy, whose
	// egress traffic the rules apply to. An empty selector selects every pod
	// in the namespace.
	//
	// +kubebuilder:validation:Required
	PodSelector *slimv1.LabelSelector `json:"podSelector"`

	// Egress is the list of rules applied to traffic leaving the selected
	// pods.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Egress []QoSEgressRule `json:"egress"`
}

// QoSEgressRule assigns QoS classes to the subset of egress traffic it
// matches. A rule with neither ToCIDR nor ToPorts matches all egress traffic
// of the selected pods.
type QoSEgressRule struct {
	// ToCIDR matches traffic by destination address. If set, a packet has to
	// fall into one of the prefixes for the rule to apply.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=64
	ToCIDR []iputil.Prefix `json:"toCIDR,omitempty"`

	// ToPorts matches traffic by destination port and protocol. If set, a
	// packet has to match one of the entries for the rule to apply.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=40
	ToPorts []QoSPortRule `json:"toPorts,omitempty"`

	// FromPorts matches traffic by the source port it leaves the selected pod
	// with. If set, a packet has to match one of the entries for the rule to
	// apply.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=40
	FromPorts []QoSPortRule `json:"fromPorts,omitempty"`

	// QoSClassRefs are the classes applied to the matching traffic. At most
	// one class per mechanism may take effect for a given packet; conflicts
	// between rules of equal specificity are resolved by class priority.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	QoSClassRefs []QoSClassReference `json:"qosClassRefs"`
}

// QoSClassReference references a cluster-scoped CiliumQoSClass by name.
type QoSClassReference struct {
	// Name of the CiliumQoSClass.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// QoSPortRule is a set of ports and protocols matched by a QoSEgressRule.
type QoSPortRule struct {
	// Ports is the list of port and protocol pairs to match on.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=40
	Ports []QoSPortProtocol `json:"ports"`
}

// QoSPortProtocol is a single L4 port, or contiguous port range, together with
// the protocol it is matched on.
type QoSPortProtocol struct {
	// Port is an L4 port number. Named ports are not supported: QoS is
	// resolved without knowledge of the container that terminates the flow.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})$`
	Port string `json:"port"`

	// EndPort makes the entry match the range [Port, EndPort]. It has to be
	// greater than or equal to Port.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	EndPort int32 `json:"endPort,omitempty"`

	// Protocol is the L4 protocol. If "ANY", omitted or empty, TCP, UDP and
	// SCTP all match.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP;ANY
	Protocol api.L4Proto `json:"protocol,omitempty"`
}

type CiliumQoSPolicyStatus struct {
	// Conditions report whether the policy resolves to existing classes and
	// has been realized.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumQoSPolicyList is a list of CiliumQoSPolicy objects.
type CiliumQoSPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumQoSPolicy.
	Items []CiliumQoSPolicy `json:"items"`
}
