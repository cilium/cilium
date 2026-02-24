// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// L2AnnounceLoadBalancerClass defines the L2 Announcer load balancer class for Services.
const L2AnnounceLoadBalancerClass = "io.cilium/l2-announcer"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliuml2announcementpolicy",path="ciliuml2announcementpolicies",scope="Cluster",shortName={l2announcement}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumL2AnnouncementPolicy is a Kubernetes third-party resource which
// is used to defined which nodes should announce what services on the
// L2 network.
type CiliumL2AnnouncementPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human readable description of a L2 announcement policy
	//
	// +kubebuilder:validation:Optional
	Spec CiliumL2AnnouncementPolicySpec `json:"spec,omitempty"`

	// Status is the status of the policy.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumL2AnnouncementPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumL2AnnouncementPolicyList is a list of
// CiliumL2AnnouncementPolicy objects.
type CiliumL2AnnouncementPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumL2AnnouncementPolicies.
	Items []CiliumL2AnnouncementPolicy `json:"items"`
}

// +deepequal-gen=true

// CiliumL2AnnouncementPolicySpec specifies which nodes should announce what
// services to the L2 networks attached to the given list of interfaces.
type CiliumL2AnnouncementPolicySpec struct {
	// NodeSelector selects a group of nodes which will announce the IPs for
	// the services selected by the service selector.
	//
	// If nil this policy applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector"`
	// ServiceSelector selects a set of services which will be announced over L2 networks.
	// The loadBalancerClass for a service must be nil or specify a supported class, e.g.
	// "io.cilium/l2-announcer". Refer to the following document for additional details
	// regarding load balancer classes:
	//
	//   https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class
	//
	// If nil this policy applies to all services.
	//
	// +kubebuilder:validation:Optional
	ServiceSelector *slimv1.LabelSelector `json:"serviceSelector"`
	// If true, the loadbalancer IPs of the services are announced
	//
	// If nil this policy applies to all services.
	//
	// +kubebuilder:validation:Optional
	LoadBalancerIPs bool `json:"loadBalancerIPs"`
	// If true, the external IPs of the services are announced
	//
	// +kubebuilder:validation:Optional
	ExternalIPs bool `json:"externalIPs"`
	// A list of regular expressions that express which network interface(s) should be used
	// to announce the services over. If nil, all network interfaces are used.
	//
	// +kubebuilder:validation:Optional
	Interfaces []string `json:"interfaces"`
}

// +deepequal-gen=false

// CiliumL2AnnouncementPolicyStatus contains the status of a CiliumL2AnnouncementPolicy.
type CiliumL2AnnouncementPolicyStatus struct {
	// Current service state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}
