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
// +kubebuilder:resource:categories={cilium},singular="ciliumloadbalancerippool",path="ciliumloadbalancerippools",scope="Cluster",shortName={ippools,ippool,lbippool,lbippools}
// +kubebuilder:printcolumn:JSONPath=".spec.disabled",name="Disabled",type=boolean
// +kubebuilder:printcolumn:name="Conflicting",type=string,JSONPath=`.status.conditions[?(@.type=="io.cilium/conflict")].status`
// +kubebuilder:printcolumn:name="IPs Available",type=string,JSONPath=`.status.conditions[?(@.type=="io.cilium/ips-available")].message`
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumLoadBalancerIPPool is a Kubernetes third-party resource which
// is used to defined pools of IPs which the operator can use to to allocate
// and advertise IPs for Services of type LoadBalancer.
type CiliumLoadBalancerIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human readable description for a BGP load balancer
	// ip pool.
	//
	// +kubebuilder:validation:Required
	Spec CiliumLoadBalancerIPPoolSpec `json:"spec,omitempty"`

	// Status is the status of the IP Pool.
	//
	// It might be possible for users to define overlapping IP Pools, we can't validate or enforce non-overlapping pools
	// during object creation. The Cilium operator will do this validation and update the status to reflect the ability
	// to allocate IPs from this pool.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumLoadBalancerIPPoolStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumLoadBalancerIPPoolList is a list of
// CiliumLoadBalancerIPPool objects.
type CiliumLoadBalancerIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPLoadBalancerIPPools.
	Items []CiliumLoadBalancerIPPool `json:"items"`
}

// +deepequal-gen=true

// CiliumLoadBalancerIPPoolSpec is a human readable description for
// a load balancer IP pool.
type CiliumLoadBalancerIPPoolSpec struct {
	// ServiceSelector selects a set of services which are eligible to receive IPs from this
	//
	// +kubebuilder:validation:Optional
	ServiceSelector *slimv1.LabelSelector `json:"serviceSelector"`
	// CiliumLoadBalancerIPPoolCIDRBlock is a list of CIDRs comprising this IP Pool
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Cidrs []CiliumLoadBalancerIPPoolCIDRBlock `json:"cidrs"`
	// Disabled, if set to true means that no new IPs will be allocated from this pool.
	// Existing allocations will not be removed from services.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	Disabled bool `json:"disabled"`
}

// CiliumLoadBalancerIPPoolCIDRBlock describes a single CIDR block.
type CiliumLoadBalancerIPPoolCIDRBlock struct {
	// +kubebuilder:validation:Format=cidr
	// +kubebuilder:validation:Required
	Cidr IPv4orIPv6CIDR `json:"cidr"`
}

// +deepequal-gen=false

// CiliumLoadBalancerIPPoolStatus contains the status of a CiliumLoadBalancerIPPool.
type CiliumLoadBalancerIPPoolStatus struct {
	// Current service state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}
