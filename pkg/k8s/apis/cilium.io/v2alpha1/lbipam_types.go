//  Copyright 2022 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

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
// +kubebuilder:printcolumn:JSONPath=".status.conflicting",name="Conflicting",type=boolean
// +kubebuilder:printcolumn:JSONPath=".status.totalCounts.available",name="IPs Available",type=integer
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

// +kubebuilder:validation:Pattern=`(^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))$)|(^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$)`
type IPv4orIPv6CIDR string

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

	// TODO(dylandreimerink) Exclude: []IPv4orIPv6CIDR
	// We would at some point like to be able to exclude sub-CIDRs which gives a more convenient
	// if a user ever needs to reserve part of a larger range for non-LB purposes.
}

// +deepequal-gen=false

// CiliumLoadBalancerIPPoolStatus contains the status of a CiliumLoadBalancerIPPool.
type CiliumLoadBalancerIPPoolStatus struct {
	// Conflicting indicates that the CIDRs in the pool conflict with another pool or themselves. Conflicting pools
	// are not considered for allocation.
	Conflicting bool `json:"conflicting"`
	// ConflictReason contains the reason for the conflict
	ConflictReason string `json:"conflictReason"`
	// TotalCounts contains the total counts of all CIDRs
	TotalCounts CiliumLoadBalancerIPCounts `json:"totalCounts"`
	// CIDRCounts has counts per CIDR
	CIDRCounts map[string]CiliumLoadBalancerIPCounts `json:"cidrCounts"`
}

// CiliumLoadBalancerIPCounts contains information about how many IPs have been allocated and are available
type CiliumLoadBalancerIPCounts struct {
	// Total is the total amount of allocatable IPs
	Total int `json:"total"`
	// Available is the amount of IPs which can still be allocated
	Available int `json:"available"`
	// Used is the amount of IPs that are currently allocated
	Used int `json:"used"`
}
