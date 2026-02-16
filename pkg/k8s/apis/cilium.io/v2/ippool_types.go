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
// +kubebuilder:resource:categories={cilium},singular="ciliumpodippool",path="ciliumpodippools",scope="Cluster",shortName={cpip}
// +kubebuilder:object:root=true
// +kubebuilder:unservedversion

// CiliumPodIPPool defines an IP pool that can be used for pooled IPAM (i.e. the multi-pool IPAM
// mode).
type CiliumPodIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec IPPoolSpec `json:"spec"`
}

type IPPoolSpec struct {
	// IPv4 specifies the IPv4 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv4 *IPv4PoolSpec `json:"ipv4,omitempty"`

	// IPv6 specifies the IPv6 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv6 *IPv6PoolSpec `json:"ipv6,omitempty"`

	// PodSelector selects the set of Pods that are eligible to receive IPs from
	// this pool when neither the Pod nor its Namespace specify an explicit
	// `ipam.cilium.io/*` annotation.
	//
	// The selector can match on regular Pod labels and on the following synthetic
	// labels that Cilium adds for convenience:
	//
	// io.kubernetes.pod.namespace – the Pod's namespace
	// io.kubernetes.pod.name      – the Pod's name
	//
	// A single Pod must not match more than one pool for the same IP family.
	// If multiple pools match, IP allocation fails for that Pod and a warning event
	// is emitted in the namespace of the Pod.
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector selects the set of Namespaces that are eligible to use
	// this pool. If both PodSelector and NamespaceSelector are specified, a Pod
	// must match both selectors to be eligible for IP allocation from this pool.
	//
	// If NamespaceSelector is empty, the pool can be used by Pods in any namespace
	// (subject to PodSelector constraints).
	//
	// +kubebuilder:validation:Optional
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.pool) || self.pool.all(p, p.cidr in self.cidrs)", message="If pool is set, each pool entry must reference a CIDR from cidrs"
type IPv4PoolSpec struct {
	// CIDRs is a list of IPv4 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MaskSize uint8 `json:"maskSize"`

	// Pool contains per-CIDR configuration for a subset of CIDRs listed in CIDRs.
	// Each entry must reference a CIDR in CIDRs.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=cidr
	// +kubebuilder:validation:MaxItems=32
	Pool []PoolCIDRConfig `json:"pool,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.pool) || self.pool.all(p, p.cidr in self.cidrs)", message="If pool is set, each pool entry must reference a CIDR from cidrs"
type IPv6PoolSpec struct {
	// CIDRs is a list of IPv6 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	MaskSize uint8 `json:"maskSize"`

	// Pool contains per-CIDR configuration for a subset of CIDRs listed in CIDRs.
	// Each entry must reference a CIDR in CIDRs.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=cidr
	// +kubebuilder:validation:MaxItems=32
	Pool []PoolCIDRConfig `json:"pool,omitempty"`
}

// PoolCIDR is an IP pool CIDR.
//
// +kubebuilder:validation:Format=cidr
type PoolCIDR string

type PoolCIDRConfig struct {
	// CIDR references one of the CIDRs listed in the parent pool spec.
	//
	// +kubebuilder:validation:Required
	CIDR PoolCIDR `json:"cidr"`

	// ReservedRanges is a list of IP ranges within CIDR that must not be allocated.
	//
	// +kubebuilder:validation:Optional
	ReservedRanges []ReservedRange `json:"reservedRanges,omitempty"`
}

type ReservedRange struct {
	// The first IP in the reserved range.
	//
	// +kubebuilder:validation:Required
	Start string `json:"start"`

	// The last IP in the reserved range.
	//
	// +kubebuilder:validation:Required
	End string `json:"end"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumPodIPPoolList is a list of CiliumPodIPPool objects.
type CiliumPodIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of CiliumPodIPPools.
	Items []CiliumPodIPPool `json:"items"`
}
