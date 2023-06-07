// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumpodippool",path="ciliumpodippools",scope="Cluster",shortName={cpip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumPodIPPool defines an IP pool that can be used for pooled IPAM (i.e. the multi-pool IPAM
// mode).
type CiliumPodIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec IPPoolSpec `json:"spec"`
}

type IPPoolSpec struct {
	// IPv4 specifies the IPv4 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv4 *IPv4PoolSpec `json:"ipv4"`

	// IPv6 specifies the IPv6 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv6 *IPv6PoolSpec `json:"ipv6"`
}

type IPv4PoolSpec struct {
	// CIDRs is a list of IPv4 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:validation:ExclusiveMaximum=false
	MaskSize uint8 `json:"maskSize"`
}

type IPv6PoolSpec struct {
	// CIDRs is a list of IPv6 CIDRs that are part of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	CIDRs []PoolCIDR `json:"cidrs"`

	// MaskSize is the mask size of the pool.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	// +kubebuilder:validation:ExclusiveMaximum=false
	MaskSize uint8 `json:"maskSize"`
}

// PoolCIDR is an IP pool CIDR.
//
// +kubebuilder:validation:Format=cidr
type PoolCIDR string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumPodIPPoolList is a list of CiliumPodIPPool objects.
type CiliumPodIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of CiliumPodIPPools.
	Items []CiliumPodIPPool `json:"items"`
}
