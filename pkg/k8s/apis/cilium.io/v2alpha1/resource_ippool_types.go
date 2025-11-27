// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumresourceippool",path="ciliumresourceippools",scope="Cluster",shortName={crip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumResourceIPPool defines an IP pool that can be used for pooled IPAM (i.e. the multi-pool IPAM
// mode).
type CiliumResourceIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec ResourceIPPoolSpec `json:"spec"`
}

type ResourceIPPoolSpec struct {
	// IPv4 specifies the IPv4 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv4 *IPv4PoolSpec `json:"ipv4"`

	// IPv6 specifies the IPv6 CIDRs and mask sizes of the pool
	//
	// +kubebuilder:validation:Optional
	IPv6 *IPv6PoolSpec `json:"ipv6"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumResourceIPPoolList is a list of CiliumResourceIPPool objects.
type CiliumResourceIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of CiliumResourceIPPool.
	Items []CiliumResourceIPPool `json:"items"`
}
