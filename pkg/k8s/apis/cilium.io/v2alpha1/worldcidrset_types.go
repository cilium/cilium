// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumworldcidrset",path="ciliumworldcidrsets",scope="Cluster"
// +kubebuilder:printcolumn:JSONPath=".spec.encapsulate",name="Encapsulate",type=boolean
// +kubebuilder:printcolumn:JSONPath=".spec.cidrs",name="CIDRs",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumWorldCIDRSet is a set of CIDRs and their routing destination.
// It is used in certain modes (e.g. highscale-IPCache) to indicate whether
// destinations require encapsulation.
type CiliumWorldCIDRSet struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumWorldCIDRSetSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumWorldCIDRSetList is a list of CiliumWorldCIDRSet objects.
type CiliumWorldCIDRSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumWorldCIDRSets.
	Items []CiliumWorldCIDRSet `json:"items"`
}

// CiliumWorldCIDRSetSpec configures the routing decision for a set of CIDRs.
type CiliumWorldCIDRSetSpec struct {

	// Encapsulate is whether or not the CIDRs in this set
	// should be encapsulated.
	//
	// Currently, only false is supported.
	//
	// +kubebuilder:validation:Required
	Encapsulate *bool `json:"encapsulate"`

	// CIDRGroupRefs is a list of CiliumCIDRGroup references. The encapsulation configuration
	// will apply to all CIDRs referenced by these groups.
	// Note: Currently only IPv4 is supported.
	//
	// +kubebuilder:validation:Required
	CIDRGroupRefs []api.CIDRGroupRef `json:"cidrGroupRefs"`
}
