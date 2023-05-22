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
// +kubebuilder:resource:categories={cilium},singular="ciliumcidrgroup",path="ciliumcidrgroups",scope="Cluster",shortName={ccg}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// CiliumCIDRGroup is a list of external CIDRs (i.e: CIDRs selecting peers
// outside the clusters) that can be referenced as a single entity from
// CiliumNetworkPolicies.
type CiliumCIDRGroup struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec CiliumCIDRGroupSpec `json:"spec"`
}

type CiliumCIDRGroupSpec struct {
	// ExternalCIDRs is a list of CIDRs selecting peers outside the clusters.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=0
	ExternalCIDRs []api.CIDR `json:"externalCIDRs"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

type CiliumCIDRGroupList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumCIDRGroup `json:"items"`
}
