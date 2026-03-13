// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumdatapathplugin",path="ciliumdatapathplugins",scope="Cluster",shortName={cddp}
// +kubebuilder:object:root=true
// +kubebuilder:deprecatedversion
// +deepequal-gen=true

// A CiliumDatapathPlugin registers a datapath plugin with Cilium and contains
// information about its status and how Cilium should interact with it.
type CiliumDatapathPlugin struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec CiliumDatapathPluginSpec `json:"spec"`
}

// +kubebuilder:validation:Enum=Always;BestEffort;Eventually
type CiliumDatapathPluginAttachmentPolicy string

const (
	AttachmentPolicyAlways     CiliumDatapathPluginAttachmentPolicy = "Always"
	AttachmentPolicyBestEffort CiliumDatapathPluginAttachmentPolicy = "BestEffort"
)

type CiliumDatapathPluginSpec struct {
	// ExternalCIDRs is a list of CIDRs selecting peers outside the clusters.
	//
	// +kubebuilder:validation:Required
	AttachmentPolicy CiliumDatapathPluginAttachmentPolicy `json:"attachmentPolicy"`
	Version          string                               `json:"version"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

type CiliumDatapathPluginList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumDatapathPlugin `json:"items"`
}
