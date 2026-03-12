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

// +kubebuilder:validation:Enum=Always;BestEffort
type CiliumDatapathPluginAttachmentPolicy string

const (
	// AttachmentPolicyAlways means that this plugin is required. BPF attachment will
	// not proceed until Cilium can talk to this plugin.
	AttachmentPolicyAlways CiliumDatapathPluginAttachmentPolicy = "Always"
	// AttachmentPolicyBestEffort means that this plugin is not required. BPF attachment
	// will proceed if Cilium cannot talk to this plugin. Cilium will not trigger
	// datapath reinitialization once connectivity with this plugin is restored.
	AttachmentPolicyBestEffort CiliumDatapathPluginAttachmentPolicy = "BestEffort"
)

type CiliumDatapathPluginSpec struct {
	// AttachmentPolicy dictates how Cilium behaves when it cannot talk to
	// a plugin.
	//
	// +kubebuilder:validation:Required
	AttachmentPolicy CiliumDatapathPluginAttachmentPolicy `json:"attachmentPolicy"`
	// Version is an opaque string used to indicate the datapath plugin version.
	// Update this when deploying a new version of a datapath plugin to trigger a datapath
	// reinitialization.
	//
	// +kubebuilder:validation:Required
	Version string `json:"version"`
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
