// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumclusterwideenvoyconfig",path="ciliumclusterwideenvoyconfigs",scope="Cluster",shortName={ccec}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="The age of the identity",name="Age",type=date
// +kubebuilder:storageversion

type CiliumClusterwideEnvoyConfig struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// +k8s:openapi-gen=false
	Spec CiliumEnvoyConfigSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumClusterwideEnvoyConfigList is a list of CiliumClusterwideEnvoyConfig objects.
type CiliumClusterwideEnvoyConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumClusterwideEnvoyConfig.
	Items []CiliumClusterwideEnvoyConfig `json:"items"`
}
