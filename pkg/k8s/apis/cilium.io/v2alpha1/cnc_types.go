// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+genclient
//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:resource:categories={cilium}
//+kubebuilder:object:root=true
//+deepequal-gen=false
//+kubebuilder:storageversion

// CiliumNodeConfig is a list of configuration key-value pairs. It is applied to
// nodes indicated by a label selector.
//
// If multiple overrides apply to the same node, they will be ordered by name
// with later Overrides overwriting any conflicting keys.
type CiliumNodeConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired Cilium configuration overrides for a given node
	Spec CiliumNodeConfigSpec `json:"spec"`
}

// +deepequal-gen=false
type CiliumNodeConfigSpec struct {
	// Defaults is treated the same as the cilium-config ConfigMap - a set
	// of key-value pairs parsed by the agent and operator processes.
	// Each key must be a valid config-map data field (i.e. a-z, A-Z, -, _, and .)
	Defaults map[string]string `json:"defaults"`

	// NodeSelector is a label selector that determines to which nodes
	// this configuration applies.
	// If not supplied, then this config applies to no nodes. If
	// empty, then it applies to all nodes.
	NodeSelector *metav1.LabelSelector `json:"nodeSelector"`
}

//+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+deepequal-gen=false

type CiliumNodeConfigList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumNodeConfig `json:"items"`
}
