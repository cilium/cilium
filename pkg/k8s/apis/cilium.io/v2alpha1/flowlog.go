// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get,list,watch,create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumflowlog",path="ciliumflowlogs",scope="Cluster",shortName={cfl,ciliumfl}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="Time duration since creation of Cilium flow log",name="Age",type=date
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// CiliumFlowLog configures a flow log task for Cilium agents.
//
// +deepequal-gen=false
type CiliumFlowLog struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired specification/configuration of the flow log.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Spec is immutable"
	Spec FlowLogSpec `json:"spec"`
}

// FlowLogSpec defines configuration of a flow log task.
//
// +deepequal-gen=false
type FlowLogSpec struct {
	// List of field names from flowpb.Flow that will be kept in the log output.
	//
	// +kubebuilder:validation:Optional
	FieldMask []string `json:"fieldMask,omitempty"`

	// Filters is a list of FlowFilters. If flow matches any of the
	// filters, it will be logged.
	//
	// If Filters are empty, all flows will be logged.
	//
	// +kubebuilder:validation:Optional
	Filters []*flowpb.FlowFilter `json:"filters,omitempty"`

	// ExcludeFilters is a list of FlowFilters. If flow matches any of the
	// filters, it won't be logged.
	//
	// All flows are logged if ExcludeFilters field is empty.
	//
	// +kubebuilder:validation:Optional
	ExcludeFilters []*flowpb.FlowFilter `json:"excludeFilters,omitempty"`

	// Expiration specifies the time when log will stop.
	//
	// Empty means that flow log won't stop until this object is deleted.
	//
	// +kubebuilder:validation:Format=date-time
	// +kubebuilder:validation:Optional
	Expiration *metav1.Time `json:"expiration,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumFlowLogList is a list of CiliumFlowLog objects.
type CiliumFlowLogList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumFlowLog
	Items []CiliumFlowLog `json:"items"`
}
