// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get,list,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumflowlogging",path="ciliumflowloggings",scope="Cluster",shortName={cfl,ciliumfl}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="Time duration since creation of CiliumFlow Logging",name="Age",type=date
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// CiliumFlowLogging configures a flow logging task for Cilium agents.
//
// +deepequal-gen=false
type CiliumFlowLogging struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired specification/configuration of the flow logging.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Spec is immutable"
	Spec FlowLoggingSpec `json:"spec"`

	// Status defines the realized specification/configuration and status
	// of the flow logging.
	//
	// +kubebuilder:validation:Optional
	Status FlowLoggingStatus `json:"status,omitempty"`
}

// FlowLoggingSpec defines configuration of a flow logging task.
//
// +deepequal-gen=false
type FlowLoggingSpec struct {
	// List of field names that will be kept in the log output.
	//
	// +kubebuilder:validation:Optional
	FieldMask []string `json:"fieldmask"`

	// Filters specifies flows to include in the logging output. Flow passes the
	// filter if any of the entries match. Only Flows matching the filter, but
	// not matching exclude-filter will be logged. The check is disabled when
	// empty.
	//
	// +kubebuilder:validation:Optional
	Filters []*flowpb.FlowFilter `json:"filters"`

	// ExcludeFilters specifies flows to exclude from the logging output. Flow
	// passes the filter if any of the entries match. Only Flows matching the
	// filter, but not matching exclude-filter will be logged. The check is
	// disabled when empty.
	//
	// +kubebuilder:validation:Optional
	ExcludeFilters []*flowpb.FlowFilter `json:"exludefilters"`

	// Expires specifies the time when logging will stop. Empty means
	// that flow logging won't stop until this object is deleted.
	//
	// +kubebuilder:validation:Format=date-time
	// +kubebuilder:validation:Optional
	Expires *metav1.Time `json:"expires"`
}

// FlowLoggingStatus is a status of a flow logging task.
type FlowLoggingStatus struct{}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumFlowLoggingList is a list of CiliumFlowLogging objects.
type CiliumFlowLoggingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumFlowLogging
	Items []CiliumFlowLogging `json:"items"`
}
