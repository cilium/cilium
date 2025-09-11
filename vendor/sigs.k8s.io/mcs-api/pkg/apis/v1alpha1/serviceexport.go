/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ServiceExportPluralName is the plural name of ServiceExport
	ServiceExportPluralName = "serviceexports"
	// ServiceExportKindName is the kind name of ServiceExport
	ServiceExportKindName = "ServiceExport"
	// ServiceExportFullName is the full name of ServiceExport
	ServiceExportFullName = ServiceExportPluralName + "." + GroupName
)

// ServiceExportVersionedName is the versioned name of ServiceExport
var ServiceExportVersionedName = ServiceExportKindName + "/" + GroupVersion.Version

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={svcex,svcexport}

// ServiceExport declares that the Service with the same name and namespace
// as this export should be consumable from other clusters.
type ServiceExport struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// spec defines the behavior of a ServiceExport.
	// +optional
	Spec ServiceExportSpec `json:"spec,omitempty"`
	// status describes the current state of an exported service.
	// Service configuration comes from the Service that had the same
	// name and namespace as this ServiceExport.
	// Populated by the multi-cluster service implementation's controller.
	// +optional
	Status ServiceExportStatus `json:"status,omitempty"`
}

// ServiceExportSpec describes an exported service extra information
type ServiceExportSpec struct {
	// exportedLabels describes the labels exported. It is optional for implementation.
	// +optional
	ExportedLabels map[string]string `json:"exportedLabels,omitempty"`
	// exportedAnnotations describes the annotations exported. It is optional for implementation.
	// +optional
	ExportedAnnotations map[string]string `json:"exportedAnnotations,omitempty"`
}

// ServiceExportStatus contains the current status of an export.
type ServiceExportStatus struct {
	// +optional
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

const (
	// ServiceExportValid means that the service referenced by this
	// service export has been recognized as valid by an mcs-controller.
	// This will be false if the service is found to be unexportable
	// (ExternalName, not found).
	//
	// Deprecated: use ServiceExportConditionValid instead
	ServiceExportValid = "Valid"
	// ServiceExportConflict means that there is a conflict between two
	// exports for the same Service. When "True", the condition message
	// should contain enough information to diagnose the conflict:
	// field(s) under contention, which cluster won, and why.
	// Users should not expect detailed per-cluster information in the
	// conflict message.
	//
	// Deprecated: use ServiceExportConditionConflict instead
	ServiceExportConflict = "Conflict"
)

// +kubebuilder:object:root=true

// ServiceExportList represents a list of endpoint slices
type ServiceExportList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of endpoint slices
	// +listType=set
	Items []ServiceExport `json:"items"`
}

// ServiceExportConditionType is a type of condition associated with a
// ServiceExport. This type should be used with the ServiceExportStatus.Conditions
// field.
type ServiceExportConditionType string

// ServiceExportConditionReason defines the set of reasons that explain why a
// particular ServiceExport condition type has been raised.
type ServiceExportConditionReason string

// NewServiceExportCondition creates a new ServiceExport condition
func NewServiceExportCondition(t ServiceExportConditionType, status metav1.ConditionStatus, reason ServiceExportConditionReason, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(t),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		LastTransitionTime: metav1.Now(),
	}
}

const (
	// ServiceExportConditionValid is true when the Service Export is valid.
	// This does not indicate whether or not the configuration has been exported
	// to a control plane / data plane.
	//
	//
	// Possible reasons for this condition to be true are:
	//
	// * "Valid"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NoService"
	// * "InvalidServiceType"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ServiceExportConditionValid ServiceExportConditionType = "Valid"

	// ServiceExportReasonValid is used with the "Valid" condition when the
	// condition is True.
	ServiceExportReasonValid ServiceExportConditionReason = "Valid"

	// ServiceExportReasonNoService is used with the "Valid" condition when
	// the associated Service does not exist.
	ServiceExportReasonNoService ServiceExportConditionReason = "NoService"

	// ServiceExportReasonInvalidServiceType is used with the "Valid"
	// condition when the associated Service has an invalid type
	// (per the KEP at least the ExternalName type).
	ServiceExportReasonInvalidServiceType ServiceExportConditionReason = "InvalidServiceType"
)

const (
	// ServiceExportConditionReady is true when the service is exported
	// to some control plane or data plane or ready to be pulled.
	//
	//
	// Possible reasons for this condition to be true are:
	//
	// * "Exported"
	// * "Ready"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Pending"
	// * "Failed"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ServiceExportConditionReady ServiceExportConditionType = "Ready"

	// ServiceExportReasonExported is used with the "Ready" condition
	// when the condition is True and the service has been exported.
	// This would be used when an implementation exports a service
	// to a control plane or data plane.
	ServiceExportReasonExported ServiceExportConditionReason = "Exported"

	// ServiceExportReasonReady is used with the "Ready" condition
	// when the condition is True and the service has been exported.
	// This would typically be used in an implementation that uses a
	// pull model.
	ServiceExportReasonReady ServiceExportConditionReason = "Ready"

	// ServiceExportReasonPending is used with the "Ready" condition
	// when the service is in the process of being exported.
	ServiceExportReasonPending ServiceExportConditionReason = "Pending"

	// ServiceExportReasonFailed is used with the "Ready" condition
	// when the service failed to be exported with the message providing
	// the specific reason.
	ServiceExportReasonFailed ServiceExportConditionReason = "Failed"
)

const (
	// ServiceExportConditionConflict indicates that some property of an
	// exported service has conflicting values across the constituent
	// ServiceExports. This condition must be at least raised on the
	// conflicting ServiceExport and is recommended to be raised on all on
	// all the constituent ServiceExports if feasible.
	//
	//
	// Possible reasons for this condition to be true are:
	//
	// * "PortConflict"
	// * "TypeConflict"
	// * "SessionAffinityConflict"
	// * "SessionAffinityConfigConflict"
	// * "AnnotationsConflict"
	// * "LabelsConflict"
	//
	// When multiple conflicts occurs the above reasons may be combined
	// using commas.
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NoConflicts"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ServiceExportConditionConflict ServiceExportConditionType = "Conflict"

	// ServiceExportReasonPortConflict is used with the "Conflict" condition
	// when the exported service has a conflict related to port configuration.
	// This includes when ports on resulting imported services would have
	// duplicated names (including unnamed/empty name) or duplicated
	// port/protocol pairs.
	ServiceExportReasonPortConflict ServiceExportConditionReason = "PortConflict"

	// ServiceExportReasonTypeConflict is used with the "Conflict" condition
	// when the exported service has a conflict related to the service type
	// (eg headless vs non-headless).
	ServiceExportReasonTypeConflict ServiceExportConditionReason = "TypeConflict"

	// ServiceExportReasonSessionAffinityConflict is used with the "Conflict"
	// condition when the exported service has a conflict related to session affinity.
	ServiceExportReasonSessionAffinityConflict ServiceExportConditionReason = "SessionAffinityConflict"

	// ServiceExportReasonSessionAffinityConfigConflict is used with the
	// "Conflict" condition when the exported service has a conflict related
	// to session affinity config.
	ServiceExportReasonSessionAffinityConfigConflict ServiceExportConditionReason = "SessionAffinityConfigConflict"

	// ServiceExportReasonLabelsConflict is used with the "Conflict"
	// condition when the ServiceExport has a conflict related to exported
	// labels.
	ServiceExportReasonLabelsConflict ServiceExportConditionReason = "LabelsConflict"

	// ServiceExportReasonAnnotationsConflict is used with the "Conflict"
	// condition when the ServiceExport has a conflict related to exported
	// annotations.
	ServiceExportReasonAnnotationsConflict ServiceExportConditionReason = "AnnotationsConflict"

	// ServiceExportReasonNoConflicts is used with the "Conflict" condition
	// when the condition is False.
	ServiceExportReasonNoConflicts ServiceExportConditionReason = "NoConflicts"
)
