/*
Copyright 2025 The Kubernetes Authors.

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

	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,scope=Cluster,shortName=mesh
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// XMesh defines mesh-wide characteristics of a GAMMA-compliant service mesh.
type XMesh struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of XMesh.
	// +required
	Spec MeshSpec `json:"spec"`

	// Status defines the current state of XMesh.
	//
	// <gateway:util:excludeFromCRD>
	// Implementations MUST populate status on all Mesh resources which
	// specify their controller name.
	// </gateway:util:excludeFromCRD>
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	// +optional
	Status MeshStatus `json:"status,omitempty"`
}

// MeshSpec defines the desired state of an XMesh.
type MeshSpec struct {
	// ControllerName is the name of a controller that is managing Gateway API
	// resources for mesh traffic management. The value of this field MUST be a
	// domain prefixed path.
	//
	// Example: "example.com/awesome-mesh".
	//
	// This field is not mutable and cannot be empty.
	//
	// Support: Core
	//
	// +kubebuilder:validation:XValidation:message="Value is immutable",rule="self == oldSelf"
	// +required
	ControllerName gatewayapiv1.GatewayController `json:"controllerName"`

	// ParametersRef is an optional reference to a resource that contains
	// implementation-specific configuration for this Mesh. If no
	// implementation-specific parameters are needed, this field MUST be
	// omitted.
	//
	// ParametersRef can reference a standard Kubernetes resource, i.e.
	// ConfigMap, or an implementation-specific custom resource. The resource
	// can be cluster-scoped or namespace-scoped.
	//
	// If the referent cannot be found, refers to an unsupported kind, or when
	// the data within that resource is malformed, the Mesh MUST be rejected
	// with the "Accepted" status condition set to "False" and an
	// "InvalidParameters" reason.
	//
	// Support: Implementation-specific
	//
	// +optional
	ParametersRef *gatewayapiv1.ParametersReference `json:"parametersRef,omitempty"`

	// Description optionally provides a human-readable description of a Mesh.
	//
	// +kubebuilder:validation:MaxLength=64
	// +optional
	Description *string `json:"description,omitempty"`
}

// MeshConditionType is the type for status conditions on Mesh resources.
// This type should be used with the MeshStatus.Conditions field.
type MeshConditionType string

// MeshConditionReason defines the set of reasons that explain why a
// particular Mesh condition type has been raised.
type MeshConditionReason string

const (
	// The "Accepted" condition indicates whether the Mesh has been accepted
	// by the controller requested in the `spec.controllerName` field.
	//
	// This condition defaults to Unknown, and MUST be set by a controller
	// when it sees a Mesh using its controller string. The status of this
	// condition MUST be set to True if the controller will accept the Mesh
	// resource. Otherwise, this status MUST be set to False. If the status is
	// set to False, the controller MUST set a Message and Reason as an
	// explanation.
	//
	// Possible reasons for this condition to be true are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "InvalidParameters"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers should prefer to use the values of MeshConditionReason for
	// the corresponding Reason, where appropriate.
	MeshConditionAccepted MeshConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the condition is
	// true.
	MeshReasonAccepted MeshConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the Mesh was not
	// accepted because the parametersRef field refers to
	//
	// * a namespaced resource but the Namespace field is not set, or
	// * a cluster-scoped resource but the Namespace field is set, or
	// * a nonexistent object, or
	// * an unsupported resource or kind, or
	// * an existing resource but the data within that resource is malformed.
	MeshReasonInvalidParameters MeshConditionReason = "InvalidParameters"

	// This reason is used with the "Accepted" condition when the status is
	// "Unknown" and the requested controller has not yet made a decision
	// about whether to accept the Mesh. It is the default Reason on a new
	// Mesh.
	MeshReasonPending MeshConditionReason = "Pending"
)

// MeshStatus is the current status for the Mesh.
type MeshStatus struct {
	// Conditions is the current status from the controller for
	// this Mesh.
	//
	// Controllers should prefer to publish conditions using values
	// of MeshConditionType for the type of each Condition.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:default={{type: "Accepted", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"},{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SupportedFeatures is the set of features the Mesh support.
	// It MUST be sorted in ascending alphabetical order by the Name key.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	SupportedFeatures []gatewayapiv1.SupportedFeature `json:"supportedFeatures,omitempty"`
}

// +kubebuilder:object:root=true
type XMeshList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []XMesh `json:"items"`
}
