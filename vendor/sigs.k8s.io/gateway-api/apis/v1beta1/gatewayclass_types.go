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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,scope=Cluster,shortName=gc
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Controller",type=string,JSONPath=`.spec.controllerName`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`,priority=1

// GatewayClass describes a class of Gateways available to the user for creating
// Gateway resources.
//
// It is recommended that this resource be used as a template for Gateways. This
// means that a Gateway is based on the state of the GatewayClass at the time it
// was created and changes to the GatewayClass or associated parameters are not
// propagated down to existing Gateways. This recommendation is intended to
// limit the blast radius of changes to GatewayClass or associated parameters.
// If implementations choose to propagate GatewayClass changes to existing
// Gateways, that MUST be clearly documented by the implementation.
//
// Whenever one or more Gateways are using a GatewayClass, implementations MUST
// add the `gateway-exists-finalizer.gateway.networking.k8s.io` finalizer on the
// associated GatewayClass. This ensures that a GatewayClass associated with a
// Gateway is not deleted while in use.
//
// GatewayClass is a Cluster level resource.
type GatewayClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of GatewayClass.
	Spec GatewayClassSpec `json:"spec"`

	// Status defines the current state of GatewayClass.
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", message: "Waiting for controller", reason: "Waiting", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status GatewayClassStatus `json:"status,omitempty"`
}

const (
	// GatewayClassFinalizerGatewaysExist should be added as a finalizer to the
	// GatewayClass whenever there are provisioned Gateways using a
	// GatewayClass.
	GatewayClassFinalizerGatewaysExist = "gateway-exists-finalizer.gateway.networking.k8s.io"
)

// GatewayClassSpec reflects the configuration of a class of Gateways.
type GatewayClassSpec struct {
	// ControllerName is the name of the controller that is managing Gateways of
	// this class. The value of this field MUST be a domain prefixed path.
	//
	// Example: "example.net/gateway-controller".
	//
	// This field is not mutable and cannot be empty.
	//
	// Support: Core
	ControllerName GatewayController `json:"controllerName"`

	// ParametersRef is a reference to a resource that contains the configuration
	// parameters corresponding to the GatewayClass. This is optional if the
	// controller does not require any additional configuration.
	//
	// ParametersRef can reference a standard Kubernetes resource, i.e. ConfigMap,
	// or an implementation-specific custom resource. The resource can be
	// cluster-scoped or namespace-scoped.
	//
	// If the referent cannot be found, the GatewayClass's "InvalidParameters"
	// status condition will be true.
	//
	// Support: Implementation-specific
	//
	// +optional
	ParametersRef *ParametersReference `json:"parametersRef,omitempty"`

	// Description helps describe a GatewayClass with more details.
	//
	// +kubebuilder:validation:MaxLength=64
	// +optional
	Description *string `json:"description,omitempty"`
}

// ParametersReference identifies an API object containing controller-specific
// configuration resource within the cluster.
type ParametersReference struct {
	// Group is the group of the referent.
	Group Group `json:"group"`

	// Kind is kind of the referent.
	Kind Kind `json:"kind"`

	// Name is the name of the referent.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the referent.
	// This field is required when referring to a Namespace-scoped resource and
	// MUST be unset when referring to a Cluster-scoped resource.
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`
}

// GatewayClassConditionType is the type for status conditions on
// Gateway resources. This type should be used with the
// GatewayClassStatus.Conditions field.
type GatewayClassConditionType string

// GatewayClassConditionReason defines the set of reasons that explain why a
// particular GatewayClass condition type has been raised.
type GatewayClassConditionReason string

const (
	// This condition indicates whether the GatewayClass has been accepted by
	// the controller requested in the `spec.controller` field.
	//
	// This condition defaults to Unknown, and MUST be set by a controller when
	// it sees a GatewayClass using its controller string. The status of this
	// condition MUST be set to True if the controller will support provisioning
	// Gateways using this class. Otherwise, this status MUST be set to False.
	// If the status is set to False, the controller SHOULD set a Message and
	// Reason as an explanation.
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
	// Controllers should prefer to use the values of GatewayClassConditionReason
	// for the corresponding Reason, where appropriate.
	GatewayClassConditionStatusAccepted GatewayClassConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the condition is
	// true.
	GatewayClassReasonAccepted GatewayClassConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the
	// GatewayClass was not accepted because the parametersRef field
	// was invalid, with more detail in the message.
	GatewayClassReasonInvalidParameters GatewayClassConditionReason = "InvalidParameters"

	// This reason is used with the "Accepted" condition when the
	// requested controller has not yet made a decision about whether
	// to admit the GatewayClass. It is the default Reason on a new
	// GatewayClass.
	GatewayClassReasonPending GatewayClassConditionReason = "Pending"

	// Deprecated: Use "Pending" instead.
	GatewayClassReasonWaiting GatewayClassConditionReason = "Waiting"
)

// GatewayClassStatus is the current status for the GatewayClass.
type GatewayClassStatus struct {
	// Conditions is the current status from the controller for
	// this GatewayClass.
	//
	// Controllers should prefer to publish conditions using values
	// of GatewayClassConditionType for the type of each Condition.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:default={{type: "Accepted", status: "Unknown", message: "Waiting for controller", reason: "Pending", lastTransitionTime: "1970-01-01T00:00:00Z"}}
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayClassList contains a list of GatewayClass
type GatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClass `json:"items"`
}
