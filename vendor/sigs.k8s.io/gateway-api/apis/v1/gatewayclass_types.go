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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,scope=Cluster,shortName=gc
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
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
// Whenever one or more Gateways are using a GatewayClass, implementations SHOULD
// add the `gateway-exists-finalizer.gateway.networking.k8s.io` finalizer on the
// associated GatewayClass. This ensures that a GatewayClass associated with a
// Gateway is not deleted while in use.
//
// GatewayClass is a Cluster level resource.
type GatewayClass struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of GatewayClass.
	// +required
	Spec GatewayClassSpec `json:"spec"`

	// Status defines the current state of GatewayClass.
	//
	// Implementations MUST populate status on all GatewayClass resources which
	// specify their controller name.
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", message: "Waiting for controller", reason: "Pending", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	// +optional
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
	//
	// +kubebuilder:validation:XValidation:message="Value is immutable",rule="self == oldSelf"
	// +required
	ControllerName GatewayController `json:"controllerName"`

	// ParametersRef is a reference to a resource that contains the configuration
	// parameters corresponding to the GatewayClass. This is optional if the
	// controller does not require any additional configuration.
	//
	// ParametersRef can reference a standard Kubernetes resource, i.e. ConfigMap,
	// or an implementation-specific custom resource. The resource can be
	// cluster-scoped or namespace-scoped.
	//
	// If the referent cannot be found, refers to an unsupported kind, or when
	// the data within that resource is malformed, the GatewayClass SHOULD be
	// rejected with the "Accepted" status condition set to "False" and an
	// "InvalidParameters" reason.
	//
	// A Gateway for this GatewayClass may provide its own `parametersRef`. When both are specified,
	// the merging behavior is implementation specific.
	// It is generally recommended that GatewayClass provides defaults that can be overridden by a Gateway.
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
	// +required
	Group Group `json:"group"`

	// Kind is kind of the referent.
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the referent.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
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
	// * "Unsupported"
	// * "UnsupportedVersion"
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

	// This reason is used with the "Accepted" condition when the GatewayClass
	// was not accepted because the parametersRef field refers to
	// * a namespaced resource but the Namespace field is not set, or
	// * a cluster-scoped resource but the Namespace field is set, or
	// * a nonexistent object, or
	// * an unsupported resource or kind, or
	// * an existing resource but the data within that resource is malformed.
	GatewayClassReasonInvalidParameters GatewayClassConditionReason = "InvalidParameters"

	// This reason is used with the "Accepted" condition when the
	// requested controller has not yet made a decision about whether
	// to admit the GatewayClass. It is the default Reason on a new
	// GatewayClass.
	GatewayClassReasonPending GatewayClassConditionReason = "Pending"

	// This reason is used with the "Accepted" condition when the GatewayClass
	// was not accepted because the implementation does not support a
	// user-defined GatewayClass.
	GatewayClassReasonUnsupported GatewayClassConditionReason = "Unsupported"

	// Deprecated: Use "Pending" instead.
	GatewayClassReasonWaiting GatewayClassConditionReason = "Waiting"
)

const (
	// This condition indicates whether the GatewayClass supports the version(s)
	// of Gateway API CRDs present in the cluster. This condition MUST be set by
	// a controller when it marks a GatewayClass "Accepted".
	//
	// The version of a Gateway API CRD is defined by the
	// gateway.networking.k8s.io/bundle-version annotation on the CRD. If
	// implementations detect any Gateway API CRDs that either do not have this
	// annotation set, or have it set to a version that is not recognized or
	// supported by the implementation, this condition MUST be set to false.
	//
	// Implementations MAY choose to either provide "best effort" support when
	// an unrecognized CRD version is present. This would be communicated by
	// setting the "Accepted" condition to true and the "SupportedVersion"
	// condition to false.
	//
	// Alternatively, implementations MAY choose not to support CRDs with
	// unrecognized versions. This would be communicated by setting the
	// "Accepted" condition to false with the reason "UnsupportedVersions".
	//
	// Possible reasons for this condition to be true are:
	//
	// * "SupportedVersion"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "UnsupportedVersion"
	//
	// Controllers should prefer to use the values of GatewayClassConditionReason
	// for the corresponding Reason, where appropriate.
	//
	// <gateway:experimental>
	GatewayClassConditionStatusSupportedVersion GatewayClassConditionType = "SupportedVersion"

	// This reason is used with the "SupportedVersion" condition when the
	// condition is true.
	GatewayClassReasonSupportedVersion GatewayClassConditionReason = "SupportedVersion"

	// This reason is used with the "SupportedVersion" or "Accepted" condition
	// when the condition is false. A message SHOULD be included in this
	// condition that includes the detected CRD version(s) present in the
	// cluster and the CRD version(s) that are supported by the GatewayClass.
	GatewayClassReasonUnsupportedVersion GatewayClassConditionReason = "UnsupportedVersion"
)

// GatewayClassStatus is the current status for the GatewayClass.
type GatewayClassStatus struct {
	// Conditions is the current status from the controller for
	// this GatewayClass.
	//
	// Controllers should prefer to publish conditions using values
	// of GatewayClassConditionType for the type of each Condition.
	//
	// <gateway:util:excludeFromCRD>
	// Notes for implementors:
	//
	// Conditions are a listType `map`, which means that they function like a
	// map with a key of the `type` field _in the k8s apiserver_.
	//
	// This means that implementations must obey some rules when updating this
	// section.
	//
	// * Implementations MUST perform a read-modify-write cycle on this field
	//   before modifying it. That is, when modifying this field, implementations
	//   must be confident they have fetched the most recent version of this field,
	//   and ensure that changes they make are on that recent version.
	// * Implementations MUST NOT remove or reorder Conditions that they are not
	//   directly responsible for. For example, if an implementation sees a Condition
	//   with type `special.io/SomeField`, it MUST NOT remove, change or update that
	//   Condition.
	// * Implementations MUST always _merge_ changes into Conditions of the same Type,
	//   rather than creating more than one Condition of the same Type.
	// * Implementations MUST always update the `observedGeneration` field of the
	//   Condition to the `metadata.generation` of the Gateway at the time of update creation.
	// * If the `observedGeneration` of a Condition is _greater than_ the value the
	//   implementation knows about, then it MUST NOT perform the update on that Condition,
	//   but must wait for a future reconciliation and status update. (The assumption is that
	//   the implementation's copy of the object is stale and an update will be re-triggered
	//   if relevant.)
	//
	// </gateway:util:excludeFromCRD>
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:default={{type: "Accepted", status: "Unknown", message: "Waiting for controller", reason: "Pending", lastTransitionTime: "1970-01-01T00:00:00Z"}}
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SupportedFeatures is the set of features the GatewayClass support.
	// It MUST be sorted in ascending alphabetical order by the Name key.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	SupportedFeatures []SupportedFeature `json:"supportedFeatures,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayClassList contains a list of GatewayClass
type GatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClass `json:"items"`
}

// FeatureName is used to describe distinct features that are covered by
// conformance tests.
type FeatureName string

type SupportedFeature struct {
	// +required
	Name FeatureName `json:"name"`
}
