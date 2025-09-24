/*
Copyright 2021 The Kubernetes Authors.

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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	// PolicyLabelKey is the label whose presence identifies a CRD that the
	// Gateway API Policy attachment model. The value of the label SHOULD be one
	// of the following:
	//  - A label value of "Inherited" indicates that this Policy is inheritable.
	//    An example of inheritable policy is one which if applied at the Gateway
	//    level would affect all attached HTTPRoutes and their respective
	//    Backends.
	//  - A label value of "Direct" indicates that the policy only affects the
	//    resource to which it is attached and does not affect it's sub resources.
	PolicyLabelKey = "gateway.networking.k8s.io/policy"
)

// LocalPolicyTargetReference identifies an API object to apply a direct or
// inherited policy to. This should be used as part of Policy resources
// that can target Gateway API resources. For more information on how this
// policy attachment model works, and a sample Policy resource, refer to
// the policy attachment documentation for Gateway API.
type LocalPolicyTargetReference struct {
	// Group is the group of the target resource.
	// +required
	Group Group `json:"group"`

	// Kind is kind of the target resource.
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the target resource.
	// +required
	Name ObjectName `json:"name"`
}

// NamespacedPolicyTargetReference identifies an API object to apply a direct or
// inherited policy to, potentially in a different namespace. This should only
// be used as part of Policy resources that need to be able to target resources
// in different namespaces. For more information on how this policy attachment
// model works, and a sample Policy resource, refer to the policy attachment
// documentation for Gateway API.
type NamespacedPolicyTargetReference struct {
	// Group is the group of the target resource.
	// +required
	Group Group `json:"group"`

	// Kind is kind of the target resource.
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the target resource.
	// +required
	Name ObjectName `json:"name"`

	// Namespace is the namespace of the referent. When unspecified, the local
	// namespace is inferred. Even when policy targets a resource in a different
	// namespace, it MUST only apply to traffic originating from the same
	// namespace as the policy.
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`
}

// LocalPolicyTargetReferenceWithSectionName identifies an API object to apply a
// direct policy to. This should be used as part of Policy resources that can
// target single resources. For more information on how this policy attachment
// mode works, and a sample Policy resource, refer to the policy attachment
// documentation for Gateway API.
//
// Note: This should only be used for direct policy attachment when references
// to SectionName are actually needed. In all other cases,
// LocalPolicyTargetReference should be used.
type LocalPolicyTargetReferenceWithSectionName struct {
	LocalPolicyTargetReference `json:",inline"`

	// SectionName is the name of a section within the target resource. When
	// unspecified, this targetRef targets the entire resource. In the following
	// resources, SectionName is interpreted as the following:
	//
	// * Gateway: Listener name
	// * HTTPRoute: HTTPRouteRule name
	// * Service: Port name
	//
	// If a SectionName is specified, but does not exist on the targeted object,
	// the Policy must fail to attach, and the policy implementation should record
	// a `ResolvedRefs` or similar Condition in the Policy's status.
	//
	// +optional
	SectionName *SectionName `json:"sectionName,omitempty"`
}

// PolicyConditionType is a type of condition for a policy. This type should be
// used with a Policy resource Status.Conditions field.
type PolicyConditionType string

// PolicyConditionReason is a reason for a policy condition.
type PolicyConditionReason string

const (
	// PolicyConditionAccepted indicates whether the policy has been accepted or
	// rejected by a targeted resource, and why.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Conflicted"
	// * "Invalid"
	// * "TargetNotFound"
	//
	PolicyConditionAccepted PolicyConditionType = "Accepted"

	// PolicyReasonAccepted is used with the "Accepted" condition when the policy
	// has been accepted by the targeted resource.
	PolicyReasonAccepted PolicyConditionReason = "Accepted"

	// PolicyReasonConflicted is used with the "Accepted" condition when the
	// policy has not been accepted by a targeted resource because there is
	// another policy that targets the same resource and a merge is not possible.
	PolicyReasonConflicted PolicyConditionReason = "Conflicted"

	// PolicyReasonInvalid is used with the "Accepted" condition when the policy
	// is syntactically or semantically invalid.
	PolicyReasonInvalid PolicyConditionReason = "Invalid"

	// PolicyReasonTargetNotFound is used with the "Accepted" condition when the
	// policy is attached to an invalid target resource.
	PolicyReasonTargetNotFound PolicyConditionReason = "TargetNotFound"
)

// PolicyAncestorStatus describes the status of a route with respect to an
// associated Ancestor.
//
// Ancestors refer to objects that are either the Target of a policy or above it
// in terms of object hierarchy. For example, if a policy targets a Service, the
// Policy's Ancestors are, in order, the Service, the HTTPRoute, the Gateway, and
// the GatewayClass. Almost always, in this hierarchy, the Gateway will be the most
// useful object to place Policy status on, so we recommend that implementations
// SHOULD use Gateway as the PolicyAncestorStatus object unless the designers
// have a _very_ good reason otherwise.
//
// In the context of policy attachment, the Ancestor is used to distinguish which
// resource results in a distinct application of this policy. For example, if a policy
// targets a Service, it may have a distinct result per attached Gateway.
//
// Policies targeting the same resource may have different effects depending on the
// ancestors of those resources. For example, different Gateways targeting the same
// Service may have different capabilities, especially if they have different underlying
// implementations.
//
// For example, in BackendTLSPolicy, the Policy attaches to a Service that is
// used as a backend in a HTTPRoute that is itself attached to a Gateway.
// In this case, the relevant object for status is the Gateway, and that is the
// ancestor object referred to in this status.
//
// Note that a parent is also an ancestor, so for objects where the parent is the
// relevant object for status, this struct SHOULD still be used.
//
// This struct is intended to be used in a slice that's effectively a map,
// with a composite key made up of the AncestorRef and the ControllerName.
type PolicyAncestorStatus struct {
	// AncestorRef corresponds with a ParentRef in the spec that this
	// PolicyAncestorStatus struct describes the status of.
	// +required
	AncestorRef ParentReference `json:"ancestorRef"`

	// ControllerName is a domain/path string that indicates the name of the
	// controller that wrote this status. This corresponds with the
	// controllerName field on GatewayClass.
	//
	// Example: "example.net/gateway-controller".
	//
	// The format of this field is DOMAIN "/" PATH, where DOMAIN and PATH are
	// valid Kubernetes names
	// (https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names).
	//
	// Controllers MUST populate this field when writing status. Controllers should ensure that
	// entries to status populated with their ControllerName are cleaned up when they are no
	// longer necessary.
	// +required
	ControllerName GatewayController `json:"controllerName"`

	// Conditions describes the status of the Policy with respect to the given Ancestor.
	//
	// <gateway:util:excludeFromCRD>
	//
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
	// +required
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// PolicyStatus defines the common attributes that all Policies should include within
// their status.
type PolicyStatus struct {
	// Ancestors is a list of ancestor resources (usually Gateways) that are
	// associated with the policy, and the status of the policy with respect to
	// each ancestor. When this policy attaches to a parent, the controller that
	// manages the parent and the ancestors MUST add an entry to this list when
	// the controller first sees the policy and SHOULD update the entry as
	// appropriate when the relevant ancestor is modified.
	//
	// Note that choosing the relevant ancestor is left to the Policy designers;
	// an important part of Policy design is designing the right object level at
	// which to namespace this status.
	//
	// Note also that implementations MUST ONLY populate ancestor status for
	// the Ancestor resources they are responsible for. Implementations MUST
	// use the ControllerName field to uniquely identify the entries in this list
	// that they are responsible for.
	//
	// Note that to achieve this, the list of PolicyAncestorStatus structs
	// MUST be treated as a map with a composite key, made up of the AncestorRef
	// and ControllerName fields combined.
	//
	// A maximum of 16 ancestors will be represented in this list. An empty list
	// means the Policy is not relevant for any ancestors.
	//
	// If this slice is full, implementations MUST NOT add further entries.
	// Instead they MUST consider the policy unimplementable and signal that
	// on any related resources such as the ancestor that would be referenced
	// here. For example, if this list was full on BackendTLSPolicy, no
	// additional Gateways would be able to reference the Service targeted by
	// the BackendTLSPolicy.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []PolicyAncestorStatus `json:"ancestors"`
}
