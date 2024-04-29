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

// ParentReference identifies an API object (usually a Gateway) that can be considered
// a parent of this resource (usually a route). There are two kinds of parent resources
// with "Core" support:
//
// * Gateway (Gateway conformance profile)
// * Service (Mesh conformance profile, ClusterIP Services only)
//
// This API may be extended in the future to support additional kinds of parent
// resources.
//
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
type ParentReference struct {
	// Group is the group of the referent.
	// When unspecified, "gateway.networking.k8s.io" is inferred.
	// To set the core API group (such as for a "Service" kind referent),
	// Group must be explicitly set to "" (empty string).
	//
	// Support: Core
	//
	// +kubebuilder:default=gateway.networking.k8s.io
	// +optional
	Group *Group `json:"group,omitempty"`

	// Kind is kind of the referent.
	//
	// There are two kinds of parent resources with "Core" support:
	//
	// * Gateway (Gateway conformance profile)
	// * Service (Mesh conformance profile, ClusterIP Services only)
	//
	// Support for other resources is Implementation-Specific.
	//
	// +kubebuilder:default=Gateway
	// +optional
	Kind *Kind `json:"kind,omitempty"`

	// Namespace is the namespace of the referent. When unspecified, this refers
	// to the local namespace of the Route.
	//
	// Note that there are specific rules for ParentRefs which cross namespace
	// boundaries. Cross-namespace references are only valid if they are explicitly
	// allowed by something in the namespace they are referring to. For example:
	// Gateway has the AllowedRoutes field, and ReferenceGrant provides a
	// generic way to enable any other kind of cross-namespace reference.
	//
	// <gateway:experimental:description>
	// ParentRefs from a Route to a Service in the same namespace are "producer"
	// routes, which apply default routing rules to inbound connections from
	// any namespace to the Service.
	//
	// ParentRefs from a Route to a Service in a different namespace are
	// "consumer" routes, and these routing rules are only applied to outbound
	// connections originating from the same namespace as the Route, for which
	// the intended destination of the connections are a Service targeted as a
	// ParentRef of the Route.
	// </gateway:experimental:description>
	//
	// Support: Core
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`

	// Name is the name of the referent.
	//
	// Support: Core
	Name ObjectName `json:"name"`

	// SectionName is the name of a section within the target resource. In the
	// following resources, SectionName is interpreted as the following:
	//
	// * Gateway: Listener name. When both Port (experimental) and SectionName
	// are specified, the name and port of the selected listener must match
	// both specified values.
	// * Service: Port name. When both Port (experimental) and SectionName
	// are specified, the name and port of the selected listener must match
	// both specified values.
	//
	// Implementations MAY choose to support attaching Routes to other resources.
	// If that is the case, they MUST clearly document how SectionName is
	// interpreted.
	//
	// When unspecified (empty string), this will reference the entire resource.
	// For the purpose of status, an attachment is considered successful if at
	// least one section in the parent resource accepts it. For example, Gateway
	// listeners can restrict which Routes can attach to them by Route kind,
	// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment from
	// the referencing Route, the Route MUST be considered successfully
	// attached. If no Gateway listeners accept attachment from this Route, the
	// Route MUST be considered detached from the Gateway.
	//
	// Support: Core
	//
	// +optional
	SectionName *SectionName `json:"sectionName,omitempty"`

	// Port is the network port this Route targets. It can be interpreted
	// differently based on the type of parent resource.
	//
	// When the parent resource is a Gateway, this targets all listeners
	// listening on the specified port that also support this kind of Route(and
	// select this Route). It's not recommended to set `Port` unless the
	// networking behaviors specified in a Route must apply to a specific port
	// as opposed to a listener(s) whose port(s) may be changed. When both Port
	// and SectionName are specified, the name and port of the selected listener
	// must match both specified values.
	//
	// <gateway:experimental:description>
	// When the parent resource is a Service, this targets a specific port in the
	// Service spec. When both Port (experimental) and SectionName are specified,
	// the name and port of the selected port must match both specified values.
	// </gateway:experimental:description>
	//
	// Implementations MAY choose to support other parent resources.
	// Implementations supporting other types of parent resources MUST clearly
	// document how/if Port is interpreted.
	//
	// For the purpose of status, an attachment is considered successful as
	// long as the parent resource accepts it partially. For example, Gateway
	// listeners can restrict which Routes can attach to them by Route kind,
	// namespace, or hostname. If 1 of 2 Gateway listeners accept attachment
	// from the referencing Route, the Route MUST be considered successfully
	// attached. If no Gateway listeners accept attachment from this Route,
	// the Route MUST be considered detached from the Gateway.
	//
	// Support: Extended
	//
	// +optional
	Port *PortNumber `json:"port,omitempty"`
}

// CommonRouteSpec defines the common attributes that all Routes MUST include
// within their spec.
type CommonRouteSpec struct {
	// ParentRefs references the resources (usually Gateways) that a Route wants
	// to be attached to. Note that the referenced parent resource needs to
	// allow this for the attachment to be complete. For Gateways, that means
	// the Gateway needs to allow attachment from Routes of this kind and
	// namespace. For Services, that means the Service must either be in the same
	// namespace for a "producer" route, or the mesh implementation must support
	// and allow "consumer" routes for the referenced Service. ReferenceGrant is
	// not applicable for governing ParentRefs to Services - it is not possible to
	// create a "producer" route for a Service in a different namespace from the
	// Route.
	//
	// There are two kinds of parent resources with "Core" support:
	//
	// * Gateway (Gateway conformance profile)
	// * Service (Mesh conformance profile, ClusterIP Services only)
	//
	// This API may be extended in the future to support additional kinds of parent
	// resources.
	//
	// ParentRefs must be _distinct_. This means either that:
	//
	// * They select different objects.  If this is the case, then parentRef
	//   entries are distinct. In terms of fields, this means that the
	//   multi-part key defined by `group`, `kind`, `namespace`, and `name` must
	//   be unique across all parentRef entries in the Route.
	// * They do not select different objects, but for each optional field used,
	//   each ParentRef that selects the same object must set the same set of
	//   optional fields to different values. If one ParentRef sets a
	//   combination of optional fields, all must set the same combination.
	//
	// Some examples:
	//
	// * If one ParentRef sets `sectionName`, all ParentRefs referencing the
	//   same object must also set `sectionName`.
	// * If one ParentRef sets `port`, all ParentRefs referencing the same
	//   object must also set `port`.
	// * If one ParentRef sets `sectionName` and `port`, all ParentRefs
	//   referencing the same object must also set `sectionName` and `port`.
	//
	// It is possible to separately reference multiple distinct objects that may
	// be collapsed by an implementation. For example, some implementations may
	// choose to merge compatible Gateway Listeners together. If that is the
	// case, the list of routes attached to those resources should also be
	// merged.
	//
	// Note that for ParentRefs that cross namespace boundaries, there are specific
	// rules. Cross-namespace references are only valid if they are explicitly
	// allowed by something in the namespace they are referring to. For example,
	// Gateway has the AllowedRoutes field, and ReferenceGrant provides a
	// generic way to enable other kinds of cross-namespace reference.
	//
	// <gateway:experimental:description>
	// ParentRefs from a Route to a Service in the same namespace are "producer"
	// routes, which apply default routing rules to inbound connections from
	// any namespace to the Service.
	//
	// ParentRefs from a Route to a Service in a different namespace are
	// "consumer" routes, and these routing rules are only applied to outbound
	// connections originating from the same namespace as the Route, for which
	// the intended destination of the connections are a Service targeted as a
	// ParentRef of the Route.
	// </gateway:experimental:description>
	//
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// <gateway:standard:validation:XValidation:message="sectionName must be specified when parentRefs includes 2 or more references to the same parent",rule="self.all(p1, self.all(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name && (((!has(p1.__namespace__) || p1.__namespace__ == '') && (!has(p2.__namespace__) || p2.__namespace__ == '')) || (has(p1.__namespace__) && has(p2.__namespace__) && p1.__namespace__ == p2.__namespace__ )) ? ((!has(p1.sectionName) || p1.sectionName == '') == (!has(p2.sectionName) || p2.sectionName == '')) : true))">
	// <gateway:standard:validation:XValidation:message="sectionName must be unique when parentRefs includes 2 or more references to the same parent",rule="self.all(p1, self.exists_one(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name && (((!has(p1.__namespace__) || p1.__namespace__ == '') && (!has(p2.__namespace__) || p2.__namespace__ == '')) || (has(p1.__namespace__) && has(p2.__namespace__) && p1.__namespace__ == p2.__namespace__ )) && (((!has(p1.sectionName) || p1.sectionName == '') && (!has(p2.sectionName) || p2.sectionName == '')) || (has(p1.sectionName) && has(p2.sectionName) && p1.sectionName == p2.sectionName))))">
	// <gateway:experimental:validation:XValidation:message="sectionName or port must be specified when parentRefs includes 2 or more references to the same parent",rule="self.all(p1, self.all(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name && (((!has(p1.__namespace__) || p1.__namespace__ == '') && (!has(p2.__namespace__) || p2.__namespace__ == '')) || (has(p1.__namespace__) && has(p2.__namespace__) && p1.__namespace__ == p2.__namespace__)) ? ((!has(p1.sectionName) || p1.sectionName == '') == (!has(p2.sectionName) || p2.sectionName == '') && (!has(p1.port) || p1.port == 0) == (!has(p2.port) || p2.port == 0)): true))">
	// <gateway:experimental:validation:XValidation:message="sectionName or port must be unique when parentRefs includes 2 or more references to the same parent",rule="self.all(p1, self.exists_one(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name && (((!has(p1.__namespace__) || p1.__namespace__ == '') && (!has(p2.__namespace__) || p2.__namespace__ == '')) || (has(p1.__namespace__) && has(p2.__namespace__) && p1.__namespace__ == p2.__namespace__ )) && (((!has(p1.sectionName) || p1.sectionName == '') && (!has(p2.sectionName) || p2.sectionName == '')) || ( has(p1.sectionName) && has(p2.sectionName) && p1.sectionName == p2.sectionName)) && (((!has(p1.port) || p1.port == 0) && (!has(p2.port) || p2.port == 0)) || (has(p1.port) && has(p2.port) && p1.port == p2.port))))">
	ParentRefs []ParentReference `json:"parentRefs,omitempty"`
}

// PortNumber defines a network port.
//
// +kubebuilder:validation:Minimum=1
// +kubebuilder:validation:Maximum=65535
type PortNumber int32

// BackendRef defines how a Route should forward a request to a Kubernetes
// resource.
//
// Note that when a namespace different than the local namespace is specified, a
// ReferenceGrant object is required in the referent namespace to allow that
// namespace's owner to accept the reference. See the ReferenceGrant
// documentation for details.
//
// <gateway:experimental:description>
//
// When the BackendRef points to a Kubernetes Service, implementations SHOULD
// honor the appProtocol field if it is set for the target Service Port.
//
// Implementations supporting appProtocol SHOULD recognize the Kubernetes
// Standard Application Protocols defined in KEP-3726.
//
// If a Service appProtocol isn't specified, an implementation MAY infer the
// backend protocol through its own means. Implementations MAY infer the
// protocol from the Route type referring to the backend Service.
//
// If a Route is not able to send traffic to the backend using the specified
// protocol then the backend is considered invalid. Implementations MUST set the
// "ResolvedRefs" condition to "False" with the "UnsupportedProtocol" reason.
//
// </gateway:experimental:description>
//
// Note that when the BackendTLSPolicy object is enabled by the implementation,
// there are some extra rules about validity to consider here. See the fields
// where this struct is used for more information about the exact behavior.
type BackendRef struct {
	// BackendObjectReference references a Kubernetes object.
	BackendObjectReference `json:",inline"`

	// Weight specifies the proportion of requests forwarded to the referenced
	// backend. This is computed as weight/(sum of all weights in this
	// BackendRefs list). For non-zero values, there may be some epsilon from
	// the exact proportion defined here depending on the precision an
	// implementation supports. Weight is not a percentage and the sum of
	// weights does not need to equal 100.
	//
	// If only one backend is specified and it has a weight greater than 0, 100%
	// of the traffic is forwarded to that backend. If weight is set to 0, no
	// traffic should be forwarded for this entry. If unspecified, weight
	// defaults to 1.
	//
	// Support for this field varies based on the context where used.
	//
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	Weight *int32 `json:"weight,omitempty"`
}

// RouteConditionType is a type of condition for a route.
type RouteConditionType string

// RouteConditionReason is a reason for a route condition.
type RouteConditionReason string

const (
	// This condition indicates whether the route has been accepted or rejected
	// by a Gateway, and why.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NotAllowedByListeners"
	// * "NoMatchingListenerHostname"
	// * "NoMatchingParent"
	// * "UnsupportedValue"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	RouteConditionAccepted RouteConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the Route has been
	// accepted by the Gateway.
	RouteReasonAccepted RouteConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the route has not
	// been accepted by a Gateway because the Gateway has no Listener whose
	// allowedRoutes criteria permit the route
	RouteReasonNotAllowedByListeners RouteConditionReason = "NotAllowedByListeners"

	// This reason is used with the "Accepted" condition when the Gateway has no
	// compatible Listeners whose Hostname matches the route
	RouteReasonNoMatchingListenerHostname RouteConditionReason = "NoMatchingListenerHostname"

	// This reason is used with the "Accepted" condition when there are
	// no matching Parents. In the case of Gateways, this can occur when
	// a Route ParentRef specifies a Port and/or SectionName that does not
	// match any Listeners in the Gateway.
	RouteReasonNoMatchingParent RouteConditionReason = "NoMatchingParent"

	// This reason is used with the "Accepted" condition when a value for an Enum
	// is not recognized.
	RouteReasonUnsupportedValue RouteConditionReason = "UnsupportedValue"

	// This reason is used with the "Accepted" when a controller has not yet
	// reconciled the route.
	RouteReasonPending RouteConditionReason = "Pending"

	// This reason is used with the "Accepted" condition when there
	// are incompatible filters present on a route rule (for example if
	// the URLRewrite and RequestRedirect are both present on an HTTPRoute).
	RouteReasonIncompatibleFilters RouteConditionReason = "IncompatibleFilters"
)

const (
	// This condition indicates whether the controller was able to resolve all
	// the object references for the Route.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "ResolvedRefs"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "RefNotPermitted"
	// * "InvalidKind"
	// * "BackendNotFound"
	// * "UnsupportedProtocol"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	RouteConditionResolvedRefs RouteConditionType = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when the condition
	// is true.
	RouteReasonResolvedRefs RouteConditionReason = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when
	// one of the Listener's Routes has a BackendRef to an object in
	// another namespace, where the object in the other namespace does
	// not have a ReferenceGrant explicitly allowing the reference.
	RouteReasonRefNotPermitted RouteConditionReason = "RefNotPermitted"

	// This reason is used with the "ResolvedRefs" condition when
	// one of the Route's rules has a reference to an unknown or unsupported
	// Group and/or Kind.
	RouteReasonInvalidKind RouteConditionReason = "InvalidKind"

	// This reason is used with the "ResolvedRefs" condition when one of the
	// Route's rules has a reference to a resource that does not exist.
	RouteReasonBackendNotFound RouteConditionReason = "BackendNotFound"

	// This reason is used with the "ResolvedRefs" condition when one of the
	// Route's rules has a reference to a resource with an app protocol that
	// is not supported by this implementation.
	RouteReasonUnsupportedProtocol RouteConditionReason = "UnsupportedProtocol"
)

const (
	// This condition indicates that the Route contains a combination of both
	// valid and invalid rules.
	//
	// When this happens, implementations MUST take one of the following
	// approaches:
	//
	// 1) Drop Rule(s): With this approach, implementations will drop the
	//    invalid Route Rule(s) until they are fully valid again. The message
	//    for this condition MUST start with the prefix "Dropped Rule" and
	//    include information about which Rules have been dropped. In this
	//    state, the "Accepted" condition MUST be set to "True" with the latest
	//    generation of the resource.
	// 2) Fall Back: With this approach, implementations will fall back to the
	//    last known good state of the entire Route. The message for this
	//    condition MUST start with the prefix "Fall Back" and include
	//    information about why the current Rule(s) are invalid. To represent
	//    this, the "Accepted" condition MUST be set to "True" with the
	//    generation of the last known good state of the resource.
	//
	// Reverting to the last known good state should only be done by
	// implementations that have a means of restoring that state if/when they
	// are restarted.
	//
	// This condition MUST NOT be set if a Route is fully valid, fully invalid,
	// or not accepted. By extension, that means that this condition MUST only
	// be set when it is "True".
	//
	// Possible reasons for this condition to be True are:
	//
	// * "UnsupportedValue"
	//
	// Controllers may raise this condition with other reasons, but should
	// prefer to use the reasons listed above to improve interoperability.
	RouteConditionPartiallyInvalid RouteConditionType = "PartiallyInvalid"
)

// RouteParentStatus describes the status of a route with respect to an
// associated Parent.
type RouteParentStatus struct {
	// ParentRef corresponds with a ParentRef in the spec that this
	// RouteParentStatus struct describes the status of.
	ParentRef ParentReference `json:"parentRef"`

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
	ControllerName GatewayController `json:"controllerName"`

	// Conditions describes the status of the route with respect to the Gateway.
	// Note that the route's availability is also subject to the Gateway's own
	// status conditions and listener status.
	//
	// If the Route's ParentRef specifies an existing Gateway that supports
	// Routes of this kind AND that Gateway's controller has sufficient access,
	// then that Gateway's controller MUST set the "Accepted" condition on the
	// Route, to indicate whether the route has been accepted or rejected by the
	// Gateway, and why.
	//
	// A Route MUST be considered "Accepted" if at least one of the Route's
	// rules is implemented by the Gateway.
	//
	// There are a number of cases where the "Accepted" condition may not be set
	// due to lack of controller visibility, that includes when:
	//
	// * The Route refers to a non-existent parent.
	// * The Route is of a type that the controller does not support.
	// * The Route is in a namespace the controller does not have access to.
	//
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RouteStatus defines the common attributes that all Routes MUST include within
// their status.
type RouteStatus struct {
	// Parents is a list of parent resources (usually Gateways) that are
	// associated with the route, and the status of the route with respect to
	// each parent. When this route attaches to a parent, the controller that
	// manages the parent must add an entry to this list when the controller
	// first sees the route and should update the entry as appropriate when the
	// route or gateway is modified.
	//
	// Note that parent references that cannot be resolved by an implementation
	// of this API will not be added to this list. Implementations of this API
	// can only populate Route status for the Gateways/parent resources they are
	// responsible for.
	//
	// A maximum of 32 Gateways will be represented in this list. An empty list
	// means the route has not been attached to any Gateway.
	//
	// +kubebuilder:validation:MaxItems=32
	Parents []RouteParentStatus `json:"parents"`
}

// Hostname is the fully qualified domain name of a network host. This matches
// the RFC 1123 definition of a hostname with 2 notable exceptions:
//
//  1. IPs are not allowed.
//  2. A hostname may be prefixed with a wildcard label (`*.`). The wildcard
//     label must appear by itself as the first label.
//
// Hostname can be "precise" which is a domain name without the terminating
// dot of a network host (e.g. "foo.example.com") or "wildcard", which is a
// domain name prefixed with a single wildcard label (e.g. `*.example.com`).
//
// Note that as per RFC1035 and RFC1123, a *label* must consist of lower case
// alphanumeric characters or '-', and must start and end with an alphanumeric
// character. No other punctuation is allowed.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type Hostname string

// PreciseHostname is the fully qualified domain name of a network host. This
// matches the RFC 1123 definition of a hostname with 1 notable exception that
// numeric IP addresses are not allowed.
//
// Note that as per RFC1035 and RFC1123, a *label* must consist of lower case
// alphanumeric characters or '-', and must start and end with an alphanumeric
// character. No other punctuation is allowed.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type PreciseHostname string

// Group refers to a Kubernetes Group. It must either be an empty string or a
// RFC 1123 subdomain.
//
// This validation is based off of the corresponding Kubernetes validation:
// https://github.com/kubernetes/apimachinery/blob/02cfb53916346d085a6c6c7c66f882e3c6b0eca6/pkg/util/validation/validation.go#L208
//
// Valid values include:
//
// * "" - empty string implies core Kubernetes API group
// * "gateway.networking.k8s.io"
// * "foo.example.com"
//
// Invalid values include:
//
// * "example.com/bar" - "/" is an invalid character
//
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^$|^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type Group string

// Kind refers to a Kubernetes Kind.
//
// Valid values include:
//
// * "Service"
// * "HTTPRoute"
//
// Invalid values include:
//
// * "invalid/kind" - "/" is an invalid character
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$`
type Kind string

// ObjectName refers to the name of a Kubernetes object.
// Object names can have a variety of forms, including RFC 1123 subdomains,
// RFC 1123 labels, or RFC 1035 labels.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
type ObjectName string

// Namespace refers to a Kubernetes namespace. It must be a RFC 1123 label.
//
// This validation is based off of the corresponding Kubernetes validation:
// https://github.com/kubernetes/apimachinery/blob/02cfb53916346d085a6c6c7c66f882e3c6b0eca6/pkg/util/validation/validation.go#L187
//
// This is used for Namespace name validation here:
// https://github.com/kubernetes/apimachinery/blob/02cfb53916346d085a6c6c7c66f882e3c6b0eca6/pkg/api/validation/generic.go#L63
//
// Valid values include:
//
// * "example"
//
// Invalid values include:
//
// * "example.com" - "." is an invalid character
//
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
type Namespace string

// SectionName is the name of a section in a Kubernetes resource.
//
// In the following resources, SectionName is interpreted as the following:
//
// * Gateway: Listener name
// * HTTPRoute: HTTPRouteRule name
// * Service: Port name
//
// Section names can have a variety of forms, including RFC 1123 subdomains,
// RFC 1123 labels, or RFC 1035 labels.
//
// This validation is based off of the corresponding Kubernetes validation:
// https://github.com/kubernetes/apimachinery/blob/02cfb53916346d085a6c6c7c66f882e3c6b0eca6/pkg/util/validation/validation.go#L208
//
// Valid values include:
//
// * "example"
// * "foo-example"
// * "example.com"
// * "foo.example.com"
//
// Invalid values include:
//
// * "example.com/bar" - "/" is an invalid character
//
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
type SectionName string

// GatewayController is the name of a Gateway API controller. It must be a
// domain prefixed path.
//
// Valid values include:
//
// * "example.com/bar"
//
// Invalid values include:
//
// * "example.com" - must include path
// * "foo.example.com" - must include path
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/[A-Za-z0-9\/\-._~%!$&'()*+,;=:]+$`
type GatewayController string

// AnnotationKey is the key of an annotation in Gateway API. This is used for
// validation of maps such as TLS options. This matches the Kubernetes
// "qualified name" validation that is used for annotations and other common
// values.
//
// Valid values include:
//
// * example
// * example.com
// * example.com/path
// * example.com/path.html
//
// Invalid values include:
//
// * example~ - "~" is an invalid character
// * example.com. - can not start or end with "."
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]/?)*$`
type AnnotationKey string

// AnnotationValue is the value of an annotation in Gateway API. This is used
// for validation of maps such as TLS options. This roughly matches Kubernetes
// annotation validation, although the length validation in that case is based
// on the entire size of the annotations struct.
//
// +kubebuilder:validation:MinLength=0
// +kubebuilder:validation:MaxLength=4096
type AnnotationValue string

// AddressType defines how a network address is represented as a text string.
// This may take two possible forms:
//
// * A predefined CamelCase string identifier (currently limited to `IPAddress` or `Hostname`)
// * A domain-prefixed string identifier (like `acme.io/CustomAddressType`)
//
// Values `IPAddress` and `Hostname` have Extended support.
//
// The `NamedAddress` value has been deprecated in favor of implementation
// specific domain-prefixed strings.
//
// All other values, including domain-prefixed values have Implementation-specific support,
// which are used in implementation-specific behaviors. Support for additional
// predefined CamelCase identifiers may be added in future releases.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^Hostname|IPAddress|NamedAddress|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/[A-Za-z0-9\/\-._~%!$&'()*+,;=:]+$`
type AddressType string

// HeaderName is the name of a header or query parameter.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
// +k8s:deepcopy-gen=false
type HeaderName string

// Duration is a string value representing a duration in time. The format is as specified
// in GEP-2257, a strict subset of the syntax parsed by Golang time.ParseDuration.
//
// +kubebuilder:validation:Pattern=`^([0-9]{1,5}(h|m|s|ms)){1,4}$`
type Duration string

const (
	// A textual representation of a numeric IP address. IPv4
	// addresses must be in dotted-decimal form. IPv6 addresses
	// must be in a standard IPv6 text representation
	// (see [RFC 5952](https://tools.ietf.org/html/rfc5952)).
	//
	// This type is intended for specific addresses. Address ranges are not
	// supported (e.g. you can not use a CIDR range like 127.0.0.0/24 as an
	// IPAddress).
	//
	// Support: Extended
	IPAddressType AddressType = "IPAddress"

	// A Hostname represents a DNS based ingress point. This is similar to the
	// corresponding hostname field in Kubernetes load balancer status. For
	// example, this concept may be used for cloud load balancers where a DNS
	// name is used to expose a load balancer.
	//
	// Support: Extended
	HostnameAddressType AddressType = "Hostname"

	// A NamedAddress provides a way to reference a specific IP address by name.
	// For example, this may be a name or other unique identifier that refers
	// to a resource on a cloud provider such as a static IP.
	//
	// The `NamedAddress` type has been deprecated in favor of implementation
	// specific domain-prefixed strings.
	//
	// Support: Implementation-specific
	NamedAddressType AddressType = "NamedAddress"
)

// SessionPersistence defines the desired state of SessionPersistence.
// +kubebuilder:validation:XValidation:message="AbsoluteTimeout must be specified when cookie lifetimeType is Permanent",rule="!has(self.cookieConfig.lifetimeType) || self.cookieConfig.lifetimeType != 'Permanent' || has(self.absoluteTimeout)"
type SessionPersistence struct {
	// SessionName defines the name of the persistent session token
	// which may be reflected in the cookie or the header. Users
	// should avoid reusing session names to prevent unintended
	// consequences, such as rejection or unpredictable behavior.
	//
	// Support: Implementation-specific
	//
	// +optional
	// +kubebuilder:validation:MaxLength=128
	SessionName *string `json:"sessionName,omitempty"`

	// AbsoluteTimeout defines the absolute timeout of the persistent
	// session. Once the AbsoluteTimeout duration has elapsed, the
	// session becomes invalid.
	//
	// Support: Extended
	//
	// +optional
	AbsoluteTimeout *Duration `json:"absoluteTimeout,omitempty"`

	// IdleTimeout defines the idle timeout of the persistent session.
	// Once the session has been idle for more than the specified
	// IdleTimeout duration, the session becomes invalid.
	//
	// Support: Extended
	//
	// +optional
	IdleTimeout *Duration `json:"idleTimeout,omitempty"`

	// Type defines the type of session persistence such as through
	// the use a header or cookie. Defaults to cookie based session
	// persistence.
	//
	// Support: Core for "Cookie" type
	//
	// Support: Extended for "Header" type
	//
	// +optional
	// +kubebuilder:default=Cookie
	Type *SessionPersistenceType `json:"type,omitempty"`

	// CookieConfig provides configuration settings that are specific
	// to cookie-based session persistence.
	//
	// Support: Core
	//
	// +optional
	CookieConfig *CookieConfig `json:"cookieConfig,omitempty"`
}

// +kubebuilder:validation:Enum=Cookie;Header
type SessionPersistenceType string

const (
	// CookieBasedSessionPersistence specifies cookie-based session
	// persistence.
	//
	// Support: Core
	CookieBasedSessionPersistence SessionPersistenceType = "Cookie"

	// HeaderBasedSessionPersistence specifies header-based session
	// persistence.
	//
	// Support: Extended
	HeaderBasedSessionPersistence SessionPersistenceType = "Header"
)

// CookieConfig defines the configuration for cookie-based session persistence.
type CookieConfig struct {
	// LifetimeType specifies whether the cookie has a permanent or
	// session-based lifetime. A permanent cookie persists until its
	// specified expiry time, defined by the Expires or Max-Age cookie
	// attributes, while a session cookie is deleted when the current
	// session ends.
	//
	// When set to "Permanent", AbsoluteTimeout indicates the
	// cookie's lifetime via the Expires or Max-Age cookie attributes
	// and is required.
	//
	// When set to "Session", AbsoluteTimeout indicates the
	// absolute lifetime of the cookie tracked by the gateway and
	// is optional.
	//
	// Support: Core for "Session" type
	//
	// Support: Extended for "Permanent" type
	//
	// +optional
	// +kubebuilder:default=Session
	LifetimeType *CookieLifetimeType `json:"lifetimeType,omitempty"`
}

// +kubebuilder:validation:Enum=Permanent;Session
type CookieLifetimeType string

const (
	// SessionCookieLifetimeType specifies the type for a session
	// cookie.
	//
	// Support: Core
	SessionCookieLifetimeType CookieLifetimeType = "Session"

	// PermanentCookieLifetimeType specifies the type for a permanent
	// cookie.
	//
	// Support: Extended
	PermanentCookieLifetimeType CookieLifetimeType = "Permanent"
)
