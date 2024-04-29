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

	v1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=gtw
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.gatewayClassName`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.addresses[*].value`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Gateway represents an instance of a service-traffic handling infrastructure
// by binding Listeners to a set of IP addresses.
type Gateway v1.Gateway

// +kubebuilder:object:root=true

// GatewayList contains a list of Gateways.
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

// GatewaySpec defines the desired state of Gateway.
//
// Not all possible combinations of options specified in the Spec are
// valid. Some invalid configurations can be caught synchronously via CRD
// validation, but there are many cases that will require asynchronous
// signaling via the GatewayStatus block.
// +k8s:deepcopy-gen=false
type GatewaySpec = v1.GatewaySpec

// Listener embodies the concept of a logical endpoint where a Gateway accepts
// network connections.
// +k8s:deepcopy-gen=false
type Listener = v1.Listener

// ProtocolType defines the application protocol accepted by a Listener.
// Implementations are not required to accept all the defined protocols. If an
// implementation does not support a specified protocol, it MUST set the
// "Accepted" condition to False for the affected Listener with a reason of
// "UnsupportedProtocol".
//
// Core ProtocolType values are listed in the table below.
//
// Implementations can define their own protocols if a core ProtocolType does not
// exist. Such definitions must use prefixed name, such as
// `mycompany.com/my-custom-protocol`. Un-prefixed names are reserved for core
// protocols. Any protocol defined by implementations will fall under
// implementation-specific conformance.
//
// Valid values include:
//
// * "HTTP" - Core support
// * "example.com/bar" - Implementation-specific support
//
// Invalid values include:
//
// * "example.com" - must include path if domain is used
// * "foo.example.com" - must include path if domain is used
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=255
// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zSA-Z0-9]*[a-zA-Z0-9])?$|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/[A-Za-z0-9]+$`
// +k8s:deepcopy-gen=false
type ProtocolType = v1.ProtocolType

// GatewayTLSConfig describes a TLS configuration.
// +k8s:deepcopy-gen=false
type GatewayTLSConfig = v1.GatewayTLSConfig

// TLSModeType type defines how a Gateway handles TLS sessions.
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Ready Condition for the Listener to `status: False`, with a
// Reason of `Invalid`.
//
// +kubebuilder:validation:Enum=Terminate;Passthrough
// +k8s:deepcopy-gen=false
type TLSModeType = v1.TLSModeType

// AllowedRoutes defines which Routes may be attached to this Listener.
// +k8s:deepcopy-gen=false
type AllowedRoutes = v1.AllowedRoutes

// FromNamespaces specifies namespace from which Routes may be attached to a
// Gateway.
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Ready Condition for the Listener to `status: False`, with a
// Reason of `Invalid`.
//
// +kubebuilder:validation:Enum=All;Selector;Same
// +k8s:deepcopy-gen=false
type FromNamespaces = v1.FromNamespaces

// RouteNamespaces indicate which namespaces Routes should be selected from.
// +k8s:deepcopy-gen=false
type RouteNamespaces = v1.RouteNamespaces

// RouteGroupKind indicates the group and kind of a Route resource.
// +k8s:deepcopy-gen=false
type RouteGroupKind = v1.RouteGroupKind

// GatewayAddress describes an address that can be bound to a Gateway.
// +k8s:deepcopy-gen=false
type GatewayAddress = v1.GatewayAddress

// GatewayStatus defines the observed state of Gateway.
// +k8s:deepcopy-gen=false
type GatewayStatus = v1.GatewayStatus

// GatewayConditionType is a type of condition associated with a
// Gateway. This type should be used with the GatewayStatus.Conditions
// field.
// +k8s:deepcopy-gen=false
type GatewayConditionType = v1.GatewayConditionType

// GatewayConditionReason defines the set of reasons that explain why a
// particular Gateway condition type has been raised.
// +k8s:deepcopy-gen=false
type GatewayConditionReason = v1.GatewayConditionReason

// ListenerStatus is the status associated with a Listener.
// +k8s:deepcopy-gen=false
type ListenerStatus = v1.ListenerStatus

// ListenerConditionType is a type of condition associated with the
// listener. This type should be used with the ListenerStatus.Conditions
// field.
// +k8s:deepcopy-gen=false
type ListenerConditionType = v1.ListenerConditionType

// ListenerConditionReason defines the set of reasons that explain
// why a particular Listener condition type has been raised.
// +k8s:deepcopy-gen=false
type ListenerConditionReason = v1.ListenerConditionReason
