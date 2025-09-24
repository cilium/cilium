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

type GatewaySpec = v1.GatewaySpec

type Listener = v1.Listener

type ProtocolType = v1.ProtocolType

type ListenerTLSConfig = v1.ListenerTLSConfig

type TLSModeType = v1.TLSModeType

type AllowedRoutes = v1.AllowedRoutes

type FromNamespaces = v1.FromNamespaces

type RouteNamespaces = v1.RouteNamespaces

type RouteGroupKind = v1.RouteGroupKind

type GatewaySpecAddress = v1.GatewaySpecAddress

type GatewayStatus = v1.GatewayStatus

type GatewayConditionType = v1.GatewayConditionType

type GatewayConditionReason = v1.GatewayConditionReason

type ListenerStatus = v1.ListenerStatus

type ListenerConditionType = v1.ListenerConditionType

type ListenerConditionReason = v1.ListenerConditionReason
