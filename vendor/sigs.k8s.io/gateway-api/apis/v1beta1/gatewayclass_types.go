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
// Whenever one or more Gateways are using a GatewayClass, implementations SHOULD
// add the `gateway-exists-finalizer.gateway.networking.k8s.io` finalizer on the
// associated GatewayClass. This ensures that a GatewayClass associated with a
// Gateway is not deleted while in use.
//
// GatewayClass is a Cluster level resource.
type GatewayClass v1.GatewayClass

// +kubebuilder:object:root=true

// GatewayClassList contains a list of GatewayClass
type GatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayClass `json:"items"`
}

// GatewayClassSpec reflects the configuration of a class of Gateways.
// +k8s:deepcopy-gen=false
type GatewayClassSpec = v1.GatewayClassSpec

// ParametersReference identifies an API object containing controller-specific
// configuration resource within the cluster.
// +k8s:deepcopy-gen=false
type ParametersReference = v1.ParametersReference

// GatewayClassConditionType is the type for status conditions on
// Gateway resources. This type should be used with the
// GatewayClassStatus.Conditions field.
// +k8s:deepcopy-gen=false
type GatewayClassConditionType = v1.GatewayClassConditionType

// GatewayClassConditionReason defines the set of reasons that explain why a
// particular GatewayClass condition type has been raised.
// +k8s:deepcopy-gen=false
type GatewayClassConditionReason = v1.GatewayClassConditionReason

// GatewayClassStatus is the current status for the GatewayClass.
// +k8s:deepcopy-gen=false
type GatewayClassStatus = v1.GatewayClassStatus
