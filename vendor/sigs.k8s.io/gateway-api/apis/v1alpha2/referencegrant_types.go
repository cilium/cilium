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

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=refgrant
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:skipversion
// +kubebuilder:deprecatedversion:warning="The v1alpha2 version of ReferenceGrant has been deprecated and will be removed in a future release of the API. Please upgrade to v1beta1."

// ReferenceGrant identifies kinds of resources in other namespaces that are
// trusted to reference the specified kinds of resources in the same namespace
// as the policy.
//
// Each ReferenceGrant can be used to represent a unique trust relationship.
// Additional Reference Grants can be used to add to the set of trusted
// sources of inbound references for the namespace they are defined within.
//
// A ReferenceGrant is required for all cross-namespace references in Gateway API
// (with the exception of cross-namespace Route-Gateway attachment, which is
// governed by the AllowedRoutes configuration on the Gateway, and cross-namespace
// Service ParentRefs on a "consumer" mesh Route, which defines routing rules
// applicable only to workloads in the Route namespace). ReferenceGrants allowing
// a reference from a Route to a Service are only applicable to BackendRefs.
//
// ReferenceGrant is a form of runtime verification allowing users to assert
// which cross-namespace object references are permitted. Implementations that
// support ReferenceGrant MUST NOT permit cross-namespace references which have
// no grant, and MUST respond to the removal of a grant by revoking the access
// that the grant allowed.
type ReferenceGrant v1beta1.ReferenceGrant

// +kubebuilder:object:root=true
// ReferenceGrantList contains a list of ReferenceGrant.
type ReferenceGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ReferenceGrant `json:"items"`
}

// ReferenceGrantSpec identifies a cross namespace relationship that is trusted
// for Gateway API.
// +k8s:deepcopy-gen=false
type ReferenceGrantSpec = v1beta1.ReferenceGrantSpec

// ReferenceGrantFrom describes trusted namespaces and kinds.
// +k8s:deepcopy-gen=false
type ReferenceGrantFrom = v1beta1.ReferenceGrantFrom

// ReferenceGrantTo describes what Kinds are allowed as targets of the
// references.
// +k8s:deepcopy-gen=false
type ReferenceGrantTo = v1beta1.ReferenceGrantTo
