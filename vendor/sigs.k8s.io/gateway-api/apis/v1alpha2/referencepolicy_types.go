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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=refpol
// +kubebuilder:deprecatedversion:warning="ReferencePolicy has been renamed to ReferenceGrant. ReferencePolicy will be removed in v0.6.0 in favor of the identical ReferenceGrant resource."
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ReferencePolicy identifies kinds of resources in other namespaces that are
// trusted to reference the specified kinds of resources in the same namespace
// as the policy.
//
// Note: This resource has been renamed to ReferenceGrant. ReferencePolicy will
// be removed in v0.6.0 in favor of the identical ReferenceGrant resource.
//
// Each ReferencePolicy can be used to represent a unique trust relationship.
// Additional Reference Policies can be used to add to the set of trusted
// sources of inbound references for the namespace they are defined within.
//
// All cross-namespace references in Gateway API (with the exception of cross-namespace
// Gateway-route attachment) require a ReferenceGrant.
//
// Support: Core
//
type ReferencePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of ReferencePolicy.
	Spec ReferenceGrantSpec `json:"spec,omitempty"`

	// Note that `Status` sub-resource has been excluded at the
	// moment as it was difficult to work out the design.
	// `Status` sub-resource may be added in future.
}

// +kubebuilder:object:root=true
// ReferencePolicyList contains a list of ReferencePolicy.
type ReferencePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ReferencePolicy `json:"items"`
}
