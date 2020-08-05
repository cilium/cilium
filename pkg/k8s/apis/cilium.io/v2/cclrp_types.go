//  Copyright 2020 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package v2

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="ciliumclusterwidelocalredirectpolicy",path="ciliumclusterwidelocalredirectpolicies",scope="Cluster",shortName={cclrp}

// CiliumClusterwideLocalRedirectPolicy is a Kubernetes Custom Resource that is a
// cluster-scoped version of CiliumLocalRedirectPolicy.
type CiliumClusterwideLocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	*CiliumLocalRedirectPolicy `json:",inline"`

	// Status is the most recent status of the clusterwide local redirect policy.
	// It is a read-only field.
	//
	// The reason this field exists in this structure is due a bug in the k8s
	// code-generator that doesn't create a `UpdateStatus` method because the
	// field does not exist in the structure.
	//
	// +kubebuilder:validation:Optional
	Status CiliumLocalRedirectPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumClusterwideLocalRedirectPolicyList is a list of CiliumClusterwideLocalRedirectPolicy objects.
type CiliumClusterwideLocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of ClusterwideLocalDirectPolicy.
	Items []CiliumClusterwideLocalRedirectPolicy `json:"items"`
}
