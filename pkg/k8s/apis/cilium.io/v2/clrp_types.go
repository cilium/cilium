/*
 * // Copyright 2020 Authors of Cilium
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package v2

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="clusterwidelocalredirectpolicy",path="clusterwidelocalredirectpolicies",scope="Cluster",shortName={clrp}

// ClusterwideLocalRedirectPolicy is a Kubernetes Custom Resource that is a
// cluster scoped version of LocalRedirectPolicy.
type ClusterwideLocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	LocalRedirectPolicy `json:",inline"`

	// Most recent status of the local redirect policy
	// Read-only
	Status LocalRedirectPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// ClusterwideLocalRedirectPolicyList is a list of ClusterwideLocalRedirectPolicy objects.
type ClusterwideLocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of ClusterwideLocalDirectPolicy.
	Items []ClusterwideLocalRedirectPolicy `json:"items"`
}
