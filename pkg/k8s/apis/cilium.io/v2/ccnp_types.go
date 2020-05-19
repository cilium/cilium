// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumClusterwideNetworkPolicy is a Kubernetes third-party resource with an modified version
// of CiliumNetworkPolicy which is cluster scoped rather than namespace scoped.
// +deepequal-gen=false
type CiliumClusterwideNetworkPolicy struct {
	*CiliumNetworkPolicy

	// Status is the status of the Cilium policy rule
	// +optional
	// The reason this field exists in this structure is due a bug in the k8s code-generator
	// that doesn't create a `UpdateStatus` method because the field does not exist in
	// the structure.
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumClusterwideNetworkPolicyList is a list of CiliumClusterwideNetworkPolicy objects
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumClusterwideNetworkPolicy
	Items []CiliumClusterwideNetworkPolicy `json:"items"`
}
