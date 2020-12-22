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
	"errors"
	"fmt"

	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:singular="ciliumclusterwidenetworkpolicy",path="ciliumclusterwidenetworkpolicies",scope="Cluster",shortName={ccnp}
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumClusterwideNetworkPolicy is a Kubernetes third-party resource with an
// modified version of CiliumNetworkPolicy which is cluster scoped rather than
// namespace scoped.
type CiliumClusterwideNetworkPolicy struct {
	// Note: The following two fields are required (regardless of embedding
	// CiliumNetworkPolicy below which bring these in), because controller-gen
	// ignores structs when generating CRDs that do not have these fields. The
	// controller-gen code responsible:
	// https://github.com/kubernetes-sigs/controller-tools/blob/4a903ddb7005459a7baf4777c67244a74c91083d/pkg/crd/gen.go#L221

	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Embedded fields require json inline tag, source:
	// https://github.com/kubernetes-sigs/controller-tools/issues/244
	*CiliumNetworkPolicy `json:",inline"`

	// Status is the status of the Cilium policy rule.
	//
	// The reason this field exists in this structure is due a bug in the k8s
	// code-generator that doesn't create a `UpdateStatus` method because the
	// field does not exist in the structure.
	//
	// +kubebuilder:validation:Optional
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// DeepEqual compares 2 CCNPs while ignoring the LastAppliedConfigAnnotation
// and ignoring the Status field of the CCNP.
func (in *CiliumClusterwideNetworkPolicy) DeepEqual(other *CiliumClusterwideNetworkPolicy) bool {
	return sharedCNPDeepEqual(in.CiliumNetworkPolicy, other.CiliumNetworkPolicy) && in.deepEqual(other)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumClusterwideNetworkPolicyList is a list of
// CiliumClusterwideNetworkPolicy objects.
type CiliumClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumClusterwideNetworkPolicies.
	Items []CiliumClusterwideNetworkPolicy `json:"items"`
}

// Parse parses a CiliumClusterwideNetworkPolicy and returns a list of cilium
// policy rules.
func (r *CiliumClusterwideNetworkPolicy) Parse() (api.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, fmt.Errorf("CiliumClusterwideNetworkPolicy must have name")
	}

	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec == nil && r.Specs == nil {
		return nil, ErrEmptyCCNP
	}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid CiliumClusterwideNetworkPolicy spec: %s", err)
		}
		cr := k8sCiliumUtils.ParseToCiliumRule("", name, uid, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid CiliumClusterwideNetworkPolicy specs: %s", err)

			}
			cr := k8sCiliumUtils.ParseToCiliumRule("", name, uid, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

// ErrEmptyCCNP is an error representing a CCNP that is empty, which means it is
// missing both a `spec` and `specs` (both are nil).
var ErrEmptyCCNP = errors.New("Invalid CiliumClusterwideNetworkPolicy spec(s): empty policy")
