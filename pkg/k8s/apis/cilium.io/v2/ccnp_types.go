// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumclusterwidenetworkpolicy",path="ciliumclusterwidenetworkpolicies",scope="Cluster",shortName={ccnp}
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Valid')].status",name="Valid",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumClusterwideNetworkPolicy is a Kubernetes third-party resource with an
// modified version of CiliumNetworkPolicy which is cluster scoped rather than
// namespace scoped.
type CiliumClusterwideNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	//
	// +kubebuilder:validation:Optional
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	//
	// +kubebuilder:validation:Optional
	Specs api.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule.
	//
	// The reason this field exists in this structure is due a bug in the k8s
	// code-generator that doesn't create a `UpdateStatus` method because the
	// field does not exist in the structure.
	//
	// +kubebuilder:validation:Optional
	Status CiliumNetworkPolicyStatus `json:"status,omitempty"`
}

// DeepEqual compares 2 CCNPs while ignoring the LastAppliedConfigAnnotation
// and ignoring the Status field of the CCNP.
func (in *CiliumClusterwideNetworkPolicy) DeepEqual(other *CiliumClusterwideNetworkPolicy) bool {
	return objectMetaDeepEqual(in.ObjectMeta, other.ObjectMeta) && in.deepEqual(other)
}

func (ccnp *CiliumClusterwideNetworkPolicy) ToCiliumNetworkPolicySpec() *CiliumNetworkPolicy {
	return &CiliumNetworkPolicy{
		TypeMeta:   ccnp.TypeMeta,
		ObjectMeta: ccnp.ObjectMeta,
		Spec:       ccnp.Spec,
		Specs:      ccnp.Specs,
	}
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *CiliumClusterwideNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status CiliumNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
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

func (r *CiliumClusterwideNetworkPolicy) Validate() error {
	if r.ObjectMeta.Name == "" {
		return NewErrParse("CiliumClusterwideNetworkPolicy must have name")
	}

	if r.Spec == nil && r.Specs == nil {
		return ErrEmptyCCNP
	}

	if r.Spec != nil {
		if err := r.Spec.Validate(); err != nil {
			return NewErrParse(fmt.Sprintf("Invalid CiliumClusterwideNetworkPolicy spec: %s", err))
		}
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Validate(); err != nil {
				return NewErrParse(fmt.Sprintf("Invalid CiliumClusterwideNetworkPolicy specs: %s", err))
			}
		}
	}

	return nil
}
