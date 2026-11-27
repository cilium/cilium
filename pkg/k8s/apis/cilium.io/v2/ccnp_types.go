// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"iter"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
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
// +kubebuilder:validation:XValidation:rule="has(self.spec) || has(self.specs)",message="spec or specs must be provided"

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

// Validate validates the CiliumClusterwideNetworkPolicy object and returns the first error.
func (r *CiliumClusterwideNetworkPolicy) Validate() error {
	for err := range r.ValidationErrors() {
		return NewErrParse(err.Error())
	}
	return nil
}

// ValidationErrors yields validation errors without modifying the policy.
// Rule errors wrap the underlying validation error.
func (r *CiliumClusterwideNetworkPolicy) ValidationErrors() iter.Seq[error] {
	return func(yield func(error) bool) {
		if r.ObjectMeta.Name == "" {
			yield(NewErrParse("CiliumClusterwideNetworkPolicy must have name"))
			return
		}

		if r.Spec == nil && r.Specs == nil {
			yield(ErrEmptyCCNP)
			return
		}
		policyRuleValidationErrors("CiliumClusterwideNetworkPolicy", r.Spec, r.Specs, false)(yield)
	}
}

// Sanitize sanitizes the CiliumClusterwideNetworkPolicy object modifying object in place
// to make it ready for parsing.
//
// NOTE: This method assumes that the CCNP object is validated beforehand.
func (r *CiliumClusterwideNetworkPolicy) Sanitize() {
	if r.Spec != nil {
		r.Spec.Sanitize()
	}
	if r.Specs != nil {
		for i := range r.Specs {
			r.Specs[i].Sanitize()
		}
	}
}

// ParseRules parses the CiliumClusterwideNetworkPolicy and returns a list of cilium policy
// rules ready for processing by downstream subsystems.
//
// NOTE: This method assumes that the CCNP object is validated beforehand.
func (r *CiliumClusterwideNetworkPolicy) ParseRules(logger *slog.Logger, clusterName string) api.Rules {
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec != nil {
		cr := k8sCiliumUtils.ParseToCiliumRule(logger, clusterName, "", name, uid, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			cr := k8sCiliumUtils.ParseToCiliumRule(logger, clusterName, "", name, uid, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules
}

// Parse parses the CiliumClusterwideNetworkPolicy and returns a list of cilium policy rules.
func (r *CiliumClusterwideNetworkPolicy) Parse(logger *slog.Logger, clusterName string) (api.Rules, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	r.Sanitize()
	return r.ParseRules(logger, clusterName), nil
}
