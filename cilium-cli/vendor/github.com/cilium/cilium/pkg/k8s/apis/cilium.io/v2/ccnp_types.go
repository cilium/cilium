// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumclusterwidenetworkpolicy",path="ciliumclusterwidenetworkpolicies",scope="Cluster",shortName={ccnp}
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumClusterwideNetworkPolicy is a Kubernetes third-party resource with an
// modified version of CiliumNetworkPolicy which is cluster scoped rather than
// namespace scoped.
type CiliumClusterwideNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs api.Rules `json:"specs,omitempty"`

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
	return objectMetaDeepEqual(in.ObjectMeta, other.ObjectMeta) && in.deepEqual(other)
}

// GetPolicyStatus returns the CiliumClusterwideNetworkPolicyNodeStatus corresponding to
// nodeName in the provided CiliumClusterwideNetworkPolicy. If Nodes within the rule's
// Status is nil, returns an empty CiliumClusterwideNetworkPolicyNodeStatus.
func (r *CiliumClusterwideNetworkPolicy) GetPolicyStatus(nodeName string) CiliumNetworkPolicyNodeStatus {
	if r.Status.Nodes == nil {
		return CiliumNetworkPolicyNodeStatus{}
	}
	return r.Status.Nodes[nodeName]
}

// SetPolicyStatus sets the given policy status for the given nodes' map.
func (r *CiliumClusterwideNetworkPolicy) SetPolicyStatus(nodeName string, cnpns CiliumNetworkPolicyNodeStatus) {
	if r.Status.Nodes == nil {
		r.Status.Nodes = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.Nodes[nodeName] = cnpns
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *CiliumClusterwideNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status CiliumNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

// AnnotationsEquals returns true if ObjectMeta.Annotations of each
// CiliumClusterwideNetworkPolicy are equivalent (i.e., they contain equivalent key-value
// pairs).
func (r *CiliumClusterwideNetworkPolicy) AnnotationsEquals(o *CiliumClusterwideNetworkPolicy) bool {
	if o == nil {
		return r == nil
	}
	return reflect.DeepEqual(r.ObjectMeta.Annotations, o.ObjectMeta.Annotations)
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
		return nil, NewErrParse("CiliumClusterwideNetworkPolicy must have name")
	}

	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec == nil && r.Specs == nil {
		return nil, ErrEmptyCCNP
	}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, NewErrParse(fmt.Sprintf("Invalid CiliumClusterwideNetworkPolicy spec: %s", err))
		}
		cr := k8sCiliumUtils.ParseToCiliumRule("", name, uid, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, NewErrParse(fmt.Sprintf("Invalid CiliumClusterwideNetworkPolicy specs: %s", err))

			}
			cr := k8sCiliumUtils.ParseToCiliumRule("", name, uid, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}
