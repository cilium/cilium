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
	"fmt"
	"reflect"

	"github.com/cilium/cilium/pkg/comparator"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:singular="ciliumnetworkpolicy",path="ciliumnetworkpolicies",scope="Namespaced",shortName={cnp,ciliumnp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended
// version of NetworkPolicy.
type CiliumNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs api.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// DeepEqual compares 2 CNPs.
func (in *CiliumNetworkPolicy) DeepEqual(other *CiliumNetworkPolicy) bool {
	return sharedCNPDeepEqual(in, other) && in.deepEqual(other)
}

// sharedCNPDeepEqual performs an equality check for CNP that ignores the
// LastAppliedConfigAnnotation and ignores the Status field of the CNP. This
// function's usage is shared among CNP and CCNP as CCNP embeds a CNP.
func sharedCNPDeepEqual(in, other *CiliumNetworkPolicy) bool {
	switch {
	case (in == nil) != (other == nil):
		return false
	case (in == nil) && (other == nil):
		return true
	}

	if !(in.Name == other.Name && in.Namespace == other.Namespace) {
		return false
	}

	// Ignore v1.LastAppliedConfigAnnotation annotation
	lastAppliedCfgAnnotation1, ok1 := in.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	lastAppliedCfgAnnotation2, ok2 := other.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	defer func() {
		if ok1 && in.GetAnnotations() != nil {
			in.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation1
		}
		if ok2 && other.GetAnnotations() != nil {
			other.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation2
		}
	}()
	delete(in.GetAnnotations(), v1.LastAppliedConfigAnnotation)
	delete(other.GetAnnotations(), v1.LastAppliedConfigAnnotation)

	return comparator.MapStringEquals(in.GetAnnotations(), other.GetAnnotations())
}

// +deepequal-gen=true

// CiliumNetworkPolicyStatus is the status of a Cilium policy rule.
type CiliumNetworkPolicyStatus struct {
	// Nodes is the Cilium policy status for each node
	Nodes map[string]CiliumNetworkPolicyNodeStatus `json:"nodes,omitempty"`

	// DerivativePolicies is the status of all policies derived from the Cilium
	// policy
	DerivativePolicies map[string]CiliumNetworkPolicyNodeStatus `json:"derivativePolicies,omitempty"`
}

// +deepequal-gen=true

// CiliumNetworkPolicyNodeStatus is the status of a Cilium policy rule for a
// specific node.
type CiliumNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been parsed and imported successfully
	// into the in-memory policy repository on the node.
	OK bool `json:"ok,omitempty"`

	// Error describes any error that occurred when parsing or importing the
	// policy, or realizing the policy for the endpoints to which it applies
	// on the node.
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated slimv1.Time `json:"lastUpdated,omitempty"`

	// Revision is the policy revision of the repository which first implemented
	// this policy.
	Revision uint64 `json:"localPolicyRevision,omitempty"`

	// Enforcing is set to true once all endpoints present at the time the
	// policy has been imported are enforcing this policy.
	Enforcing bool `json:"enforcing,omitempty"`

	// Annotations corresponds to the Annotations in the ObjectMeta of the CNP
	// that have been realized on the node for CNP. That is, if a CNP has been
	// imported and has been assigned annotation X=Y by the user,
	// Annotations in CiliumNetworkPolicyNodeStatus will be X=Y once the
	// CNP that was imported corresponding to Annotation X=Y has been realized on
	// the node.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CreateCNPNodeStatus returns a CiliumNetworkPolicyNodeStatus created from the
// provided fields.
func CreateCNPNodeStatus(enforcing, ok bool, cnpError error, rev uint64, annotations map[string]string) CiliumNetworkPolicyNodeStatus {
	cnpns := CiliumNetworkPolicyNodeStatus{
		Enforcing:   enforcing,
		Revision:    rev,
		OK:          ok,
		LastUpdated: slimv1.Now(),
		Annotations: annotations,
	}
	if cnpError != nil {
		cnpns.Error = cnpError.Error()
	}
	return cnpns
}

func (r *CiliumNetworkPolicy) String() string {
	result := ""
	result += fmt.Sprintf("TypeMeta: %s, ", r.TypeMeta.String())
	result += fmt.Sprintf("ObjectMeta: %s, ", r.ObjectMeta.String())
	if r.Spec != nil {
		result += fmt.Sprintf("Spec: %v", *(r.Spec))
	}
	if r.Specs != nil {
		result += fmt.Sprintf("Specs: %v", r.Specs)
	}
	result += fmt.Sprintf("Status: %v", r.Status)
	return result
}

// GetPolicyStatus returns the CiliumNetworkPolicyNodeStatus corresponding to
// nodeName in the provided CiliumNetworkPolicy. If Nodes within the rule's
// Status is nil, returns an empty CiliumNetworkPolicyNodeStatus.
func (r *CiliumNetworkPolicy) GetPolicyStatus(nodeName string) CiliumNetworkPolicyNodeStatus {
	if r.Status.Nodes == nil {
		return CiliumNetworkPolicyNodeStatus{}
	}
	return r.Status.Nodes[nodeName]
}

// SetPolicyStatus sets the given policy status for the given nodes' map.
func (r *CiliumNetworkPolicy) SetPolicyStatus(nodeName string, cnpns CiliumNetworkPolicyNodeStatus) {
	if r.Status.Nodes == nil {
		r.Status.Nodes = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.Nodes[nodeName] = cnpns
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *CiliumNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status CiliumNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

// AnnotationsEquals returns true if ObjectMeta.Annotations of each
// CiliumNetworkPolicy are equivalent (i.e., they contain equivalent key-value
// pairs).
func (r *CiliumNetworkPolicy) AnnotationsEquals(o *CiliumNetworkPolicy) bool {
	if o == nil {
		return r == nil
	}
	return reflect.DeepEqual(r.ObjectMeta.Annotations, o.ObjectMeta.Annotations)
}

// Parse parses a CiliumNetworkPolicy and returns a list of cilium policy
// rules.
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	// Temporary fix for CCNPs. See #12834.
	// TL;DR. CCNPs are converted into SlimCNPs and end up here so we need to
	// convert them back to CCNPs to allow proper parsing.
	if namespace == "" {
		ccnp := CiliumClusterwideNetworkPolicy{
			TypeMeta:            r.TypeMeta,
			ObjectMeta:          r.ObjectMeta,
			CiliumNetworkPolicy: r,
			Status:              r.Status,
		}
		return ccnp.Parse()
	}
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid CiliumNetworkPolicy spec: %s", err)
		}
		if r.Spec.NodeSelector.LabelSelector != nil {
			return nil, fmt.Errorf("Invalid CiliumNetworkPolicy spec: rule cannot have NodeSelector")
		}
		cr := k8sCiliumUtils.ParseToCiliumRule(namespace, name, uid, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid CiliumNetworkPolicy specs: %s", err)

			}
			cr := k8sCiliumUtils.ParseToCiliumRule(namespace, name, uid, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

// GetControllerName returns the unique name for the controller manager.
func (r *CiliumNetworkPolicy) GetControllerName() string {
	name := k8sUtils.GetObjNamespaceName(&r.ObjectMeta)
	return fmt.Sprintf("%s (v2 %s)", k8sConst.CtrlPrefixPolicyStatus, name)
}

// GetIdentityLabels returns all rule labels in the CiliumNetworkPolicy.
func (r *CiliumNetworkPolicy) GetIdentityLabels() labels.LabelArray {
	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	// Even though the struct represents CiliumNetworkPolicy, we use it both for
	// CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy, so here we check for namespace
	// to send correct derivedFrom label to get the correct policy labels.
	derivedFrom := k8sCiliumUtils.ResourceTypeCiliumNetworkPolicy
	if namespace == "" {
		derivedFrom = k8sCiliumUtils.ResourceTypeCiliumClusterwideNetworkPolicy
	}
	return k8sCiliumUtils.GetPolicyLabels(namespace, name, uid, derivedFrom)
}

// RequiresDerivative return true if the CNP has any rule that will create a new
// derivative rule.
func (r *CiliumNetworkPolicy) RequiresDerivative() bool {
	if r.Spec != nil {
		if r.Spec.RequiresDerivative() {
			return true
		}
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if rule.RequiresDerivative() {
				return true
			}
		}
	}
	return false
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects.
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}
