// Copyright 2016-2017 Authors of Cilium
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

package k8s

import (
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
type CiliumNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	Metadata metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec api.Rule `json:"spec"`
}

// GetObjectKind returns the kind of the object
func (r *CiliumNetworkPolicy) GetObjectKind() schema.ObjectKind {
	return &r.TypeMeta
}

// GetObjectMeta returns the metadata of the object
func (r *CiliumNetworkPolicy) GetObjectMeta() metav1.Object {
	return &r.Metadata
}

// Parse parses a CiliumNetworkPolicy and returns a list of internal policy rules
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if err := r.Spec.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid spec: %s", err)
	}

	if r.Metadata.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := ExtractNamespace(&r.Metadata)

	retRule := &api.Rule{}
	if r.Spec.EndpointSelector.LabelSelector != nil {
		retRule.EndpointSelector = api.NewESFromK8sLabelSelector("", r.Spec.EndpointSelector.LabelSelector)
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		if retRule.EndpointSelector.LabelSelector.MatchLabels == nil {
			retRule.EndpointSelector.LabelSelector.MatchLabels = map[string]string{}
		}
		retRule.EndpointSelector.LabelSelector.MatchLabels[k8s.LabelSourceKeyPrefix+k8s.PodNamespaceLabel] = namespace
	}

	retRule.Ingress = make([]api.IngressRule, len(r.Spec.Ingress))
	for i, ing := range r.Spec.Ingress {
		retRule.Ingress[i].FromEndpoints = make([]api.EndpointSelector, len(ing.FromEndpoints))
		for j, ep := range ing.FromEndpoints {
			retRule.Ingress[i].FromEndpoints[j] = api.NewESFromK8sLabelSelector("", ep.LabelSelector)
			if retRule.Ingress[i].FromEndpoints[j].MatchLabels == nil {
				retRule.Ingress[i].FromEndpoints[j].MatchLabels = map[string]string{}
			}
			retRule.Ingress[i].FromEndpoints[j].MatchLabels[k8s.LabelSourceKeyPrefix+k8s.PodNamespaceLabel] = namespace
		}
		copy(retRule.Ingress[i].ToPorts, ing.ToPorts)
		copy(retRule.Ingress[i].FromCIDR, ing.FromCIDR)

		retRule.Ingress[i].FromRequires = make([]api.EndpointSelector, len(ing.FromRequires))
		for j, ep := range ing.FromRequires {
			retRule.Ingress[i].FromRequires[j] = api.NewESFromK8sLabelSelector("", ep.LabelSelector)
			if retRule.Ingress[i].FromRequires[j].MatchLabels == nil {
				retRule.Ingress[i].FromRequires[j].MatchLabels = map[string]string{}
			}
			retRule.Ingress[i].FromRequires[j].MatchLabels[k8s.LabelSourceKeyPrefix+k8s.PodNamespaceLabel] = namespace
		}
	}

	retRule.Egress = make([]api.EgressRule, len(r.Spec.Egress))
	for i, ing := range r.Spec.Egress {
		copy(retRule.Egress[i].ToPorts, ing.ToPorts)
		copy(retRule.Egress[i].ToCIDR, ing.ToCIDR)
	}

	// Convert resource name to a Cilium policy rule label
	label := fmt.Sprintf("%s=%s", k8s.PolicyLabelName, r.Metadata.Name)

	// TODO: Warn about overwritten labels?
	retRule.Labels = labels.ParseLabelArray(label)

	retRule.Description = r.Spec.Description

	return api.Rules{retRule}, nil
}

type ciliumNetworkPolicyCopy CiliumNetworkPolicy

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	Metadata metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}

// GetObjectKind returns the kind of the object
func (r *CiliumNetworkPolicyList) GetObjectKind() schema.ObjectKind {
	return &r.TypeMeta
}

// GetListMeta returns the metadata of the object
func (r *CiliumNetworkPolicyList) GetListMeta() metav1.List {
	return &r.Metadata
}
