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
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	log "github.com/sirupsen/logrus"
)

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
type CiliumNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	Metadata metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs api.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// CiliumNetworkPolicyStatus is the status of a Cilium policy rule
type CiliumNetworkPolicyStatus struct {
	// Nodes is the Cilium policy status for each node
	Nodes map[string]CiliumNetworkPolicyNodeStatus `json:"nodes,omitempty"`
}

// CiliumNetworkPolicyNodeStatus is the status of a Cilium policy rule for a
// specific node
type CiliumNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been installed successfully
	OK bool `json:"ok,omitempty"`

	// Error describes the error condition if OK is false
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated time.Time `json:"lastUpdated,omitempty"`
}

// SetPolicyStatus sets the given policy status for the given nodes' map
func (r *CiliumNetworkPolicy) SetPolicyStatus(nodeName string, cnpns CiliumNetworkPolicyNodeStatus) {
	if r.Status.Nodes == nil {
		r.Status.Nodes = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.Nodes[nodeName] = cnpns
}

// SpecEquals returns true if the spec and specs metadata is the sa
func (r *CiliumNetworkPolicy) SpecEquals(o *CiliumNetworkPolicy) bool {
	if o == nil {
		return r == nil
	}
	return reflect.DeepEqual(r.Spec, o.Spec) &&
		reflect.DeepEqual(r.Specs, o.Specs)
}

// GetObjectKind returns the kind of the object
func (r *CiliumNetworkPolicy) GetObjectKind() schema.ObjectKind {
	return &r.TypeMeta
}

// GetObjectMeta returns the metadata of the object
func (r *CiliumNetworkPolicy) GetObjectMeta() metav1.Object {
	return &r.Metadata
}

// parseToCilium returns an api.Rule with all the labels parsed into cilium
// labels.
func parseToCilium(namespace, name string, r *api.Rule) *api.Rule {
	retRule := &api.Rule{}
	if r.EndpointSelector.LabelSelector != nil {
		retRule.EndpointSelector = api.NewESFromK8sLabelSelector("", r.EndpointSelector.LabelSelector)
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		if retRule.EndpointSelector.LabelSelector.MatchLabels == nil {
			retRule.EndpointSelector.LabelSelector.MatchLabels = map[string]string{}
		}

		userNamespace, ok := retRule.EndpointSelector.LabelSelector.MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel]
		if ok && userNamespace != namespace {
			log.Warningf("k8s: CiliumNetworkPolicy %s/%s contains illegal namespace match '%s' in EndpointSelector."+
				" EndpointSelector always applies in namespace of the policy resource, removing namespace match '%s'.",
				namespace, name, userNamespace, userNamespace)
		}
		retRule.EndpointSelector.LabelSelector.MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel] = namespace
	}

	if r.Ingress != nil {
		retRule.Ingress = make([]api.IngressRule, len(r.Ingress))
		for i, ing := range r.Ingress {
			if ing.FromEndpoints != nil {
				retRule.Ingress[i].FromEndpoints = make([]api.EndpointSelector, len(ing.FromEndpoints))
				for j, ep := range ing.FromEndpoints {
					retRule.Ingress[i].FromEndpoints[j] = api.NewESFromK8sLabelSelector("", ep.LabelSelector)
					if retRule.Ingress[i].FromEndpoints[j].MatchLabels == nil {
						retRule.Ingress[i].FromEndpoints[j].MatchLabels = map[string]string{}
					}
					// There's no need to prefixed K8s
					// prefix for reserved labels
					if retRule.Ingress[i].FromEndpoints[j].HasKeyPrefix(labels.LabelSourceReservedKeyPrefix) {
						continue
					}
					// The user can explicitly specify the namespace in the
					// FromEndpoints selector. If omitted, we limit the
					// scope to the namespace the policy lives in.
					if _, ok := retRule.Ingress[i].FromEndpoints[j].MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel]; !ok {
						retRule.Ingress[i].FromEndpoints[j].MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel] = namespace
					}
				}
			}

			if ing.ToPorts != nil {
				retRule.Ingress[i].ToPorts = make([]api.PortRule, len(ing.ToPorts))
				copy(retRule.Ingress[i].ToPorts, ing.ToPorts)
			}
			if ing.FromCIDR != nil {
				retRule.Ingress[i].FromCIDR = make([]api.CIDR, len(ing.FromCIDR))
				copy(retRule.Ingress[i].FromCIDR, ing.FromCIDR)
			}

			if ing.FromCIDRSet != nil {
				retRule.Ingress[i].FromCIDRSet = make([]api.CIDRRule, len(ing.FromCIDRSet))
				copy(retRule.Ingress[i].FromCIDRSet, ing.FromCIDRSet)
			}

			if ing.FromRequires != nil {
				retRule.Ingress[i].FromRequires = make([]api.EndpointSelector, len(ing.FromRequires))
				for j, ep := range ing.FromRequires {
					retRule.Ingress[i].FromRequires[j] = api.NewESFromK8sLabelSelector("", ep.LabelSelector)
					if retRule.Ingress[i].FromRequires[j].MatchLabels == nil {
						retRule.Ingress[i].FromRequires[j].MatchLabels = map[string]string{}
					}
					// The user can explicitly specify the namespace in the
					// FromEndpoints selector. If omitted, we limit the
					// scope to the namespace the policy lives in.
					if _, ok := retRule.Ingress[i].FromRequires[j].MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel]; !ok {
						retRule.Ingress[i].FromRequires[j].MatchLabels[labels.LabelSourceK8sKeyPrefix+PodNamespaceLabel] = namespace
					}
				}
			}
		}
	}

	if r.Egress != nil {
		retRule.Egress = make([]api.EgressRule, len(r.Egress))
		copy(retRule.Egress, r.Egress)
	}

	// Convert resource name to a Cilium policy rule label
	label := fmt.Sprintf("%s=%s", PolicyLabelName, name)

	// TODO: Warn about overwritten labels?
	retRule.Labels = labels.ParseLabelArray(label)

	retRule.Description = r.Description

	return retRule
}

// Parse parses a CiliumNetworkPolicy and returns a list of cilium policy
// rules.
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if r.Metadata.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := ExtractNamespace(&r.Metadata)
	name := r.Metadata.Name

	retRules := api.Rules{}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid spec: %s", err)

		}
		cr := parseToCilium(namespace, name, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid specs: %s", err)

			}
			cr := parseToCilium(namespace, name, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

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
