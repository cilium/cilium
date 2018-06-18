// Copyright 2017-2018 Authors of Cilium
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

package utils

import (
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
	// podPrefixLbl is the value the prefix used in the label selector to
	// represent pods on the default namespace.
	podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel

	// podInitLbl is the label used in a label selector to match on
	// initializing pods.
	podInitLbl = labels.LabelSourceReservedKeyPrefix + labels.IDNameInit
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// ExtractNamespace extracts the namespace of ObjectMeta.
func ExtractNamespace(np *metav1.ObjectMeta) string {
	if np.Namespace == "" {
		return v1.NamespaceDefault
	}

	return np.Namespace
}

// GetObjNamespaceName returns the object's namespace and name.
func GetObjNamespaceName(obj *metav1.ObjectMeta) string {
	return ExtractNamespace(obj) + "/" + obj.GetName()
}

// GetPolicyLabels returns a LabelArray for the given namespace and name.
func GetPolicyLabels(ns, name string) labels.LabelArray {
	return []*labels.Label{
		labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PolicyLabelNamespace, ns, labels.LabelSourceK8s),
	}
}

// getEndpointSelector converts the provided labelSelector into an EndpointSelector,
// adding the relevant matches for namespaces based on the provided options.
func getEndpointSelector(namespace string, labelSelector *metav1.LabelSelector, addK8sPrefix, matchesInit bool) api.EndpointSelector {
	es := api.NewESFromK8sLabelSelector("", labelSelector)

	// There's no need to prefixed K8s
	// prefix for reserved labels
	if addK8sPrefix && es.HasKeyPrefix(labels.LabelSourceReservedKeyPrefix) {
		return es
	}

	// The user can explicitly specify the namespace in the
	// FromEndpoints selector. If omitted, we limit the
	// scope to the namespace the policy lives in.
	//
	// Policies applying on initializing pods are a special case.
	// Those pods don't have any labels, so they don't have a namespace label either.
	// Don't add a namespace label to those endpoint selectors, or we wouldn't be
	// able to match on those pods.
	if !matchesInit && !es.HasKey(podPrefixLbl) {
		es.AddMatch(podPrefixLbl, namespace)
	}

	return es
}

func parseToCiliumIngressRule(namespace string, inRule, retRule *api.Rule) {
	matchesInit := retRule.EndpointSelector.HasKey(podInitLbl)

	if inRule.Ingress != nil {
		retRule.Ingress = make([]api.IngressRule, len(inRule.Ingress))
		for i, ing := range inRule.Ingress {
			if ing.FromEndpoints != nil {
				retRule.Ingress[i].FromEndpoints = make([]api.EndpointSelector, len(ing.FromEndpoints))
				for j, ep := range ing.FromEndpoints {
					retRule.Ingress[i].FromEndpoints[j] = getEndpointSelector(namespace, ep.LabelSelector, true, matchesInit)
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
					retRule.Ingress[i].FromRequires[j] = getEndpointSelector(namespace, ep.LabelSelector, false, matchesInit)
				}
			}

			if ing.FromEntities != nil {
				retRule.Ingress[i].FromEntities = make([]api.Entity, len(ing.FromEntities))
				copy(retRule.Ingress[i].FromEntities, ing.FromEntities)
			}
		}
	}
}

func parseToCiliumEgressRule(namespace string, inRule, retRule *api.Rule) {
	matchesInit := retRule.EndpointSelector.HasKey(podInitLbl)

	if inRule.Egress != nil {
		retRule.Egress = make([]api.EgressRule, len(inRule.Egress))

		for i, egr := range inRule.Egress {
			if egr.ToEndpoints != nil {
				retRule.Egress[i].ToEndpoints = make([]api.EndpointSelector, len(egr.ToEndpoints))
				for j, ep := range egr.ToEndpoints {
					retRule.Egress[i].ToEndpoints[j] = getEndpointSelector(namespace, ep.LabelSelector, true, matchesInit)
				}
			}

			if egr.ToPorts != nil {
				retRule.Egress[i].ToPorts = make([]api.PortRule, len(egr.ToPorts))
				copy(retRule.Egress[i].ToPorts, egr.ToPorts)
			}
			if egr.ToCIDR != nil {
				retRule.Egress[i].ToCIDR = make([]api.CIDR, len(egr.ToCIDR))
				copy(retRule.Egress[i].ToCIDR, egr.ToCIDR)
			}

			if egr.ToCIDRSet != nil {
				retRule.Egress[i].ToCIDRSet = make(api.CIDRRuleSlice, len(egr.ToCIDRSet))
				copy(retRule.Egress[i].ToCIDRSet, egr.ToCIDRSet)
			}

			if egr.ToRequires != nil {
				retRule.Egress[i].ToRequires = make([]api.EndpointSelector, len(egr.ToRequires))
				for j, ep := range egr.ToRequires {
					retRule.Egress[i].ToRequires[j] = getEndpointSelector(namespace, ep.LabelSelector, false, matchesInit)
				}
			}

			if egr.ToServices != nil {
				retRule.Egress[i].ToServices = make([]api.Service, len(egr.ToServices))
				copy(retRule.Egress[i].ToServices, egr.ToServices)
			}

			if egr.ToEntities != nil {
				retRule.Egress[i].ToEntities = make([]api.Entity, len(egr.ToEntities))
				copy(retRule.Egress[i].ToEntities, egr.ToEntities)
			}
		}
	}
}

// ParseToCiliumRule returns an api.Rule with all the labels parsed into cilium
// labels.
func ParseToCiliumRule(namespace, name string, r *api.Rule) *api.Rule {
	retRule := &api.Rule{}
	if r.EndpointSelector.LabelSelector != nil {
		retRule.EndpointSelector = api.NewESFromK8sLabelSelector("", r.EndpointSelector.LabelSelector)
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		//
		// Policies applying on initializing pods are a special case.
		// Those pods don't have any labels, so they don't have a namespace label either.
		// Don't add a namespace label to those endpoint selectors, or we wouldn't be
		// able to match on those pods.
		if !retRule.EndpointSelector.HasKey(podInitLbl) {
			userNamespace, ok := retRule.EndpointSelector.GetMatch(podPrefixLbl)
			if ok && (len(userNamespace) > 1 || (len(userNamespace) == 1 && userNamespace[1] != namespace)) {
				log.WithFields(logrus.Fields{
					logfields.K8sNamespace:              namespace,
					logfields.CiliumNetworkPolicyName:   name,
					logfields.K8sNamespace + ".illegal": userNamespace,
				}).Warn("CiliumNetworkPolicy contains illegal namespace match in EndpointSelector." +
					" EndpointSelector always applies in namespace of the policy resource, removing illegal namespace match'.")
			}
			retRule.EndpointSelector.AddMatch(podPrefixLbl, namespace)
		}
	}

	parseToCiliumIngressRule(namespace, r, retRule)
	parseToCiliumEgressRule(namespace, r, retRule)

	policyLbls := GetPolicyLabels(namespace, name)
	if retRule.Labels == nil {
		retRule.Labels = make(labels.LabelArray, 0, len(policyLbls)+len(r.Labels))
	}
	retRule.Labels = append(retRule.Labels, policyLbls...)
	retRule.Labels = append(retRule.Labels, r.Labels...)

	retRule.Description = r.Description

	return retRule
}
