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
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
	// podPrefixLbl is the value the prefix used in the label selector to
	// represent pods on the default namespace.
	podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel

	// podAnyPrefixLbl is the value of the prefix used in the label selector to
	// represent pods in the default namespace for any source type.
	podAnyPrefixLbl = labels.LabelSourceAnyKeyPrefix + k8sConst.PodNamespaceLabel

	// podInitLbl is the label used in a label selector to match on
	// initializing pods.
	podInitLbl = labels.LabelSourceReservedKeyPrefix + labels.IDNameInit

	// ResourceTypeCiliumNetworkPolicy is the resource type used for the
	// PolicyLabelDerivedFrom label
	ResourceTypeCiliumNetworkPolicy = "CiliumNetworkPolicy"

	// ResourceTypeCiliumClusterwideNetworkPolicy is the resource type used for the
	// PolicyLabelDerivedFrom label
	ResourceTypeCiliumClusterwideNetworkPolicy = "CiliumClusterwideNetworkPolicy"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// GetPolicyLabels returns a LabelArray for the given namespace and name.
func GetPolicyLabels(ns, name string, uid types.UID, derivedFrom string) labels.LabelArray {
	// Keep labels sorted by the key.
	labelsArr := labels.LabelArray{
		labels.NewLabel(k8sConst.PolicyLabelDerivedFrom, derivedFrom, labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceK8s),
	}

	// For clusterwide policy namespace will be empty.
	if ns != "" {
		nsLabel := labels.NewLabel(k8sConst.PolicyLabelNamespace, ns, labels.LabelSourceK8s)
		labelsArr = append(labelsArr, nsLabel)
	}

	srcLabel := labels.NewLabel(k8sConst.PolicyLabelUID, string(uid), labels.LabelSourceK8s)
	return append(labelsArr, srcLabel)
}

// getEndpointSelector converts the provided labelSelector into an EndpointSelector,
// adding the relevant matches for namespaces based on the provided options.
// If no namespace is provided then it is assumed that the selector is global to the cluster
// this is when translating selectors for CiliumClusterwideNetworkPolicy.
func getEndpointSelector(namespace string, labelSelector *slim_metav1.LabelSelector, addK8sPrefix, matchesInit bool) api.EndpointSelector {
	es := api.NewESFromK8sLabelSelector("", labelSelector)

	// The k8s prefix must not be added to reserved labels.
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
	if !matchesInit && !es.HasKey(podPrefixLbl) && !es.HasKey(podAnyPrefixLbl) {
		if namespace == "" {
			// For a clusterwide policy if a namespace is not specified in the labels we add
			// a selector to only match endpoints that contains a namespace label.
			// This is to make sure that we are only allowing traffic for cilium managed k8s endpoints
			// and even if a wildcard is provided in the selector we don't proceed with a truly
			// empty(allow all) endpoint selector for the policy.
			es.AddMatchExpression(podPrefixLbl, slim_metav1.LabelSelectorOpExists, []string{})
		} else {
			es.AddMatch(podPrefixLbl, namespace)
		}
	}

	return es
}

func parseToCiliumIngressRule(namespace string, inRule, retRule *api.Rule) {
	matchesInit := matchesPodInit(retRule.EndpointSelector)

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

			retRule.Ingress[i].SetAggregatedSelectors()
		}
	}
}

func parseToCiliumEgressRule(namespace string, inRule, retRule *api.Rule) {
	matchesInit := matchesPodInit(retRule.EndpointSelector)

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

			if egr.ToFQDNs != nil {
				retRule.Egress[i].ToFQDNs = make([]api.FQDNSelector, len(egr.ToFQDNs))
				copy(retRule.Egress[i].ToFQDNs, egr.ToFQDNs)
			}

			if egr.ToGroups != nil {
				retRule.Egress[i].ToGroups = make([]api.ToGroups, len(egr.ToGroups))
				copy(retRule.Egress[i].ToGroups, egr.ToGroups)
			}

			retRule.Egress[i].SetAggregatedSelectors()
		}
	}
}

func matchesPodInit(epSelector api.EndpointSelector) bool {
	if epSelector.LabelSelector == nil {
		return false
	}
	return epSelector.HasKey(podInitLbl)
}

// namespacesAreValid checks the set of namespaces from a rule returns true if
// they are not specified, or if they are specified and match the namespace
// where the rule is being inserted.
func namespacesAreValid(namespace string, userNamespaces []string) bool {
	return len(userNamespaces) == 0 ||
		(len(userNamespaces) == 1 && userNamespaces[0] == namespace)
}

// ParseToCiliumRule returns an api.Rule with all the labels parsed into cilium
// labels. If the namespace provided is empty then the rule is cluster scoped, this
// might happen in case of CiliumClusterwideNetworkPolicy which enforces a policy on the cluster
// instead of the particular namespace.
func ParseToCiliumRule(namespace, name string, uid types.UID, r *api.Rule) *api.Rule {
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
		if !retRule.EndpointSelector.HasKey(podInitLbl) && namespace != "" {
			userNamespace, present := r.EndpointSelector.GetMatch(podPrefixLbl)
			if present && !namespacesAreValid(namespace, userNamespace) {
				log.WithFields(logrus.Fields{
					logfields.K8sNamespace:              namespace,
					logfields.CiliumNetworkPolicyName:   name,
					logfields.K8sNamespace + ".illegal": userNamespace,
				}).Warn("CiliumNetworkPolicy contains illegal namespace match in EndpointSelector." +
					" EndpointSelector always applies in namespace of the policy resource, removing illegal namespace match'.")
			}
			retRule.EndpointSelector.AddMatch(podPrefixLbl, namespace)
		}
	} else if r.NodeSelector.LabelSelector != nil {
		retRule.NodeSelector = api.NewESFromK8sLabelSelector("", r.NodeSelector.LabelSelector)
	}

	parseToCiliumIngressRule(namespace, r, retRule)
	parseToCiliumEgressRule(namespace, r, retRule)

	retRule.Labels = ParseToCiliumLabels(namespace, name, uid, r.Labels)

	retRule.Description = r.Description

	return retRule
}

// ParseToCiliumLabels returns all ruleLbls appended with a specific label that
// represents the given namespace and name along with a label that specifies
// these labels were derived from a CiliumNetworkPolicy.
func ParseToCiliumLabels(namespace, name string, uid types.UID, ruleLbs labels.LabelArray) labels.LabelArray {
	resourceType := ResourceTypeCiliumNetworkPolicy
	if namespace == "" {
		resourceType = ResourceTypeCiliumClusterwideNetworkPolicy
	}

	policyLbls := GetPolicyLabels(namespace, name, uid, resourceType)
	return append(policyLbls, ruleLbs...).Sort()
}
