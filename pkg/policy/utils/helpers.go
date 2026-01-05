// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// addClusterFilterByDefault attempt to add a cluster filter if the cluster name
// is defined and that the EndpointSelector doesn't already have a cluster selector
func addClusterFilterByDefault(es *api.EndpointSelector, clusterName string) {
	if clusterName != cmtypes.PolicyAnyCluster && !es.HasKey(clusterPrefixLbl) && !es.HasKey(clusterAnyPrefixLbl) {
		es.AddMatch(clusterPrefixLbl, clusterName)
	}
}

// getEndpointSelector converts the provided labelSelector into an EndpointSelector,
// adding the relevant matches for namespaces and clusters based on the provided options.
// If no namespace is provided then it is assumed that the selector is global to the cluster
// this is when translating selectors for CiliumClusterwideNetworkPolicy.
// If a clusterName is provided then is is assumed that the selector is scoped to the local
// cluster by default in a ClusterMesh environment.
func getEndpointSelector(clusterName, namespace string, labelSelector *slim_metav1.LabelSelector, matchesInit bool) api.EndpointSelector {
	es := api.NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, labelSelector)

	// The k8s prefix must not be added to reserved labels.
	if es.HasKeyPrefix(labels.LabelSourceReservedKeyPrefix) {
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
	if !es.HasKey(podPrefixLbl) && !es.HasKey(podAnyPrefixLbl) {
		if namespace == "" {
			// For a clusterwide policy if a namespace is not specified in the labels we add
			// a selector to only match endpoints that contains a namespace label.
			// This is to make sure that we are only allowing traffic for cilium managed k8s endpoints
			// and even if a wildcard is provided in the selector we don't proceed with a truly
			// empty(allow all) endpoint selector for the policy.
			if !matchesInit {
				es.AddMatchExpression(podPrefixLbl, slim_metav1.LabelSelectorOpExists, []string{})
			}
		} else if !es.HasKeyPrefix(podK8SNamespaceLabelsPrefix) && !es.HasKeyPrefix(podAnyNamespaceLabelsPrefix) {
			es.AddMatch(podPrefixLbl, namespace)
		}
	}

	// Similarly to namespace, the user can explicitly specify the cluster in the
	// FromEndpoints selector. If omitted, we limit the
	// scope to the cluster the policy lives in.
	addClusterFilterByDefault(&es, clusterName)

	return es
}

func getNodeSelector(clusterName string, labelSelector *slim_metav1.LabelSelector) api.EndpointSelector {
	es := api.NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, labelSelector)
	es.AddMatchExpression(labels.LabelSourceReservedKeyPrefix+labels.IDNameRemoteNode, slim_metav1.LabelSelectorOpExists, []string{})

	addClusterFilterByDefault(&es, clusterName)
	return es
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

func evaluateDefaultDenyForRule(rule *api.Rule) (ingress bool, egress bool) {
	if option.Config.EnableNonDefaultDenyPolicies {
		// Fill in the default traffic posture of this Rule.
		// Default posture is per-direction (ingress or egress),
		// if there is a peer selector for that direction, the
		// default is deny, else allow.
		if rule.EnableDefaultDeny.Ingress == nil {
			ingress = len(rule.Ingress) > 0 || len(rule.IngressDeny) > 0
		} else {
			ingress = *rule.EnableDefaultDeny.Ingress
		}
		if rule.EnableDefaultDeny.Egress == nil {
			egress = len(rule.Egress) > 0 || len(rule.EgressDeny) > 0
		} else {
			egress = *rule.EnableDefaultDeny.Egress
		}

		return
	}

	// Since Non Default Deny Policies is disabled by flag, DefaultDeny is enabled
	return true, true
}

func mergeEndpointSelectors(endpoints, nodes api.EndpointSelectorSlice, entities api.EntitySlice, cidrSlice api.CIDRSlice, cidrRuleSlice api.CIDRRuleSlice, fqdns api.FQDNSelectorSlice) types.Selectors {
	// Explicitly check for empty non-nil slices, it should not result in any identity being selected.
	if (endpoints != nil && len(endpoints) == 0) ||
		(nodes != nil && len(nodes) == 0) ||
		(entities != nil && len(entities) == 0) ||
		(cidrSlice != nil && len(cidrSlice) == 0) ||
		(cidrRuleSlice != nil && len(cidrRuleSlice) == 0) {
		return nil
	}
	l3 := make(types.Selectors, 0, len(endpoints)+len(nodes)+len(entities)+len(cidrSlice)+len(cidrRuleSlice)+len(fqdns))
	l3 = append(l3, types.ToSelectors(endpoints...)...)
	l3 = append(l3, types.ToSelectors(nodes...)...)
	l3 = append(l3, types.ToSelectors(entities.GetAsEndpointSelectors()...)...)
	l3 = append(l3, types.ToSelectors(cidrSlice...)...)
	l3 = append(l3, types.ToSelectors(cidrRuleSlice...)...)
	l3 = append(l3, types.ToSelectors(fqdns...)...)
	return l3
}

func portDenyRulesToPortRules(portRules api.PortDenyRules) api.PortRules {
	out := make(api.PortRules, 0, len(portRules))
	for _, pr := range portRules {
		out = append(out, api.PortRule{Ports: pr.GetPortProtocols()})
	}
	return out
}

func icmpRules(icmpRules api.ICMPRules) api.PortRules {
	out := make(api.PortRules, 0, len(icmpRules))
	icmpRules.Iterate(func(p api.Ports) error {
		pr := p.GetPortRule()
		if pr != nil {
			out = append(out, *pr)
		}
		return nil
	})
	return out
}
