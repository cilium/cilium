// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"log/slog"

	k8sTypes "k8s.io/apimachinery/pkg/types"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func ParseCiliumNetworkPolicy(logger *slog.Logger, clusterName string, policy *ciliumv2.CiliumNetworkPolicy) (types.PolicyEntries, error) {
	err := policy.Validate()
	if err != nil {
		return nil, err
	}

	entries := types.PolicyEntries{}

	cnp := policy.DeepCopy()
	namespace := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)
	name := cnp.ObjectMeta.Name
	uid := cnp.ObjectMeta.UID

	if cnp.Spec != nil {
		entries = append(entries, ParseCiliumRule(logger, clusterName, namespace, name, uid, cnp.Spec)...)
	}
	if cnp.Specs != nil {
		for _, rule := range cnp.Specs {
			entries = append(entries, ParseCiliumRule(logger, clusterName, namespace, name, uid, rule)...)
		}
	}

	return entries, nil
}

func ParseCiliumRule(logger *slog.Logger, clusterName, namespace, name string, uid k8sTypes.UID, r *api.Rule) types.PolicyEntries {
	rulesCount := len(r.Ingress) + len(r.IngressDeny) + len(r.Egress) + len(r.EgressDeny)
	entries := make(types.PolicyEntries, 0, rulesCount)

	var (
		hostPolicy      bool
		subjectSelector api.EndpointSelector
	)

	if r.EndpointSelector.LabelSelector != nil {
		hostPolicy = false
		subjectSelector = api.NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, r.EndpointSelector.LabelSelector)
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map. Additionally, Policy repository relies
		// on this fact to properly choose correct network policies for
		// a given Security Identity.
		//
		// Policies applying to all namespaces are a special case.
		// Such policies can match on any traffic from Pods or Nodes,
		// so it wouldn't make sense to inject a namespace match for
		// those policies.
		if namespace != "" {
			userNamespaces, present := r.EndpointSelector.GetMatch(podPrefixLbl)
			if present && !namespacesAreValid(namespace, userNamespaces) {
				logger.Warn("CiliumNetworkPolicy contains illegal namespace match in EndpointSelector."+
					" EndpointSelector always applies in namespace of the policy resource, removing illegal namespace match'.",
					logfields.K8sNamespace, namespace,
					logfields.CiliumNetworkPolicyName, name,
					logfields.K8sNamespaceIllegal, userNamespaces,
				)
			}
			subjectSelector.AddMatch(podPrefixLbl, namespace)
		}
	} else if r.NodeSelector.LabelSelector != nil {
		hostPolicy = true
		subjectSelector = api.NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, r.NodeSelector.LabelSelector)
	}

	ingressDefaultDeny, egressDefaultDeny := evaluateDefaultDenyForRule(r)

	subjectLabelSelector := types.NewLabelSelector(subjectSelector)
	matchesPodInit := matchesPodInit(subjectSelector)
	ruleLabels := ParseToCiliumLabels(namespace, name, uid, r.Labels)

	newPolicyEntry := func(ingress bool, deny bool) *types.PolicyEntry {
		defaultDeny := egressDefaultDeny
		if ingress {
			defaultDeny = ingressDefaultDeny
		}

		return &types.PolicyEntry{
			Subject:     subjectLabelSelector,
			Node:        hostPolicy,
			Labels:      ruleLabels,
			DefaultDeny: defaultDeny,
			Ingress:     ingress,
			Deny:        deny,
			Log:         r.Log,
		}
	}

	for _, iRule := range r.Ingress {
		entry := newPolicyEntry(true, false)
		iRule.Sanitize()
		ParseCiliumIngressRule(clusterName, namespace, matchesPodInit, iRule, entry)
		entries = append(entries, entry)
	}

	for _, iRule := range r.IngressDeny {
		entry := newPolicyEntry(true, true)
		iRule.Sanitize()
		ParseCiliumIngressDenyRule(clusterName, namespace, matchesPodInit, iRule, entry)
		entries = append(entries, entry)
	}

	for _, eRule := range r.Egress {
		entry := newPolicyEntry(false, false)
		eRule.Sanitize()
		ParseCiliumEgressRule(clusterName, namespace, matchesPodInit, eRule, entry)
		entries = append(entries, entry)
	}

	for _, eRule := range r.EgressDeny {
		entry := newPolicyEntry(false, true)
		eRule.Sanitize()
		ParseCiliumEgressDenyRule(clusterName, namespace, matchesPodInit, eRule, entry)
		entries = append(entries, entry)
	}

	return entries
}

func ParseCiliumIngressCommonRule(clusterName, namespace string, matchesInit bool, rule api.IngressCommonRule, entry *types.PolicyEntry) {
	var (
		fromEndpoints api.EndpointSelectorSlice
		fromNodes     api.EndpointSelectorSlice
	)

	if rule.FromEndpoints != nil {
		fromEndpoints = make(api.EndpointSelectorSlice, len(rule.FromEndpoints))
		for i, ep := range rule.FromEndpoints {
			fromEndpoints[i] = getEndpointSelector(clusterName, namespace, ep.LabelSelector, matchesInit)
		}
	}

	if rule.FromNodes != nil {
		fromNodes = make(api.EndpointSelectorSlice, len(rule.FromNodes))
		for i, node := range rule.FromNodes {
			fromNodes[i] = getNodeSelector(clusterName, node.LabelSelector)
		}
	}

	entry.L3 = mergeEndpointSelectors(fromEndpoints, fromNodes, rule.FromEntities, rule.FromCIDR, rule.FromCIDRSet, nil)
}

func ParseCiliumIngressRule(clusterName, namespace string, matchesInit bool, rule api.IngressRule, entry *types.PolicyEntry) {
	ParseCiliumIngressCommonRule(clusterName, namespace, matchesInit, rule.IngressCommonRule, entry)

	l4 := make(api.PortRules, 0, len(rule.ToPorts)+len(rule.ICMPs))
	l4 = append(l4, rule.ToPorts...)
	l4 = append(l4, icmpRules(rule.ICMPs)...)

	entry.L4 = l4
	entry.Authentication = rule.Authentication
}

func ParseCiliumIngressDenyRule(clusterName, namespace string, matchesInit bool, rule api.IngressDenyRule, entry *types.PolicyEntry) {
	ParseCiliumIngressCommonRule(clusterName, namespace, matchesInit, rule.IngressCommonRule, entry)

	l4 := make(api.PortRules, 0, len(rule.ToPorts)+len(rule.ICMPs))
	l4 = append(l4, portDenyRulesToPortRules(rule.ToPorts)...)
	l4 = append(l4, icmpRules(rule.ICMPs)...)

	entry.L4 = l4
}

func ParseCiliumEgressCommonRule(clusterName, namespace string, matchesInit bool, rule api.EgressCommonRule, entry *types.PolicyEntry) {
	var (
		toEndpoints api.EndpointSelectorSlice
		toNodes     api.EndpointSelectorSlice
	)

	if rule.ToEndpoints != nil {
		toEndpoints = make(api.EndpointSelectorSlice, len(rule.ToEndpoints))
		for i, ep := range rule.ToEndpoints {
			toEndpoints[i] = getEndpointSelector(clusterName, namespace, ep.LabelSelector, matchesInit)
			toEndpoints[i].Generated = ep.Generated
		}
	}

	if rule.ToNodes != nil {
		toNodes = make(api.EndpointSelectorSlice, len(rule.ToNodes))
		for i, node := range rule.ToNodes {
			toNodes[i] = getNodeSelector(clusterName, node.LabelSelector)
		}
	}

	// ToGroups are ToServices are normalized to ToCIDRSet and ToEndpointSelector respectively.
	entry.L3 = mergeEndpointSelectors(toEndpoints, toNodes, rule.ToEntities, rule.ToCIDR, rule.ToCIDRSet, nil)
}

func ParseCiliumEgressRule(clusterName, namespace string, matchesInit bool, rule api.EgressRule, entry *types.PolicyEntry) {
	ParseCiliumEgressCommonRule(clusterName, namespace, matchesInit, rule.EgressCommonRule, entry)

	entry.L3 = append(entry.L3, types.ToSelectors(rule.ToFQDNs...)...)

	l4 := make(api.PortRules, 0, len(rule.ToPorts)+len(rule.ICMPs))
	l4 = append(l4, rule.ToPorts...)
	l4 = append(l4, icmpRules(rule.ICMPs)...)

	entry.L4 = l4
	entry.Authentication = rule.Authentication
}

func ParseCiliumEgressDenyRule(clusterName, namespace string, matchesInit bool, rule api.EgressDenyRule, entry *types.PolicyEntry) {
	ParseCiliumEgressCommonRule(clusterName, namespace, matchesInit, rule.EgressCommonRule, entry)

	l4 := make(api.PortRules, 0, len(rule.ToPorts)+len(rule.ICMPs))
	l4 = append(l4, portDenyRulesToPortRules(rule.ToPorts)...)
	l4 = append(l4, icmpRules(rule.ICMPs)...)

	entry.L4 = l4
}
