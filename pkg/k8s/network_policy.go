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
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetPolicyLabelsv1 extracts the name of policy name
func GetPolicyLabelsv1(np *networkingv1.NetworkPolicy) labels.LabelArray {
	policyName := np.Annotations[AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	ns := k8sconst.ExtractNamespace(&np.ObjectMeta)

	return k8sconst.GetPolicyLabels(ns, policyName)
}

func parseNetworkPolicyPeer(namespace string, peer *networkingv1.NetworkPolicyPeer) (*api.EndpointSelector, error) {
	var labelSelector *metav1.LabelSelector

	// Only one or the other can be set, not both
	if peer.PodSelector != nil {
		labelSelector = peer.PodSelector
		if peer.PodSelector.MatchLabels == nil {
			peer.PodSelector.MatchLabels = map[string]string{}
		}
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		peer.PodSelector.MatchLabels[k8sconst.PodNamespaceLabel] = namespace
	} else if peer.NamespaceSelector != nil {
		labelSelector = peer.NamespaceSelector
		matchLabels := map[string]string{}
		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for k, v := range peer.NamespaceSelector.MatchLabels {
			matchLabels[policy.JoinPath(PodNamespaceMetaLabels, k)] = v
		}
		peer.NamespaceSelector.MatchLabels = matchLabels

		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for i, lsr := range peer.NamespaceSelector.MatchExpressions {
			lsr.Key = policy.JoinPath(PodNamespaceMetaLabels, lsr.Key)
			peer.NamespaceSelector.MatchExpressions[i] = lsr
		}
	}

	selector := api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSelector)
	return &selector, nil
}

// ParseNetworkPolicy parses a k8s NetworkPolicy and returns a list of
// Cilium policy rules that can be added
func ParseNetworkPolicy(np *networkingv1.NetworkPolicy) (api.Rules, error) {
	ingresses := []api.IngressRule{}
	egresses := []api.EgressRule{}

	namespace := k8sconst.ExtractNamespace(&np.ObjectMeta)
	for _, iRule := range np.Spec.Ingress {
		ingress := api.IngressRule{}
		if iRule.From != nil && len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				endpointSelector, err := parseNetworkPolicyPeer(namespace, &rule)
				if err != nil {
					return nil, err
				}
				if rule.IPBlock != nil {
					ingress.FromCIDRSet = append(ingress.FromCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}
				ingress.FromEndpoints = append(ingress.FromEndpoints, *endpointSelector)
			}
		}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			ingress.ToPorts = parsePorts(iRule.Ports)
		} else if iRule.From == nil || len(iRule.From) == 0 {
			// Based on NetworkPolicyIngressRule docs:
			//   From []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			all := api.NewESFromLabels(
				labels.NewLabel(labels.IDNameAll, "", labels.LabelSourceReserved),
			)
			ingress.FromEndpoints = append(ingress.FromEndpoints, all)
		}

		ingresses = append(ingresses, ingress)
	}

	for _, eRule := range np.Spec.Egress {
		egress := api.EgressRule{}
		if eRule.To != nil && len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				if rule.NamespaceSelector != nil || rule.PodSelector != nil {
					// TODO: GH-2095
					log.Warning("Cilium does not support PodSelector or NamespaceSelector for K8s Egress rules")
				}
				if rule.IPBlock != nil {
					egress.ToCIDRSet = append(egress.ToCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}
			}
		}
		egresses = append(egresses, egress)
	}

	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[k8sconst.PodNamespaceLabel] = namespace

	rule := &api.Rule{
		EndpointSelector: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector),
		Labels:           GetPolicyLabelsv1(np),
		Ingress:          ingresses,
		Egress:           egresses,
	}

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}

func ipBlockToCIDRRule(block *networkingv1.IPBlock) api.CIDRRule {
	cidrRule := api.CIDRRule{}
	cidrRule.Cidr = api.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, api.CIDR(v))
	}
	return cidrRule
}

// Converts list of K8s NetworkPolicyPorts to Cilium PortRules.
// Assumes that provided list of NetworkPolicyPorts is not nil.
func parsePorts(ports []networkingv1.NetworkPolicyPort) []api.PortRule {
	portRules := []api.PortRule{}
	for _, port := range ports {
		if port.Protocol == nil && port.Port == nil {
			continue
		}

		protocol := api.ProtoTCP
		if port.Protocol != nil {
			protocol, _ = api.ParseL4Proto(string(*port.Protocol))
		}

		portStr := ""
		if port.Port != nil {
			portStr = port.Port.String()
		}

		portRule := api.PortRule{
			Ports: []api.PortProtocol{
				{Port: portStr, Protocol: protocol},
			},
		}

		portRules = append(portRules, portRule)
	}

	return portRules
}
