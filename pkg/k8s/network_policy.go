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

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExtractPolicyName extracts the name of policy name
func ExtractPolicyName(np *networkingv1.NetworkPolicy) string {
	policyName := np.Annotations[AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	return fmt.Sprintf("%s=%s", PolicyLabelName, policyName)
}

// ExtractNamespace extracts the namespace of ObjectMeta.
func ExtractNamespace(np *metav1.ObjectMeta) string {
	if np.Namespace == "" {
		return v1.NamespaceDefault
	}

	return np.Namespace
}

// ParseNetworkPolicy parses a k8s NetworkPolicy and returns a list of
// Cilium policy rules that can be added
func ParseNetworkPolicy(np *networkingv1.NetworkPolicy) (api.Rules, error) {
	ingress := api.IngressRule{}
	egress := api.EgressRule{}
	namespace := ExtractNamespace(&np.ObjectMeta)
	for _, iRule := range np.Spec.Ingress {
		// Based on NetworkPolicyIngressRule docs:
		//   From []NetworkPolicyPeer
		//   If this field is empty or missing, this rule matches all
		//   sources (traffic not restricted by source).
		if iRule.From == nil || len(iRule.From) == 0 {
			all := api.NewESFromLabels(
				labels.NewLabel(labels.IDNameAll, "", labels.LabelSourceReserved),
			)
			ingress.FromEndpoints = append(ingress.FromEndpoints, all)
		} else {
			for _, rule := range iRule.From {
				// Only one or the other can be set, not both
				if rule.PodSelector != nil {
					if rule.PodSelector.MatchLabels == nil {
						rule.PodSelector.MatchLabels = map[string]string{}
					}
					// The PodSelector should only reflect to the same namespace
					// the policy is being stored, thus we add the namespace to
					// the MatchLabels map.
					rule.PodSelector.MatchLabels[PodNamespaceLabel] = namespace
					ingress.FromEndpoints = append(ingress.FromEndpoints,
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, rule.PodSelector))
				} else if rule.NamespaceSelector != nil {
					matchLabels := map[string]string{}
					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for k, v := range rule.NamespaceSelector.MatchLabels {
						matchLabels[policy.JoinPath(PodNamespaceMetaLabels, k)] = v
					}
					rule.NamespaceSelector.MatchLabels = matchLabels

					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for i, lsr := range rule.NamespaceSelector.MatchExpressions {
						lsr.Key = policy.JoinPath(PodNamespaceMetaLabels, lsr.Key)
						rule.NamespaceSelector.MatchExpressions[i] = lsr
					}
					ingress.FromEndpoints = append(ingress.FromEndpoints,
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, rule.NamespaceSelector))
				}
			}
		}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			ingress.ToPorts = parsePorts(iRule.Ports)
		}
	}

	for _, eRule := range np.Spec.Egress {
		// Based on NetworkPolicyEgressRule docs:
		//   From []NetworkPolicyPeer
		//   If this field is  empty or missing, this rule matches all
		// destinations (traffic not restricted by destination)
		if eRule.To == nil || len(eRule.To) == 0 {
			all := api.NewESFromLabels(
				labels.NewLabel(labels.IDNameAll, "", labels.LabelSourceReserved),
			)
			egress.ToEndpoints = append(ingress.FromEndpoints, all)
			// TODO(ianvernon) - should we use this instead of ToEndpoints? egress.ToCIDR = append(egress.ToCIDR, "0.0.0.0/0")
		} else {
			for _, rule := range eRule.To {
				// Only one or the other can be set, not both
				if rule.PodSelector != nil {
					if rule.PodSelector.MatchLabels == nil {
						rule.PodSelector.MatchLabels = map[string]string{}
					}
					// The PodSelector should only reflect to the same namespace
					// the policy is being stored, thus we add the namespace to
					// the MatchLabels map.
					rule.PodSelector.MatchLabels[PodNamespaceLabel] = namespace
					egress.ToEndpoints = append(egress.ToEndpoints,
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, rule.PodSelector))
				} else if rule.NamespaceSelector != nil {
					matchLabels := map[string]string{}
					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for k, v := range rule.NamespaceSelector.MatchLabels {
						matchLabels[policy.JoinPath(PodNamespaceMetaLabels, k)] = v
					}
					rule.NamespaceSelector.MatchLabels = matchLabels

					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for i, lsr := range rule.NamespaceSelector.MatchExpressions {
						lsr.Key = policy.JoinPath(PodNamespaceMetaLabels, lsr.Key)
						rule.NamespaceSelector.MatchExpressions[i] = lsr
					}
					egress.ToEndpoints = append(egress.ToEndpoints,
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, rule.NamespaceSelector))
				}
			}
		}

		if eRule.Ports != nil && len(eRule.Ports) > 0 {
			egress.ToPorts = parsePorts(eRule.Ports)
		}
	}

	tag := ExtractPolicyName(np)
	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[PodNamespaceLabel] = namespace

	rule := &api.Rule{
		EndpointSelector: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector),
		Labels:           labels.ParseLabelArray(tag),
		Ingress:          []api.IngressRule{ingress},
		Egress:           []api.EgressRule{egress},
	}

	if err := rule.Validate(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}

// Converts list of K8s NetworkPolicyPorts to Cilium PortRules.
// Assumes that provided list of NetworkPolicyPorts is not nil.
func parsePorts(ports []networkingv1.NetworkPolicyPort) []api.PortRule {
	portRules := []api.PortRule{}
	for _, port := range ports {
		if port.Protocol == nil && port.Port == nil {
			continue
		}
		protocol := "tcp"

		if port.Protocol != nil {
			protocol = string(*port.Protocol)

		}

		portStr := ""

		if port.Port != nil {
			portStr = port.Port.String()
		}

		portRule :=
			api.PortRule{
				Ports: []api.PortProtocol{
					{Port: portStr, Protocol: protocol},
				},
			}

		portRules = append(portRules, portRule)
	}

	return portRules
}
