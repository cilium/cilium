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

// FIXME Remove this file in k8s 1.8

import (
	"fmt"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// ExtractPolicyNameDeprecated extracts the name of policy name
func ExtractPolicyNameDeprecated(np *v1beta1.NetworkPolicy) string {
	policyName := np.Annotations[AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	return fmt.Sprintf("%s=%s", PolicyLabelName, policyName)
}

// ParseNetworkPolicyDeprecated parses a k8s NetworkPolicy and returns a list of
// Cilium policy rules that can be added
func ParseNetworkPolicyDeprecated(np *v1beta1.NetworkPolicy) (api.Rules, error) {
	ingresses := []api.IngressRule{}
	namespace := ExtractNamespace(&np.ObjectMeta)
	for _, iRule := range np.Spec.Ingress {
		// Based on NetworkPolicyIngressRule docs:
		//   From []NetworkPolicyPeer
		//   If this field is empty or missing, this rule matches all
		//   sources (traffic not restricted by source).
		ingress := api.IngressRule{}
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
			for _, port := range iRule.Ports {
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

				ingress.ToPorts = append(ingress.ToPorts, portRule)
			}
		}

		ingresses = append(ingresses, ingress)
	}

	tag := ExtractPolicyNameDeprecated(np)
	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[PodNamespaceLabel] = namespace

	rule := &api.Rule{
		EndpointSelector: api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector),
		Labels:           labels.ParseLabelArray(tag),
		Ingress:          ingresses,
	}

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}
