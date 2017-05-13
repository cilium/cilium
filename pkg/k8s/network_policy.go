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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// ExtractPolicyName extracts the name of policy name
func ExtractPolicyName(np *v1beta1.NetworkPolicy) string {
	policyName := np.Annotations[AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	return fmt.Sprintf("%s=%s", PolicyLabelName, policyName)
}

// ParseNetworkPolicy parses a k8s NetworkPolicy and returns a list of
// Cilium policy rules that can be added
func ParseNetworkPolicy(np *v1beta1.NetworkPolicy) (api.Rules, error) {
	ingress := api.IngressRule{}
	for _, iRule := range np.Spec.Ingress {
		// Based on NetworkPolicyIngressRule docs:
		//   From []NetworkPolicyPeer
		//   If this field is empty or missing, this rule matches all
		//   sources (traffic not restricted by source).
		if iRule.From == nil || len(iRule.From) == 0 {
			all := api.EndpointSelector{
				labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource),
			}
			ingress.FromEndpoints = append(ingress.FromEndpoints, all)
		} else {
			for _, rule := range iRule.From {
				if rule.PodSelector != nil {
					lbls := api.EndpointSelector{}
					for k, v := range rule.PodSelector.MatchLabels {
						l := labels.NewLabel(k, v, "")
						if l.Source == common.CiliumLabelSource {
							l.Source = common.K8sLabelSource
						}
						lbls = append(lbls, l)
					}
					ingress.FromEndpoints = append(ingress.FromEndpoints, lbls)
				} else if rule.NamespaceSelector != nil {
					lbls := api.EndpointSelector{}
					for k := range rule.NamespaceSelector.MatchLabels {
						l := labels.NewLabel(common.K8sPodNamespaceLabel, k, common.K8sLabelSource)
						lbls = append(lbls, l)
					}
					ingress.FromEndpoints = append(ingress.FromEndpoints, lbls)
				}
			}
		}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			for _, port := range iRule.Ports {
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

				portRule := api.PortRule{
					Ports: []api.PortProtocol{
						{Port: portStr, Protocol: protocol},
					},
				}

				ingress.ToPorts = append(ingress.ToPorts, portRule)
			}
		}
	}

	tag := ExtractPolicyName(np)
	coverageLbls := labels.Map2Labels(np.Spec.PodSelector.MatchLabels, common.K8sLabelSource)

	rule := &api.Rule{
		EndpointSelector: coverageLbls.ToSlice(),
		Labels:           labels.ParseLabelArray(tag),
		Ingress:          []api.IngressRule{ingress},
	}

	if err := rule.Validate(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}
