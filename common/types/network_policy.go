//
// Copyright 2016 Authors of Cilium
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
//
package types

import (
	"fmt"

	"github.com/cilium/cilium/common"

	"k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
)

func K8sNP2CP(np v1beta1.NetworkPolicy) (string, *PolicyNode, error) {
	parentNodeName := np.Annotations[common.K8sAnnotationParentName]
	if parentNodeName == "" {
		return "", nil, fmt.Errorf("%s not found in network policy annotations", common.K8sAnnotationParentName)
	}
	policyName := np.Annotations[common.K8sAnnotationName]
	if policyName == "" {
		return "", nil, fmt.Errorf("%s not found in network policy annotations", common.K8sAnnotationName)
	}

	allowRules := []AllowRule{}
	for _, iRule := range np.Spec.Ingress {
		if iRule.From != nil {
			for _, rule := range iRule.From {
				if rule.PodSelector != nil {
					for k, v := range rule.PodSelector.MatchLabels {
						l := NewLabel(k, v, "")
						if l.Source == common.CiliumLabelSource {
							l.Source = common.K8sLabelSource
						}
						ar := AllowRule{
							Action: ALWAYS_ACCEPT,
							Label:  *l,
						}
						allowRules = append(allowRules, ar)
					}
				} else if rule.NamespaceSelector != nil {
					for k, _ := range rule.NamespaceSelector.MatchLabels {
						l := NewLabel(common.K8sPodNamespaceLabel, k, common.K8sLabelSource)
						ar := AllowRule{
							Action: ALWAYS_ACCEPT,
							Label:  *l,
						}
						allowRules = append(allowRules, ar)
					}
				}
			}
		}
	}

	coverageLbls := Map2Labels(np.Spec.PodSelector.MatchLabels, common.K8sLabelSource)
	pn := NewPolicyNode(policyName, nil)
	pn.Rules = []PolicyRule{
		&PolicyRuleConsumers{
			Coverage: coverageLbls.ToSlice(),
			Allow:    allowRules,
		},
	}
	return parentNodeName, pn, nil
}
