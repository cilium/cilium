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

package types

import (
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
)

func K8sNP2CP(np *v1beta1.NetworkPolicy) (string, *policy.Node, error) {
	var parentNodeName, policyName string
	if np.Annotations[common.K8sAnnotationParentName] == "" {
		parentNodeName = common.K8sDefaultParent
	} else {
		parentNodeName = np.Annotations[common.K8sAnnotationParentName]
	}
	if np.Annotations[common.K8sAnnotationName] == "" {
		policyName = np.Name
	} else {
		policyName = np.Annotations[common.K8sAnnotationName]
	}

	allowRules := []policy.AllowRule{}
	for _, iRule := range np.Spec.Ingress {
		if iRule.From != nil {
			for _, rule := range iRule.From {
				if rule.PodSelector != nil {
					for k, v := range rule.PodSelector.MatchLabels {
						l := labels.NewLabel(k, v, "")
						if l.Source == common.CiliumLabelSource {
							l.Source = common.K8sLabelSource
						}
						ar := policy.AllowRule{
							Action: policy.ALWAYS_ACCEPT,
							Label:  *l,
						}
						allowRules = append(allowRules, ar)
					}
				} else if rule.NamespaceSelector != nil {
					for k := range rule.NamespaceSelector.MatchLabels {
						l := labels.NewLabel(common.K8sPodNamespaceLabel, k, common.K8sLabelSource)
						ar := policy.AllowRule{
							Action: policy.ALWAYS_ACCEPT,
							Label:  *l,
						}
						allowRules = append(allowRules, ar)
					}
				}
			}
		}
	}

	coverageLbls := labels.Map2Labels(np.Spec.PodSelector.MatchLabels, common.K8sLabelSource)
	pn := policy.NewNode(policyName, nil)
	pn.Rules = []policy.PolicyRule{
		&policy.RuleConsumers{
			Coverage: coverageLbls.ToSlice(),
			Allow:    allowRules,
		},
	}
	return parentNodeName, pn, nil
}
