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
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
)

// ParseNetworkPolicy parses a k8s NetworkPolicy and returns a Cilium policy
// node that can be merged into the return parent path
func ParseNetworkPolicy(np *v1beta1.NetworkPolicy) (string, *policy.Node, error) {
	// The parent policy node can optionally be specified via an annotation
	parentNodeName := np.Annotations[AnnotationParentPath]
	if parentNodeName == "" {
		parentNodeName = DefaultPolicyParentPath
	}

	policyName := np.Annotations[AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	allowRules := []*policy.AllowRule{}
	for _, iRule := range np.Spec.Ingress {
		if iRule.From != nil {
			for _, rule := range iRule.From {
				if rule.PodSelector != nil {
					lbls := labels.LabelArray{}
					for k, v := range rule.PodSelector.MatchLabels {
						l := labels.NewLabel(k, v, "")
						if l.Source == common.CiliumLabelSource {
							l.Source = common.K8sLabelSource
						}
						lbls = append(lbls, l)
					}
					ar := &policy.AllowRule{
						Action: api.ALWAYS_ACCEPT,
						Labels: lbls,
					}
					allowRules = append(allowRules, ar)
				} else if rule.NamespaceSelector != nil {
					lbls := labels.LabelArray{}
					for k := range rule.NamespaceSelector.MatchLabels {
						l := labels.NewLabel(common.K8sPodNamespaceLabel, k, common.K8sLabelSource)
						lbls = append(lbls, l)
					}
					ar := &policy.AllowRule{
						Action: api.ALWAYS_ACCEPT,
						Labels: lbls,
					}
					allowRules = append(allowRules, ar)
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
