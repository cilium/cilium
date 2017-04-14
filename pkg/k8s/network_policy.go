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
	"net"

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
	l4Rules := []policy.AllowL4{}
	for _, iRule := range np.Spec.Ingress {
		// Based on NetworkPolicyIngressRule docs:
		//   From []NetworkPolicyPeer
		//   If this field is empty or missing, this rule matches all
		//   sources (traffic not restricted by source).
		if iRule.From == nil || len(iRule.From) == 0 {
			all := labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource)
			ar := &policy.AllowRule{
				Action: api.ALWAYS_ACCEPT,
				Labels: labels.LabelArray{all},
			}
			allowRules = append(allowRules, ar)
		} else {
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

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			l4filters := []policy.L4Filter{}
			for _, port := range iRule.Ports {
				if port.Protocol == nil && port.Port == nil {
					continue
				}

				protocol := "tcp"
				if port.Protocol != nil {
					protocol = string(*port.Protocol)
				}

				portNum := 0
				if port.Port != nil {
					portStr := port.Port.String()
					p, err := net.LookupPort(protocol, portStr)
					if err != nil {
						return "", nil, fmt.Errorf("Unable to parse port %s: %s",
							portStr, err)
					}
					portNum = p
				}

				l4filters = append(l4filters, policy.L4Filter{
					Port:     portNum,
					Protocol: protocol,
				})
			}

			if len(l4filters) > 0 {
				l4Rules = append(l4Rules, policy.AllowL4{
					Ingress: l4filters,
				})
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

	if len(l4Rules) > 0 {
		pn.Rules = append(pn.Rules, &policy.RuleL4{
			Coverage: coverageLbls.ToSlice(),
			Allow:    l4Rules,
		})
	}

	return parentNodeName, pn, nil
}
