package types

import (
	"fmt"

	"github.com/noironetworks/cilium-net/common"

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
