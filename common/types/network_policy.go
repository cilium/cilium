package types

import (
	"fmt"

	"github.com/noironetworks/cilium-net/common"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
)

type NetworkPolicy struct {
	unversioned.TypeMeta `json:",inline"`
	api.ObjectMeta       `json:"metadata"`

	// Specification of the desired behavior for this NetworkPolicy.
	Spec NetworkPolicySpec
}

type NetworkPolicySpec struct {
	// Selects the pods to which this NetworkPolicy object applies.  The array of ingress rules
	// is applied to any pods selected by this field. Multiple network policies can select the
	// same set of pods.  In this case, the ingress rules for each are combined additively.
	// This field is NOT optional and follows standard unversioned.LabelSelector semantics.
	// An empty podSelector matches all pods in this namespace.
	PodSelector unversioned.LabelSelector `json:"podSelector"`

	// List of ingress rules to be applied to the selected pods.
	// Traffic is allowed to a pod if namespace.networkPolicy.ingress.isolation is undefined and cluster policy allows it,
	// OR if the traffic source is the pod's local node,
	// OR if the traffic matches at least one ingress rule across all of the NetworkPolicy
	// objects whose podSelector matches the pod.
	// If this field is empty then this NetworkPolicy does not affect ingress isolation.
	// If this field is present and contains at least one rule, this policy allows any traffic
	// which matches at least one of the ingress rules in this list.
	Ingress []NetworkPolicyIngressRule `json:"ingress,omitempty"`
}

// This NetworkPolicyIngressRule matches traffic if and only if the traffic matches both ports AND from.
type NetworkPolicyIngressRule struct {
	// List of ports which should be made accessible on the pods selected for this rule.
	// Each item in this list is combined using a logical OR.
	// If this field is not provided, this rule matches all ports (traffic not restricted by port).
	// If this field is empty, this rule matches no ports (no traffic matches).
	// If this field is present and contains at least one item, then this rule allows traffic
	// only if the traffic matches at least one port in the ports list.
	Ports *[]NetworkPolicyPort `json:"ports,omitempty"`

	// List of sources which should be able to access the pods selected for this rule.
	// Items in this list are combined using a logical OR operation.
	// If this field is not provided, this rule matches all sources (traffic not restricted by source).
	// If this field is empty, this rule matches no sources (no traffic matches).
	// If this field is present and contains at least on item, this rule allows traffic only if the
	// traffic matches at least one item in the from list.
	From *[]NetworkPolicyPeer `json:"from,omitempty"`
}

type NetworkPolicyPort struct {
	// Optional.  The protocol (TCP or UDP) which traffic must match.
	// If not specified, this field defaults to TCP.
	Protocol *api.Protocol `json:"protocol,omitempty"`

	// If specified, the port on the given protocol.  This can
	// either be a numerical or named port.  If this field is not provided,
	// this matches all port names and numbers.
	// If present, only traffic on the specified protocol AND port
	// will be matched.
	Port *intstr.IntOrString `json:"port,omitempty"`
}

type NetworkPolicyPeer struct {
	// Exactly one of the following must be specified.

	// This is a label selector which selects Pods in this namespace.
	// This field follows standard unversioned.LabelSelector semantics.
	// If not provided, this selector selects no pods.
	// If present but empty, this selector selects all pods in this namespace.
	PodSelector *unversioned.LabelSelector `json:"podSelector,omitempty"`

	// Selects Namespaces using cluster scoped-labels.  This
	// matches all pods in all namespaces selected by this label selector.
	// This field follows standard unversioned.LabelSelector semantics.
	// If omited, this selector selects no namespaces.
	// If present but empty, this selector selects all namespaces.
	NamespaceSelector *unversioned.LabelSelector `json:"namespaceSelector,omitempty"`
}

func K8sNP2CP(np NetworkPolicy) (string, *PolicyNode, error) {
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
			for _, rule := range *iRule.From {
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
	pn.Rules = []interface{}{
		PolicyRuleConsumers{
			Coverage: coverageLbls.ToSlice(),
			Allow:    allowRules,
		},
	}
	return parentNodeName, pn, nil
}
