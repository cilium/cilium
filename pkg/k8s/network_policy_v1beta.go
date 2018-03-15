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
	"github.com/cilium/cilium/pkg/annotation"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetPolicyLabelsv1beta1 returns the label selector for the given network
// policy.
func GetPolicyLabelsv1beta1(np *v1beta1.NetworkPolicy) labels.LabelArray {
	policyName := np.Annotations[annotation.Name]
	if policyName == "" {
		policyName = np.Name
	}

	ns := k8sUtils.ExtractNamespace(&np.ObjectMeta)

	return k8sUtils.GetPolicyLabels(ns, policyName)
}

func parsev1beta1NetworkPolicyPeer(namespace string, peer *v1beta1.NetworkPolicyPeer) *v2.EndpointSelector {
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
		peer.PodSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace
	} else if peer.NamespaceSelector != nil {
		labelSelector = peer.NamespaceSelector
		matchLabels := map[string]string{}
		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for k, v := range peer.NamespaceSelector.MatchLabels {
			matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
		}
		peer.NamespaceSelector.MatchLabels = matchLabels

		// We use our own special label prefix for namespace metadata,
		// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
		for i, lsr := range peer.NamespaceSelector.MatchExpressions {
			lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
			peer.NamespaceSelector.MatchExpressions[i] = lsr
		}
	} else {
		// Neither PodSelector nor NamespaceSelector set.
		return nil
	}

	selector := v2.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSelector)
	return &selector
}

func hasV1beta1PolicyType(pTypes []v1beta1.PolicyType, typ v1beta1.PolicyType) bool {
	for _, pType := range pTypes {
		if pType == typ {
			return true
		}
	}
	return false
}

// ParseNetworkPolicyV1beta1 parses a k8s NetworkPolicyv1beta1. Returns a list of
// Cilium policy rules that can be added, along with an error if there was an
// error sanitizing the rules.
func ParseNetworkPolicyV1beta1(np *v1beta1.NetworkPolicy) (v2.Rules, error) {
	ingresses := []v2.IngressRule{}
	egresses := []v2.EgressRule{}

	namespace := k8sUtils.ExtractNamespace(&np.ObjectMeta)
	for _, iRule := range np.Spec.Ingress {
		ingress := v2.IngressRule{}
		if iRule.From != nil && len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				endpointSelector := parsev1beta1NetworkPolicyPeer(namespace, &rule)

				if endpointSelector != nil {
					ingress.FromEndpoints = append(ingress.FromEndpoints, *endpointSelector)
				} else {
					// No label-based selectors were in NetworkPolicyPeer.
					log.WithField(logfields.K8sNetworkPolicyName, np.Name).Debug("NetworkPolicyPeer does not have PodSelector or NamespaceSelector")
				}

				// Parse CIDR-based parts of rule.
				if rule.IPBlock != nil {
					ingress.FromCIDRSet = append(ingress.FromCIDRSet, v1beta1IPBlockToCIDRRule(rule.IPBlock))
				}
			}
		}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			ingress.ToPorts = parseV1Beta1Ports(iRule.Ports)
		} else if iRule.From == nil || len(iRule.From) == 0 {
			// Based on NetworkPolicyIngressRule docs:
			//   From []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			all := v2.NewESFromLabels(
				labels.NewLabel(labels.IDNameAll, "", labels.LabelSourceReserved),
			)
			ingress.FromEndpoints = append(ingress.FromEndpoints, all)
		}

		ingresses = append(ingresses, ingress)
	}

	for _, eRule := range np.Spec.Egress {
		egress := v2.EgressRule{}
		if eRule.To != nil && len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				if rule.NamespaceSelector != nil || rule.PodSelector != nil {
					// TODO: GH-2095
					log.Warning("Cilium does not support PodSelector or NamespaceSelector for K8s Egress rules")
				}
				if rule.IPBlock != nil {
					egress.ToCIDRSet = append(egress.ToCIDRSet, v1beta1IPBlockToCIDRRule(rule.IPBlock))
				}
			}
		}
		egresses = append(egresses, egress)
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	//spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Ingress
	// Since k8s 1.7 doesn't contain any PolicyTypes, we default deny
	// if podSelector is empty and the policyTypes is not egress
	if len(ingresses) == 0 &&
		(hasV1beta1PolicyType(np.Spec.PolicyTypes, v1beta1.PolicyTypeIngress) ||
			!hasV1beta1PolicyType(np.Spec.PolicyTypes, v1beta1.PolicyTypeEgress)) {
		ingresses = []v2.IngressRule{{}}
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	//spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Egress
	if len(egresses) == 0 && hasV1beta1PolicyType(np.Spec.PolicyTypes, v1beta1.PolicyTypeEgress) {
		egresses = []v2.EgressRule{{}}
	}

	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace

	rule := &v2.Rule{
		EndpointSelector: v2.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector),
		Labels:           GetPolicyLabelsv1beta1(np),
		Ingress:          ingresses,
		Egress:           egresses,
	}

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return v2.Rules{rule}, nil
}

func v1beta1IPBlockToCIDRRule(block *v1beta1.IPBlock) v2.CIDRRule {
	cidrRule := v2.CIDRRule{}
	cidrRule.Cidr = v2.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, v2.CIDR(v))
	}
	return cidrRule
}

// Converts list of K8s NetworkPolicyPorts to Cilium PortRules.
// Assumes that provided list of NetworkPolicyPorts is not nil.
func parseV1Beta1Ports(ports []v1beta1.NetworkPolicyPort) []v2.PortRule {
	portRules := []v2.PortRule{}
	for _, port := range ports {
		if port.Protocol == nil && port.Port == nil {
			continue
		}

		protocol := v2.ProtoTCP
		if port.Protocol != nil {
			protocol, _ = v2.ParseL4Proto(string(*port.Protocol))
		}

		portStr := ""
		if port.Port != nil {
			portStr = port.Port.String()
		}

		portRule := v2.PortRule{
			Ports: []v2.PortProtocol{
				{Port: portStr, Protocol: protocol},
			},
		}

		portRules = append(portRules, portRule)
	}

	return portRules
}
