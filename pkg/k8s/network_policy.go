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

	"github.com/cilium/cilium/pkg/annotation"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetPolicyLabelsv1 extracts the name of np. It uses the name  from the Cilium
// annotation if present. If the policy's annotations do not contain
// the Cilium annotation, the policy's name field is used instead.
func GetPolicyLabelsv1(np *networkingv1.NetworkPolicy) labels.LabelArray {

	// TODO: add unit test (GH-3080).
	if np == nil {
		log.Warningf("unable to extract policy labels because provided NetworkPolicy is nil")
		return nil
	}

	policyName := np.Annotations[annotation.Name]

	if policyName == "" {
		policyName = np.Name
	}

	ns := k8sUtils.ExtractNamespace(&np.ObjectMeta)

	return k8sUtils.GetPolicyLabels(ns, policyName)
}

func parseNetworkPolicyPeer(namespace string, peer *networkingv1.NetworkPolicyPeer) *v2.EndpointSelector {

	// TODO add unit test (GH-3080).
	if peer == nil {
		return nil
	}

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

func hasV1PolicyType(pTypes []networkingv1.PolicyType, typ networkingv1.PolicyType) bool {
	for _, pType := range pTypes {
		if pType == typ {
			return true
		}
	}
	return false
}

// ParseNetworkPolicy parses a k8s NetworkPolicy. Returns a list of
// Cilium policy rules that can be added, along with an error if there was an
// error sanitizing the rules.
func ParseNetworkPolicy(np *networkingv1.NetworkPolicy) (v2.Rules, error) {

	if np == nil {
		return nil, fmt.Errorf("cannot parse NetworkPolicy because it is nil")
	}

	ingresses := []v2.IngressRule{}
	egresses := []v2.EgressRule{}

	namespace := k8sUtils.ExtractNamespace(&np.ObjectMeta)

	for _, iRule := range np.Spec.Ingress {
		ingress := v2.IngressRule{}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			ingress.ToPorts = parsePorts(iRule.Ports)
		}

		if iRule.From != nil && len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				endpointSelector := parseNetworkPolicyPeer(namespace, &rule)

				if endpointSelector != nil {
					ingress.FromEndpoints = append(ingress.FromEndpoints, *endpointSelector)
				} else {
					// No label-based selectors were in NetworkPolicyPeer.
					log.WithField(logfields.K8sNetworkPolicyName, np.Name).Debug("NetworkPolicyPeer does not have PodSelector or NamespaceSelector")
				}

				// Parse CIDR-based parts of rule.
				if rule.IPBlock != nil {
					ingress.FromCIDRSet = append(ingress.FromCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}
			}
		} else {
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

		if eRule.Ports != nil && len(eRule.Ports) > 0 {
			egress.ToPorts = parsePorts(eRule.Ports)
		}

		if eRule.To != nil && len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				if rule.NamespaceSelector != nil || rule.PodSelector != nil {
					endpointSelector := parseNetworkPolicyPeer(namespace, &rule)

					if endpointSelector != nil {
						egress.ToEndpoints = append(egress.ToEndpoints, *endpointSelector)
					} else {
						log.WithField(logfields.K8sNetworkPolicyName, np.Name).Debug("NetworkPolicyPeer does not have PodSelector or NamespaceSelector")
					}
				}
				if rule.IPBlock != nil {
					egress.ToCIDRSet = append(egress.ToCIDRSet, ipBlockToCIDRRule(rule.IPBlock))
				}
			}
		} else {
			// []To is wildcard
			all := v2.NewESFromLabels(
				labels.NewLabel(labels.IDNameAll, "", labels.LabelSourceReserved),
			)
			egress.ToEndpoints = append(egress.ToEndpoints, all)
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
		(hasV1PolicyType(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) ||
			!hasV1PolicyType(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress)) {
		ingresses = []v2.IngressRule{{}}
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	//spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Egress
	if len(egresses) == 0 && hasV1PolicyType(np.Spec.PolicyTypes, networkingv1.PolicyTypeEgress) {
		egresses = []v2.EgressRule{{}}
	}

	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace

	rule := &v2.Rule{
		EndpointSelector: v2.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector),
		Labels:           GetPolicyLabelsv1(np),
		Ingress:          ingresses,
		Egress:           egresses,
	}

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return v2.Rules{rule}, nil
}

func ipBlockToCIDRRule(block *networkingv1.IPBlock) v2.CIDRRule {

	// TODO: add unit test (GH-3080).
	cidrRule := v2.CIDRRule{}
	cidrRule.Cidr = v2.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, v2.CIDR(v))
	}
	return cidrRule
}

// parsePorts converts list of K8s NetworkPolicyPorts to Cilium PortRules.
func parsePorts(ports []networkingv1.NetworkPolicyPort) []v2.PortRule {
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
