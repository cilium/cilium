// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"

	"github.com/cilium/cilium/pkg/annotation"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	resourceTypeNetworkPolicy = "NetworkPolicy"
)

var (
	allowAllNamespacesRequirement = slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
)

// GetPolicyLabelsv1 extracts the name of np. It uses the name  from the Cilium
// annotation if present. If the policy's annotations do not contain
// the Cilium annotation, the policy's name field is used instead.
func GetPolicyLabelsv1(np *slim_networkingv1.NetworkPolicy) labels.LabelArray {
	if np == nil {
		log.Warningf("unable to extract policy labels because provided NetworkPolicy is nil")
		return nil
	}

	policyName, _ := annotation.Get(np, annotation.PolicyName, annotation.PolicyNameAlias)
	policyUID := np.UID

	if policyName == "" {
		policyName = np.Name
	}

	// Here we are using ExtractNamespaceOrDefault instead of ExtractNamespace because we know
	// for sure that the Object is namespace scoped, so if no namespace is provided instead
	// of assuming that the Object is cluster scoped we return the default namespace.
	ns := k8sUtils.ExtractNamespaceOrDefault(&np.ObjectMeta)

	return k8sCiliumUtils.GetPolicyLabels(ns, policyName, policyUID, resourceTypeNetworkPolicy)
}

func parseNetworkPolicyPeer(namespace string, peer *slim_networkingv1.NetworkPolicyPeer) *api.EndpointSelector {
	if peer == nil {
		return nil
	}

	var retSel *api.EndpointSelector

	if peer.NamespaceSelector != nil {
		labelSelector := peer.NamespaceSelector
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

		// Empty namespace selector selects all namespaces (i.e., a namespace
		// label exists).
		if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
			peer.NamespaceSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
		}

		selector := api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSelector, peer.PodSelector)
		retSel = &selector
	} else if peer.PodSelector != nil {
		labelSelector := peer.PodSelector
		if peer.PodSelector.MatchLabels == nil {
			peer.PodSelector.MatchLabels = map[string]string{}
		}
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		peer.PodSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace

		selector := api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, labelSelector)
		retSel = &selector
	}

	return retSel
}

func hasV1PolicyType(pTypes []slim_networkingv1.PolicyType, typ slim_networkingv1.PolicyType) bool {
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
func ParseNetworkPolicy(np *slim_networkingv1.NetworkPolicy) (api.Rules, error) {

	if np == nil {
		return nil, fmt.Errorf("cannot parse NetworkPolicy because it is nil")
	}

	ingresses := []api.IngressRule{}
	egresses := []api.EgressRule{}

	// Since we know that the object NetworkPolicy is namespace scoped we assign
	// namespace to default namespace if the field is empty in the object.
	namespace := k8sUtils.ExtractNamespaceOrDefault(&np.ObjectMeta)

	for _, iRule := range np.Spec.Ingress {
		fromRules := []api.IngressRule{}
		if iRule.From != nil && len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				ingress := api.IngressRule{}
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

				fromRules = append(fromRules, ingress)
			}
		} else {
			// Based on NetworkPolicyIngressRule docs:
			//   From []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			ingress := api.IngressRule{}
			ingress.FromEndpoints = append(ingress.FromEndpoints, api.WildcardEndpointSelector)

			fromRules = append(fromRules, ingress)
		}

		// We apply the ports to all rules generated from the From section
		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			toPorts := parsePorts(iRule.Ports)
			for i := range fromRules {
				fromRules[i].ToPorts = toPorts
			}
		}

		ingresses = append(ingresses, fromRules...)
	}

	for _, eRule := range np.Spec.Egress {
		toRules := []api.EgressRule{}

		if eRule.To != nil && len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				egress := api.EgressRule{}
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

				toRules = append(toRules, egress)
			}
		} else {
			// Based on NetworkPolicyEgressRule docs:
			//   To []NetworkPolicyPeer
			//   If this field is empty or missing, this rule matches all
			//   destinations (traffic not restricted by destination)
			egress := api.EgressRule{}
			egress.ToEndpoints = append(egress.ToEndpoints, api.WildcardEndpointSelector)

			toRules = append(toRules, egress)
		}

		// We apply the ports to all rules generated from the To section
		if eRule.Ports != nil && len(eRule.Ports) > 0 {
			toPorts := parsePorts(eRule.Ports)
			for i := range toRules {
				toRules[i].ToPorts = toPorts
			}
		}

		egresses = append(egresses, toRules...)
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	//spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Ingress
	// Since k8s 1.7 doesn't contain any PolicyTypes, we default deny
	// if podSelector is empty and the policyTypes is not egress
	if len(ingresses) == 0 &&
		(hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeIngress) ||
			!hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeEgress)) {
		ingresses = []api.IngressRule{{}}
	}

	// Convert the k8s default-deny model to the Cilium default-deny model
	//spec:
	//  podSelector: {}
	//  policyTypes:
	//	  - Egress
	if len(egresses) == 0 && hasV1PolicyType(np.Spec.PolicyTypes, slim_networkingv1.PolicyTypeEgress) {
		egresses = []api.EgressRule{{}}
	}

	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[k8sConst.PodNamespaceLabel] = namespace

	// The next patch will pass the UID.
	rule := api.NewRule().
		WithEndpointSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, &np.Spec.PodSelector)).
		WithLabels(GetPolicyLabelsv1(np)).
		WithIngressRules(ingresses).
		WithEgressRules(egresses)

	if err := rule.Sanitize(); err != nil {
		return nil, err
	}

	return api.Rules{rule}, nil
}

func ipBlockToCIDRRule(block *slim_networkingv1.IPBlock) api.CIDRRule {
	cidrRule := api.CIDRRule{}
	cidrRule.Cidr = api.CIDR(block.CIDR)
	for _, v := range block.Except {
		cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, api.CIDR(v))
	}
	return cidrRule
}

// parsePorts converts list of K8s NetworkPolicyPorts to Cilium PortRules.
func parsePorts(ports []slim_networkingv1.NetworkPolicyPort) []api.PortRule {
	portRules := []api.PortRule{}
	for _, port := range ports {
		protocol := api.ProtoTCP
		if port.Protocol != nil {
			protocol, _ = api.ParseL4Proto(string(*port.Protocol))
		}

		portStr := "0"
		if port.Port != nil {
			portStr = port.Port.String()
		}

		portRule := api.PortRule{
			Ports: []api.PortProtocol{
				{Port: portStr, Protocol: protocol},
			},
		}

		portRules = append(portRules, portRule)
	}

	return portRules
}
