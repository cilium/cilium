// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

const (
	resourceTypeClusterNetworkPolicy = "ClusterNetworkPolicy"
)

func toSlimLabelSelector(ls *metav1.LabelSelector) *slim_metav1.LabelSelector {
	if ls == nil {
		return nil
	}
	result := &slim_metav1.LabelSelector{
		MatchLabels: ls.MatchLabels,
	}
	if len(ls.MatchExpressions) > 0 {
		result.MatchExpressions = make([]slim_metav1.LabelSelectorRequirement, len(ls.MatchExpressions))
		for k, v := range ls.MatchExpressions {
			result.MatchExpressions[k] = slim_metav1.LabelSelectorRequirement{
				Key:      v.Key,
				Operator: slim_metav1.LabelSelectorOperator(string(v.Operator)),
				Values:   v.Values,
			}
		}
	}
	return result
}

func kcnpProcessNamespaceSelector(namespaces *metav1.LabelSelector) *slim_metav1.LabelSelector {
	return processNamespaceSelector(toSlimLabelSelector(namespaces))
}

// kcnpParseNamespacedPod converts a NamespacedPod into an EndpointSelector,
// which selects all the specified pods in the specified namespaces. If a
// cluster name is provided and the pod selector does not already explicitly
// target a cluster, a selector targeting the named cluster will be added.
func kcnpParseNamespacedPod(clusterName string, peer policyv1alpha2.NamespacedPod) api.EndpointSelector {
	podSelector := toSlimLabelSelector(&peer.PodSelector)
	es := api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		kcnpProcessNamespaceSelector(&peer.NamespaceSelector),
		podSelector)

	if clusterName != cmtypes.PolicyAnyCluster && !isPodSelectorSelectingCluster(podSelector) {
		es.AddMatch(k8sConst.PolicyLabelCluster, clusterName)
	}

	return es
}

// kcnpProcessNodeSelector converts a label selector targeting a node into an
// EndpointSelector. If a cluster name is provided and the pod selector does
// not already explicitly target a cluster, a selector targeting the named
// cluster will be added.
func kcnpProcessNodeSelector(clusterName string, nodeSelector *metav1.LabelSelector) api.EndpointSelector {
	ns := toSlimLabelSelector(nodeSelector)
	es := api.NewESFromK8sLabelSelector(labels.LabelSourceNode+".", ns)
	es.AddMatchExpression(labels.LabelSourceReservedKeyPrefix+labels.IDNameRemoteNode, slim_metav1.LabelSelectorOpExists, []string{})

	if clusterName != cmtypes.PolicyAnyCluster && !isPodSelectorSelectingCluster(ns) {
		es.AddMatch(k8sConst.PolicyLabelCluster, clusterName)
	}

	return es
}

func kcnpParseCIDRSelectors(cidrs []policyv1alpha2.CIDR) types.PeerSelectorSlice {
	result := types.PeerSelectorSlice{}
	for _, cidr := range cidrs {
		result = append(result, api.CIDR(string(cidr)))
	}
	return result
}

// kcnpParseFQDNSelectors parses a DomainName struct from a ClusterNetworkPolicy.
// It returns two distinct lists:
// 1. A slice of FQDN selectors for L3 filtering.
// 2. A slice of L4 port rules for L7 filtering of allowed DNS traffic.
//
// This dual-return is necessary for Cilium's FQDN proxy implementation.
// An explicit L4 rule must first allow the DNS request traffic, enabling the
// L7 proxy to intercept and enforce policy based on the domain names.
//
// Returns an error if the domain name or pattern is not formatted correctly.
func kcnpParseFQDNSelectors(fqdns []policyv1alpha2.DomainName) (types.PeerSelectorSlice, api.PortRulesDNS, error) {
	peerSelectors := types.PeerSelectorSlice{}
	dnsRules := api.PortRulesDNS{}
	for _, fqdn := range fqdns {
		var fqdnSelector api.FQDNSelector
		// If the domain name contains an asterisk, we assume it is a
		// pattern instead of a plain domain name.
		//
		// TODO: Cilium only matches on direct subdomains. In ClusterNetworkPolicy,
		// "*.kubernetes.io" is supposed to match both "blog.kubernetes.io" and
		// "latest.blog.kubernetes.io".
		//
		// TODO: https://github.com/cilium/cilium/issues/22081

		if pattern := string(fqdn); strings.Contains(pattern, "*") {
			fqdnSelector.MatchPattern = pattern
		} else {
			fqdnSelector.MatchName = string(fqdn)
		}
		dnsRule := api.PortRuleDNS(fqdnSelector)
		if err := dnsRule.Sanitize(); err != nil {
			return nil, nil, err
		}
		peerSelectors = append(peerSelectors, fqdnSelector)
		dnsRules = append(dnsRules, dnsRule)
	}
	return peerSelectors, dnsRules, nil
}

// kcnpParsePorts converts a slice of CNP Port specifications into a slice of api.PortRule.
// Exactly one of PortNumber, PortRange or NamedPort in each slice value must be non-nil,
// which is ensured through CRD validation. Returns an error if the protocol specification
// can not be parsed.
func kcnpParsePorts(ports []policyv1alpha2.ClusterNetworkPolicyPort) (api.PortRules, error) {
	portRules := api.PortRules{}
	for _, port := range ports {
		portStr := "0"
		endPort := int32(0)
		protocol := api.ProtoTCP

		if pn := port.PortNumber; pn != nil {
			var err error
			protocol, err = api.ParseL4Proto(string(pn.Protocol))
			if err != nil {
				return nil, err
			}
			portStr = strconv.Itoa(int(pn.Port))
		} else if pr := port.PortRange; pr != nil {
			var err error
			protocol, err = api.ParseL4Proto(string(pr.Protocol))
			if err != nil {
				return nil, err
			}
			portStr = strconv.Itoa(int(pr.Start))
			endPort = pr.End
		} else if np := port.NamedPort; np != nil {
			portStr = *np
		}

		portRule := api.PortRule{
			Ports: []api.PortProtocol{
				{Port: portStr, EndPort: endPort, Protocol: protocol},
			},
		}

		portRules = append(portRules, portRule)
	}
	return portRules, nil
}

// GetKCNPPolicyLabels extracts the name of the k8s Cluster Network Policy.
// It uses the name from the Cilium annotation if present. If the policy's
// annotations do not contain the Cilium annotation, the policy's name field
// is used instead.
func GetKCNPPolicyLabels(logger *slog.Logger, cnp *policyv1alpha2.ClusterNetworkPolicy) labels.LabelArray {
	if cnp == nil {
		logger.Warn("unable to extract policy labels because provided ClusterNetworkPolicy is nil")
		return nil
	}

	policyName, _ := annotation.Get(cnp, annotation.PolicyName, annotation.PolicyNameAlias)
	policyUID := cnp.UID

	if policyName == "" {
		policyName = cnp.Name
	}

	return k8sCiliumUtils.GetPolicyLabels("", policyName, policyUID, resourceTypeClusterNetworkPolicy)
}

// ParseClusterNetworkPolicy parses a k8s ClusterNetworkPolicy. Returns a list of
// Cilium policy rules that can be added, along with an error if there was an
// error sanitizing the rules.
func ParseClusterNetworkPolicy(logger *slog.Logger, clusterName string, cnp *policyv1alpha2.ClusterNetworkPolicy) (types.PolicyEntries, error) {
	if cnp == nil {
		return nil, errors.New("cannot parse ClusterNetworkPolicy because it is nil")
	}

	ingresses := types.PolicyEntries{}
	egresses := types.PolicyEntries{}

	// TODO: Implement support for rule priorities.
	_, _ = cnp.Spec.Tier, cnp.Spec.Priority

	for _, iRule := range cnp.Spec.Ingress {
		fromRules := types.PolicyEntries{}

		accept := iRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionAccept
		deny := iRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionDeny
		// TODO: Implement support for Pass rules.
		_ = iRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionPass

		var l4 api.PortRules
		if iRule.Ports != nil && len(*iRule.Ports) > 0 {
			var err error
			l4, err = kcnpParsePorts(*iRule.Ports)
			if err != nil {
				return nil, err
			}
		}

		if len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				ingress := &types.PolicyEntry{Ingress: true, Deny: deny, L4: l4}
				// Only one of Namespaces or Pods will be non-nil.
				if ps := rule.Pods; ps != nil {
					ingress.L3 = types.PeerSelectorSlice{
						kcnpParseNamespacedPod(clusterName, *ps),
					}
				} else if ns := rule.Namespaces; ns != nil {
					ingress.L3 = types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(ns)),
					}
				} else {
					// If no destination endpoint can be identified, fail closed.
					// For "Accept" rules, "fail closed" means: "treat the rule as matching no
					// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
					// as a 'Deny all' rule".
					if accept {
						ingress.L3 = types.PeerSelectorSlice{api.EndpointSelectorNone}
					} else {
						ingress.L3 = types.PeerSelectorSlice{api.WildcardEndpointSelector}
					}
				}
				fromRules = append(fromRules, ingress)
			}
		} else {
			// Based on ClusterNetworkPolicyIngressRule docs:
			//   From []ClusterNetworkPolicyIngressPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			ingress := &types.PolicyEntry{Ingress: true, Deny: deny, L4: l4}
			ingress.L3 = types.PeerSelectorSlice{api.WildcardEndpointSelector}
			fromRules = append(fromRules, ingress)
		}

		ingresses = append(ingresses, fromRules...)
	}

	for _, eRule := range cnp.Spec.Egress {
		toRules := types.PolicyEntries{}

		accept := eRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionAccept
		deny := eRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionDeny
		// TODO: Implement support for Pass rules.
		_ = eRule.Action == policyv1alpha2.ClusterNetworkPolicyRuleActionPass

		var l4 api.PortRules
		if eRule.Ports != nil && len(*eRule.Ports) > 0 {
			var err error
			l4, err = kcnpParsePorts(*eRule.Ports)
			if err != nil {
				return nil, err
			}
		}

		if len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				egress := &types.PolicyEntry{Ingress: false, Deny: deny, L4: l4}
				// Only one of Namespaces, Pods, Nodes, Networks or DomainNames will be non-nil.
				if ps := rule.Pods; ps != nil {
					egress.L3 = types.PeerSelectorSlice{kcnpParseNamespacedPod(clusterName, *ps)}
				} else if ns := rule.Namespaces; ns != nil {
					egress.L3 = types.PeerSelectorSlice{
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(ns)),
					}
				} else if nd := rule.Nodes; nd != nil {
					if !option.Config.EnableNodeSelectorLabels {
						return nil, errors.New("egress.to.nodes is not supported since node selector labels are disabled")
					}
					egress.L3 = types.PeerSelectorSlice{kcnpProcessNodeSelector(clusterName, nd)}
				} else if n := rule.Networks; n != nil {
					egress.L3 = kcnpParseCIDRSelectors(n)
				} else if dn := rule.DomainNames; dn != nil {
					if !accept {
						return nil, errors.New("egress.to.domainNames is only supported for egress.action=Accept")
					}
					if !option.Config.EnableL7Proxy {
						return nil, errors.New("egress.to.domainNames is not supported since L7 proxy is disabled")
					}
					l3, dnsL4, err := kcnpParseFQDNSelectors(dn)
					if err != nil {
						return nil, err
					}
					egress.L3 = l3
					// To allow FQDNs, we need to explicitly add an additional L3 and L4 selector
					// that allows DNS requests for the specified FQDNs.
					dnsEgress := &types.PolicyEntry{
						Ingress: false,
						Deny:    false,
						L3:      types.PeerSelectorSlice{api.WildcardEndpointSelector},
						L4: api.PortRules{{
							Ports: []api.PortProtocol{
								{Port: "53", Protocol: api.ProtoUDP},
								{Port: "53", Protocol: api.ProtoTCP},
							},
							Rules: &api.L7Rules{DNS: dnsL4},
						}},
					}
					toRules = append(toRules, dnsEgress)
				} else {
					// If no destination endpoint can be identified, fail closed.
					// For "Accept" rules, "fail closed" means: "treat the rule as matching no
					// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
					// as a 'Deny all' rule".
					if accept {
						egress.L3 = types.PeerSelectorSlice{api.EndpointSelectorNone}
					} else {
						egress.L3 = types.PeerSelectorSlice{api.WildcardEndpointSelector}
					}
				}
				toRules = append(toRules, egress)
			}
		} else {
			// Based on ClusterNetworkPolicyEgressRule docs:
			//   From []ClusterNetworkPolicyEgressPeer
			//   If this field is empty or missing, this rule matches all
			//   destinations (traffic not restricted by destination).
			egress := &types.PolicyEntry{Ingress: false, Deny: deny, L4: l4}
			egress.L3 = types.PeerSelectorSlice{api.WildcardEndpointSelector}
			toRules = append(toRules, egress)
		}

		egresses = append(egresses, toRules...)
	}

	var subject api.EndpointSelector
	// Only one of Namespaces or Pods will be non-nil.
	if ns := cnp.Spec.Subject.Namespaces; ns != nil {
		subject = api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(ns))
	} else if ps := cnp.Spec.Subject.Pods; ps != nil {
		subject = kcnpParseNamespacedPod("", *ps)
	}

	rules := append(ingresses, egresses...)
	labels := GetKCNPPolicyLabels(logger, cnp)
	for _, r := range rules {
		r.DefaultDeny = false
		r.Subject = subject
		r.Labels = labels
	}

	return rules, nil
}
