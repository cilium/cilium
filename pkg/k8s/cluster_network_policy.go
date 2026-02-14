// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"log/slog"
	"maps"
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
	clusterPrefixLbl                 = labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelCluster
)

func toSlimLabelSelector(ls *metav1.LabelSelector) *slim_metav1.LabelSelector {
	if ls == nil {
		return nil
	}
	result := &slim_metav1.LabelSelector{
		MatchLabels: make(map[string]slim_metav1.MatchLabelsValue, len(ls.MatchLabels)),
	}
	maps.Copy(result.MatchLabels, ls.MatchLabels)
	if len(ls.MatchExpressions) > 0 {
		result.MatchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(ls.MatchExpressions))
		for _, matchExp := range ls.MatchExpressions {
			lsr := slim_metav1.LabelSelectorRequirement{
				Key:      matchExp.Key,
				Operator: slim_metav1.LabelSelectorOperator(string(matchExp.Operator)),
			}
			if matchExp.Values != nil {
				lsr.Values = make([]string, 0, len(matchExp.Values))
				copy(lsr.Values, matchExp.Values)
			}
			result.MatchExpressions = append(result.MatchExpressions, lsr)
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
func kcnpParseNamespacedPod(clusterName string, peer policyv1alpha2.NamespacedPod) *types.LabelSelector {
	podSelector := toSlimLabelSelector(&peer.PodSelector)
	es := api.NewESFromK8sLabelSelector(
		labels.LabelSourceK8sKeyPrefix,
		kcnpProcessNamespaceSelector(&peer.NamespaceSelector),
		podSelector)

	if clusterName != cmtypes.PolicyAnyCluster && !isPodSelectorSelectingCluster(podSelector) {
		es.AddMatch(clusterPrefixLbl, clusterName)
	}
	return types.NewLabelSelector(es)
}

// kcnpProcessNodeSelector converts a label selector targeting a node into an
// EndpointSelector. If a cluster name is provided and the pod selector does
// not already explicitly target a cluster, a selector targeting the named
// cluster will be added.
func kcnpProcessNodeSelector(clusterName string, nodeSelector *metav1.LabelSelector) types.Selectors {
	ns := toSlimLabelSelector(nodeSelector)
	es := api.NewESFromK8sLabelSelector(labels.LabelSourceNodeKeyPrefix, ns)
	es.AddMatchExpression(labels.LabelSourceReservedKeyPrefix+labels.IDNameRemoteNode, slim_metav1.LabelSelectorOpExists, []string{})

	if clusterName != cmtypes.PolicyAnyCluster && !isPodSelectorSelectingCluster(ns) {
		es.AddMatch(clusterPrefixLbl, clusterName)
	}

	return types.ToSelectors(es)
}

func kcnpParseCIDRSelectors(cidrs []policyv1alpha2.CIDR) types.Selectors {
	result := types.Selectors{}
	for _, cidr := range cidrs {
		result = append(result, types.ToSelector(api.CIDR(string(cidr))))
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
func kcnpParseFQDNSelectors(fqdns []policyv1alpha2.DomainName) (types.Selectors, api.PortRulesDNS, error) {
	peerSelectors := types.Selectors{}
	dnsRules := api.PortRulesDNS{}
	for _, fqdn := range fqdns {
		var fqdnSelector api.FQDNSelector
		// If the domain name contains an asterisk, we assume it is a
		// pattern instead of a plain domain name.
		if pattern := string(fqdn); strings.HasPrefix(pattern, "*") {
			// K8s ClusterNetworkPolicy restricts wildcards to domain prefixes (e.g.,
			// "*.example.com"), a constraint enforced at the CRD validation level.
			//
			// There is a functional discrepancy in how subdomains are handled:
			// 1. K8s CNP: "*.kubernetes.io" is recursive; it matches "blog.kubernetes.io"
			//    subdomains like "latest.blog.kubernetes.io".
			// 2. Cilium: By default, a single wildcard matches only one label level.
			//
			// To preserve K8s semantics, we convert single-prefix wildcards to Cilium's
			// double-wildcard syntax ("**") to enable recursive subdomain matching.
			if !strings.HasPrefix(pattern, "**") {
				pattern = "*" + pattern
			}
			fqdnSelector.MatchPattern = pattern
		} else {
			fqdnSelector.MatchName = string(fqdn)
		}
		dnsRule := api.PortRuleDNS(fqdnSelector)
		if err := dnsRule.Sanitize(); err != nil {
			return nil, nil, err
		}
		peerSelectors = append(peerSelectors, types.ToSelector(fqdnSelector))
		dnsRules = append(dnsRules, dnsRule)
	}
	return peerSelectors, dnsRules, nil
}

// kcnpParseProtocols converts a slice of CNP Port specifications into a slice of api.PortRule.
// Exactly one of PortNumber, PortRange or NamedPort in each slice value must be non-nil,
// which is ensured through CRD validation. Returns an error if the protocol specification
// can not be parsed.
func kcnpParseProtocols(protocols []policyv1alpha2.ClusterNetworkPolicyProtocol) (api.PortRules, error) {
	portRules := api.PortRules{}
	for _, proto := range protocols {
		var (
			pp   api.PortProtocol
			port *policyv1alpha2.Port
		)

		// Only one of TCP, UDP, SCTP or DestinationNamedPort can be specified.
		// This is ensured by CRD validation.
		if tcp := proto.TCP; tcp != nil {
			port = tcp.DestinationPort
			pp.Protocol = api.ProtoTCP
		} else if udp := proto.UDP; udp != nil {
			port = udp.DestinationPort
			pp.Protocol = api.ProtoUDP
		} else if sctp := proto.SCTP; sctp != nil {
			port = sctp.DestinationPort
			pp.Protocol = api.ProtoSCTP
		}

		if port != nil {
			if r := port.Range; r != nil {
				pp.Port = strconv.Itoa(int(r.Start))
				pp.EndPort = r.End
			} else {
				pp.Port = strconv.Itoa(int(port.Number))
			}
		} else if np := proto.DestinationNamedPort; np != "" {
			pp.Port = np
			pp.Protocol = api.ProtoAny
		}

		portRules = append(portRules, api.PortRule{Ports: []api.PortProtocol{pp}})
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

func actionToVerdict(action policyv1alpha2.ClusterNetworkPolicyRuleAction) types.Verdict {
	switch action {
	case policyv1alpha2.ClusterNetworkPolicyRuleActionDeny:
		return types.Deny
	case policyv1alpha2.ClusterNetworkPolicyRuleActionPass:
		return types.Pass
	default:
		return types.Allow
	}
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

	basePriority := float64(cnp.Spec.Priority)
	tier := types.Admin
	if cnp.Spec.Tier == policyv1alpha2.BaselineTier {
		tier = types.Baseline
	}

	for i, iRule := range cnp.Spec.Ingress {
		fromRules := types.PolicyEntries{}
		priority := basePriority + float64(i)/100
		verdict := actionToVerdict(iRule.Action)

		var l4 api.PortRules
		if len(iRule.Protocols) > 0 {
			var err error
			l4, err = kcnpParseProtocols(iRule.Protocols)
			if err != nil {
				return nil, err
			}
		}

		if len(iRule.From) > 0 {
			for _, rule := range iRule.From {
				ingress := &types.PolicyEntry{Ingress: true, Verdict: verdict, L4: l4, Priority: priority, Tier: tier}
				// Only one of Namespaces or Pods will be non-nil.
				switch {
				case rule.Pods != nil:
					ingress.L3 = types.Selectors{
						kcnpParseNamespacedPod(clusterName, *rule.Pods),
					}
				case rule.Namespaces != nil:
					ingress.L3 = types.ToSelectors(
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(rule.Namespaces)))
				default:
					// If no destination endpoint can be identified, fail closed.
					// For "Accept" rules, "fail closed" means: "treat the rule as matching no
					// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
					// as a 'Deny all' rule".
					if verdict == types.Allow {
						continue
					} else {
						ingress.L3 = types.WildcardSelectors
						ingress.Verdict = types.Deny
					}
				}
				fromRules = append(fromRules, ingress)
			}
		} else {
			// Based on ClusterNetworkPolicyIngressRule docs:
			//   From []ClusterNetworkPolicyIngressPeer
			//   If this field is empty or missing, this rule matches all
			//   sources (traffic not restricted by source).
			ingress := &types.PolicyEntry{Ingress: true, Verdict: verdict, L4: l4, Priority: priority, Tier: tier}
			ingress.L3 = types.WildcardSelectors
			fromRules = append(fromRules, ingress)
		}

		ingresses = append(ingresses, fromRules...)
	}

	for i, eRule := range cnp.Spec.Egress {
		toRules := types.PolicyEntries{}
		priority := basePriority + float64(i)/100
		verdict := actionToVerdict(eRule.Action)

		var l4 api.PortRules
		if len(eRule.Protocols) > 0 {
			var err error
			l4, err = kcnpParseProtocols(eRule.Protocols)
			if err != nil {
				return nil, err
			}
		}

		if len(eRule.To) > 0 {
			for _, rule := range eRule.To {
				egress := &types.PolicyEntry{Ingress: false, Verdict: verdict, L4: l4, Priority: priority, Tier: tier}
				// Only one of Namespaces, Pods, Nodes, Networks or DomainNames will be non-nil.
				switch {
				case rule.Pods != nil:
					egress.L3 = types.Selectors{kcnpParseNamespacedPod(clusterName, *rule.Pods)}
				case rule.Namespaces != nil:
					egress.L3 = types.ToSelectors(
						api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(rule.Namespaces)))
				case rule.Nodes != nil:
					if !option.Config.EnableNodeSelectorLabels {
						return nil, errors.New("egress.to.nodes is not supported since node selector labels are disabled")
					}
					egress.L3 = kcnpProcessNodeSelector(clusterName, rule.Nodes)
				case rule.Networks != nil:
					egress.L3 = kcnpParseCIDRSelectors(rule.Networks)
				case rule.DomainNames != nil:
					if verdict != types.Allow {
						return nil, errors.New("egress.to.domainNames is only supported for egress.action=Accept")
					}
					if !option.Config.EnableL7Proxy {
						return nil, errors.New("egress.to.domainNames is not supported since L7 proxy is disabled")
					}
					l3, dnsL4, err := kcnpParseFQDNSelectors(rule.DomainNames)
					if err != nil {
						return nil, err
					}
					egress.L3 = l3
					// To allow FQDNs, we need to explicitly add an additional L3 and L4 selector
					// that allows DNS requests for the specified FQDNs.
					dnsEgress := &types.PolicyEntry{
						Ingress: false,
						Verdict: types.Allow,
						// TODO: Make this configurable
						L3: types.ToSelectors(api.NewESFromLabels(labels.ParseSelectLabel("k8s-app=kube-dns"))),
						L4: api.PortRules{{
							Ports: []api.PortProtocol{
								{Port: "dns"},
								{Port: "dns-tcp"},
							},
							Rules: &api.L7Rules{DNS: dnsL4},
						}},
						Priority: priority,
						Tier:     tier,
					}
					toRules = append(toRules, dnsEgress)
				default:
					// If no destination endpoint can be identified, fail closed.
					// For "Accept" rules, "fail closed" means: "treat the rule as matching no
					// traffic". For "Deny" and "Pass" rules, "fail closed" means: "treat the rule
					// as a 'Deny all' rule".
					if verdict == types.Allow {
						continue
					} else {
						egress.L3 = types.WildcardSelectors
						egress.Verdict = types.Deny
					}
				}
				toRules = append(toRules, egress)
			}
		} else {
			// Based on ClusterNetworkPolicyEgressRule docs:
			//   From []ClusterNetworkPolicyEgressPeer
			//   If this field is empty or missing, this rule matches all
			//   destinations (traffic not restricted by destination).
			egress := &types.PolicyEntry{Ingress: false, Verdict: verdict, L4: l4, Priority: priority, Tier: tier}
			egress.L3 = types.WildcardSelectors
			toRules = append(toRules, egress)
		}

		egresses = append(egresses, toRules...)
	}

	var subject *types.LabelSelector
	// Only one of Namespaces or Pods will be non-nil.
	if ns := cnp.Spec.Subject.Namespaces; ns != nil {
		subject = types.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, kcnpProcessNamespaceSelector(ns)))
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
