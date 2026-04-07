// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"slices"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_upstream_codec "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// allowAllPortNetworkPolicy is a PortNetworkPolicy that allows all traffic
	// to any L4 port.
	allowAllTCPPortNetworkPolicy = &cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		Protocol: envoy_config_core.SocketAddress_TCP,
	}
	allowAllPortNetworkPolicy = []*cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		allowAllTCPPortNetworkPolicy,
		// Allow all UDP/SCTP traffic to any port.
		// UDP/SCTP rules not sent to Envoy for now.
	}

	DenyVerdict = &cilium.PortNetworkPolicyRule_Deny{Deny: true}
)

const (
	CiliumXDSClusterName = "xds-grpc-cilium"

	// LocalNodeID is the Envoy node ID used by the host proxy.
	LocalNodeID = "host~127.0.0.1~no-id~localdomain"

	// direction logging
	ingressDirection = "ingress"
	egressDirection  = "egress"
)

type GetEgressNamedPorts func(name string, proto u8proto.U8proto, idents iter.Seq[identity.NumericIdentity]) ciliumTypes.NidPortSeq

type Resource interface {
	proto.Message
}

type portKey struct {
	port    uint16
	endPort uint16
}

type portState struct {
	rules []*cilium.PortNetworkPolicyRule

	// Assume none of the rules have side-effects so that rule evaluation can be
	// stopped as soon as the first allowing rule is found. Values are added to
	// 'cantShortCircuit' for each precedence for which this is not true.
	cantShortCircuit map[uint32]struct{}

	// port-specific wildcard selector rules, if any, only for the highest
	// precedence rules.
	allowAllPrecedence uint32
	denyAllPrecedence  uint32
	allowAllRule       *cilium.PortNetworkPolicyRule
	denyAllRule        *cilium.PortNetworkPolicyRule
}

func ToAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}

func GetPublicListenerAddress(port uint16, ipv4, ipv6 bool) *envoy_config_core.Address {
	listenerAddr := "0.0.0.0"
	if ipv6 {
		listenerAddr = "::"
	}
	return &envoy_config_core.Address{
		Address: &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       listenerAddr,
				Ipv4Compat:    ipv4 && ipv6,
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		},
	}
}

func GetLocalListenerAddresses(port uint16, ipv4, ipv6 bool) (*envoy_config_core.Address, []*envoy_config_listener.AdditionalAddress) {
	addresses := []*envoy_config_core.Address_SocketAddress{}

	if ipv4 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "127.0.0.1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	if ipv6 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "::1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	var additionalAddress []*envoy_config_listener.AdditionalAddress

	if len(addresses) > 1 {
		additionalAddress = append(additionalAddress, &envoy_config_listener.AdditionalAddress{
			Address: &envoy_config_core.Address{
				Address: addresses[1],
			},
		})
	}

	return &envoy_config_core.Address{
		Address: addresses[0],
	}, additionalAddress
}

func GetListenerFilter(isIngress bool, useOriginalSourceAddr bool, proxyPort uint16, lingerConfig int) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                isIngress,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   false,
		ProxyId:                  uint32(proxyPort),
		IpcacheName:              ipcache.Name,
	}

	if ADSModeEnabled() {
		// Keep NPHDS disabled in production. Envoy can resolve identities from
		// ipcache/BPF maps, while standalone Envoy tests enable NPHDS explicitly
		// for environments without datapath maps.
		conf.CiliumConfigSource = NewCiliumXdsWithAdsConfigSource()
	}

	if lingerConfig >= 0 {
		lingerTime := uint32(lingerConfig)
		conf.OriginalSourceSoLingerTime = &lingerTime
	}

	return &envoy_config_listener.ListenerFilter{
		Name: "cilium.bpf_metadata",
		ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
			TypedConfig: ToAny(conf),
		},
	}
}

func GetInternalListenerCIDRs(ipv4, ipv6 bool) []*envoy_config_core.CidrRange {
	var cidrRanges []*envoy_config_core.CidrRange

	if ipv4 {
		cidrRanges = append(cidrRanges,
			[]*envoy_config_core.CidrRange{
				{AddressPrefix: "10.0.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 8}},
				{AddressPrefix: "172.16.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 12}},
				{AddressPrefix: "192.168.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 16}},
				{AddressPrefix: "127.0.0.1", PrefixLen: &wrapperspb.UInt32Value{Value: 32}},
			}...)
	}

	if ipv6 {
		cidrRanges = append(cidrRanges, &envoy_config_core.CidrRange{
			AddressPrefix: "::1",
			PrefixLen:     &wrapperspb.UInt32Value{Value: 128},
		})
	}
	return cidrRanges
}

// toEnvoyOriginatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for originating TLS (i.e., verifying TLS connections from *outside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyOriginatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If values are not present in these fields, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				ValidationContextSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		TrustedCa: tls.TrustedCA,
	}
}

// toEnvoyTerminatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for terminating TLS (i.e., providing a valid cert to clients *inside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyTerminatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If the values have been read from Kubernetes, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				TlsSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

func namespacedNametoSyncedSDSSecretName(namespacedName types.NamespacedName, policySecretsNamespace string) string {
	if policySecretsNamespace == "" {
		return fmt.Sprintf("%s/%s", namespacedName.Namespace, namespacedName.Name)
	}
	return fmt.Sprintf("%s/%s-%s", policySecretsNamespace, namespacedName.Namespace, namespacedName.Name)
}

// return the Envoy proxy node IDs that need to ACK the policy.
func GetNodeIDs(ep endpoint.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)

	// Host proxy uses LocalNodeID as the nodeID
	nodeIDs = append(nodeIDs, LocalNodeID)
	return nodeIDs
}

// GetLegacyFormatNodeIDs returns the Envoy proxy IDs that need to ACK policy
// updates on the legacy per-type xDS server. The legacy server records ACKs by
// parsed node IP, not by full Envoy node ID.
func GetLegacyFormatNodeIDs(ep endpoint.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)

	nodeIDs = append(nodeIDs, "127.0.0.1")
	return nodeIDs
}

func GetNetworkPolicy(ep endpoint.EndpointUpdater, getEgressNamedPorts GetEgressNamedPorts, selectors policy.SelectorSnapshot, names []string, l4Policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS bool, policySecretsNamespace string, logger *slog.Logger, l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator,
) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		EndpointIps: names,
		EndpointId:  ep.GetID(),
	}

	if l4Policy != nil {
		p.IngressPerPortPolicies = GetDirectionNetworkPolicy(ep, getEgressNamedPorts, selectors, &l4Policy.Ingress, ingressPolicyEnforced, useFullTLSContext, useSDS, ingressDirection, policySecretsNamespace, logger, l7RulesTranslator)
		p.EgressPerPortPolicies = GetDirectionNetworkPolicy(ep, getEgressNamedPorts, selectors, &l4Policy.Egress, egressPolicyEnforced, useFullTLSContext, useSDS, egressDirection, policySecretsNamespace, logger, l7RulesTranslator)
	}

	return p
}

func GetPortNetworkPolicyRule(ep endpoint.EndpointUpdater, selectors policy.SelectorSnapshot, sel policy.CachedSelector, psp *policy.PerSelectorPolicy, tierBasePriority, tierLastPriority policyTypes.Priority, useFullTLSContext, useSDS bool, policySecretsNamespace string, l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator, logger *slog.Logger) (*cilium.PortNetworkPolicyRule, bool) {
	r := InitPortNetworkPolicyRule(psp, tierBasePriority, tierLastPriority, logger)

	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	if !sel.IsWildcard() {
		selections := sel.GetSelectionsAt(selectors)

		// No remote policies would match this rule. Discard it.
		if len(selections) == 0 {
			return nil, true
		}

		r.RemotePolicies = selections.AsUint32Slice()
	}

	if psp == nil {
		// L3/L4 only rule, everything in L7 is allowed && no TLS
		return r, true
	}

	// Deny rules never have L7 rules and can not be short-circuited (i.e., rule evaluation
	// after an allow rule must continue to find the possibly applicable deny rule).
	if psp.IsDeny() {
		return r, false
	}

	// Pass redirect port as proxy ID if the rule has an explicit listener reference.
	// This makes this rule to be ignored on any listener that does not have a matching
	// proxy ID.
	if psp.Listener != "" {
		r.ProxyId = uint32(ep.GetListenerProxyPort(psp.Listener))
	}

	// If secret synchronization is disabled, policySecretsNamespace will be the empty string.
	//
	// In that case, useFullTLSContext is used to retain an old, buggy behavior where Secrets
	// may contain a `ca.crt` field as well, which can lead Envoy to enforce client TLS between
	// the client pod and the interception point in Envoy. In this case, Secrets will be sent to
	// Envoy via the old, inline-in-NPDS method, and _not_ via SDS.
	//
	// If secret synchronization is enabled, useFullTLSContext is unused, as SDS handling can
	// handle Secrets with extra keys correctly.
	if psp.TerminatingTLS != nil {
		r.DownstreamTlsContext = toEnvoyTerminatingTLSContext(psp.TerminatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}
	if psp.OriginatingTLS != nil {
		r.UpstreamTlsContext = toEnvoyOriginatingTLSContext(psp.OriginatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}

	if len(psp.ServerNames) > 0 {
		r.ServerNames = make([]string, 0, len(psp.ServerNames))
		for sni := range psp.ServerNames {
			r.ServerNames = append(r.ServerNames, sanitizeServerNamePattern(sni))
		}
		slices.Sort(r.ServerNames)
	}

	// Assume none of the rules have side-effects so that rule evaluation can
	// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
	// is set to 'false' below if any rules with side effects are encountered,
	// causing all the applicable rules to be evaluated instead.
	canShortCircuit := true
	switch psp.L7Parser {
	case policy.ParserTypeHTTP:
		// 'r.L7' is an interface which must not be set to a typed 'nil',
		// so check if we have any rules
		if len(psp.HTTP) > 0 {
			// Use L7 rules computed earlier?
			var httpRules *cilium.HttpNetworkPolicyRules
			if psp.EnvoyHTTPRules() != nil {
				httpRules = psp.EnvoyHTTPRules()
				canShortCircuit = psp.CanShortCircuit()
			} else {
				httpRules, canShortCircuit = l7RulesTranslator.GetEnvoyHTTPRules(&psp.L7Rules, "")
			}
			r.L7 = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: httpRules,
			}
		}

	case policy.ParserTypeDNS:
		// TODO: Support DNS. For now, just ignore any DNS L7 rule.
	}

	return r, canShortCircuit
}

func GetDirectionNetworkPolicy(ep endpoint.EndpointUpdater, getEgressNamedPorts GetEgressNamedPorts, selectors policy.SelectorSnapshot, l4DirectionPolicy *policy.L4DirectionPolicy, policyEnforced bool, useFullTLSContext, useSDS bool, dir string, policySecretsNamespace string, logger *slog.Logger, l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator) []*cilium.PortNetworkPolicy {
	// TODO: integrate visibility with enforced policy
	if !policyEnforced {
		// Always allow all ports
		return []*cilium.PortNetworkPolicy{allowAllTCPPortNetworkPolicy}
	}

	if l4DirectionPolicy == nil {
		return nil
	}

	l4Policy := l4DirectionPolicy.PortRules

	if l4Policy.Len() == 0 {
		return nil
	}

	debugEnabled := logger.Enabled(context.Background(), slog.LevelDebug)

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, l4Policy.Len())

	// Check for wildcard port policy first, one tier at the time
	addWildcardPortRules := func(l4 *policy.L4Filter,
		tierBasePriority, tierLastPriority policyTypes.Priority) (bool, policyTypes.Precedence) {
		wildcardPortRules, havePassRules, wildcardSelectorPrecedence := GetWildcardPortNetworkPolicyRules(ep, selectors, tierBasePriority, tierLastPriority, l4.PerSelectorPolicies, useFullTLSContext, useSDS, policySecretsNamespace, logger, l7RulesTranslator)

		if debugEnabled {
			for _, rule := range wildcardPortRules {
				logger.Debug("Wildcard PortNetworkPolicyRule matching remote IDs",
					logfields.EndpointID, ep.GetID(),
					logfields.Version, selectors,
					logfields.TrafficDirection, dir,
					logfields.Port, "0",
					logfields.IsDeny, rule.GetDeny(),
					logfields.PolicyPassPrecedence, rule.GetPassPrecedence(),
					logfields.PolicyID, rule.RemotePolicies,
					logfields.Tier, l4.Tier,
				)
			}
		}

		if len(wildcardPortRules) > 0 {
			if len(wildcardPortRules) == 1 && isEmptyRule(wildcardPortRules[0]) {
				wildcardPortRules = nil
			} else if len(wildcardPortRules) > 1 {
				envoypolicy.SortPortNetworkPolicyRules(wildcardPortRules)
			}
			portPolicy := &cilium.PortNetworkPolicy{
				Port:     0,
				EndPort:  0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules:    wildcardPortRules,
			}
			PerPortPolicies = append(PerPortPolicies, portPolicy)
		} else if debugEnabled {
			logger.Debug("Skipping wildcard PortNetworkPolicy due to no matching remote identities",
				logfields.EndpointID, ep.GetID(),
				logfields.TrafficDirection, dir,
				logfields.Port, "0",
				logfields.Tier, l4.Tier,
			)
		}
		return havePassRules, wildcardSelectorPrecedence
	}

	// interate tier-by-tier
	for i := range l4Policy {
		tier := policyTypes.Tier(i)
		tierBasePriority, tierLastPriority := l4DirectionPolicy.GetTierPriorities(tier)

		var havePassRules bool
		var wildcardSelectorPrecedence policyTypes.Precedence
		for _, protocol := range []u8proto.U8proto{u8proto.ANY, u8proto.TCP} {
			l4 := l4Policy[tier].ExactLookupPortNum(0, 0, protocol)
			if l4 != nil {
				havePasses, wildcardPrecedence := addWildcardPortRules(l4, tierBasePriority, tierLastPriority)
				if wildcardSelectorPrecedence < wildcardPrecedence {
					wildcardSelectorPrecedence = wildcardPrecedence
				}
				havePassRules = havePassRules || havePasses
			}
		}

		rulesByPort := map[portKey]portState{}
		var ports []portKey
		ensurePortState := func(key portKey) portState {
			byPort, ok := rulesByPort[key]
			if !ok {
				byPort.cantShortCircuit = make(map[uint32]struct{})
				ports = append(ports, key)
			}
			return byPort
		}

		for l4 := range l4Policy[tier].Filters() {
			switch l4.U8Proto {
			case u8proto.TCP, u8proto.ANY:
			default:
				// Other protocol rules not sent to Envoy for now.
				continue
			}

			port := l4.Port
			if port == 0 && l4.PortName != "" && l4.Ingress {
				port = ep.GetIngressNamedPort(l4.PortName, l4.U8Proto)
			}

			for sel, psp := range l4.PerSelectorPolicies {
				precedence := psp.GetPrecedence()

				if precedence < wildcardSelectorPrecedence ||
					wildcardSelectorPrecedence.IsDeny() && precedence == wildcardSelectorPrecedence {
					if debugEnabled {
						logger.Debug("PortNetworkPolicyRule skipping rule due to higher precedence wildcard port rule",
							logfields.EndpointID, ep.GetID(),
							logfields.Version, selectors,
							logfields.TrafficDirection, dir,
							logfields.Port, port,
						)
					}
					continue
				}

				// Handle egress named ports separately
				if port == 0 && l4.PortName != "" && !l4.Ingress {
					if getEgressNamedPorts == nil {
						continue
					}

					selections := sel.GetSelectionsAt(selectors)
					if len(selections) == 0 {
						continue
					}

					remotePoliciesByPort := map[uint16][]uint32{}
					for id, port := range getEgressNamedPorts(l4.PortName, l4.U8Proto, slices.Values(selections)) {
						// selections is sorted, so remotePolicies is also sorted.
						remotePoliciesByPort[port] = append(remotePoliciesByPort[port], uint32(id))
					}
					for port, remotePolicies := range remotePoliciesByPort {
						rule, csc := GetPortNetworkPolicyRule(ep, selectors, sel, psp,
							tierBasePriority, tierLastPriority,
							useFullTLSContext, useSDS, policySecretsNamespace, l7RulesTranslator, logger)
						if rule == nil {
							continue
						}
						rule.RemotePolicies = remotePolicies

						if debugEnabled {
							logger.Debug("PortNetworkPolicyRule matching remote IDs",
								logfields.EndpointID, ep.GetID(),
								logfields.Version, selectors,
								logfields.TrafficDirection, dir,
								logfields.Port, port,
								logfields.ProxyPort, rule.ProxyId,
								logfields.PolicyID, rule.RemotePolicies,
								logfields.ServerNames, rule.ServerNames,
							)
						}

						portKey := portKey{port, l4.EndPort}
						byPort := ensurePortState(portKey)
						if !csc {
							byPort.cantShortCircuit[rule.Precedence] = struct{}{}
						}
						byPort.rules = append(byPort.rules, rule)
						rulesByPort[portKey] = byPort
					}
					continue
				}

				// Skip if a named port can not be resolved (yet)
				// wildcard port already taken care of above
				if port == 0 {
					continue
				}

				rule, csc := GetPortNetworkPolicyRule(ep, selectors, sel, psp,
					tierBasePriority, tierLastPriority,
					useFullTLSContext, useSDS, policySecretsNamespace, l7RulesTranslator, logger)
				if rule == nil {
					continue
				}

				if debugEnabled {
					logger.Debug("PortNetworkPolicyRule matching remote IDs",
						logfields.EndpointID, ep.GetID(),
						logfields.Version, selectors,
						logfields.TrafficDirection, dir,
						logfields.Port, port,
						logfields.ProxyPort, rule.ProxyId,
						logfields.PolicyID, rule.RemotePolicies,
						logfields.ServerNames, rule.ServerNames,
					)
				}

				portKey := portKey{port, l4.EndPort}
				byPort := ensurePortState(portKey)
				if !csc {
					byPort.cantShortCircuit[rule.Precedence] = struct{}{}
				}

				if len(rule.RemotePolicies) == 0 {
					if rule.GetDeny() {
						if rule.Precedence > byPort.denyAllPrecedence {
							byPort.denyAllRule = rule
							byPort.denyAllPrecedence = rule.Precedence
						}
					} else if isEmptyRuleButPrecedence(rule) {
						if rule.Precedence > byPort.allowAllPrecedence {
							byPort.allowAllRule = rule
							byPort.allowAllPrecedence = rule.Precedence
						}
					}
				}
				byPort.rules = append(byPort.rules, rule)
				rulesByPort[portKey] = byPort
			}
		}

		if len(ports) > 1 {
			slices.SortFunc(ports, func(a, b portKey) int {
				if a.port < b.port {
					return -1
				}
				if a.port > b.port {
					return 1
				}
				if a.endPort < b.endPort {
					return -1
				}
				if a.endPort > b.endPort {
					return 1
				}
				return 0
			})
		}
		for _, portKey := range ports {
			byPort := rulesByPort[portKey]
			rules, cantShortCircuit, allowAllRule, denyAllRule :=
				byPort.rules, byPort.cantShortCircuit, byPort.allowAllRule, byPort.denyAllRule

			// prune out rules due to wildcard rules on this port, if any
			if denyAllRule != nil || allowAllRule != nil {
				nRules := len(rules)
				rules = slices.DeleteFunc(rules, func(rule *cilium.PortNetworkPolicyRule) bool {
					_, found := cantShortCircuit[rule.Precedence]
					canShortCircuit := !found

					return denyAllRule != nil && rule != denyAllRule && rule.Precedence <= denyAllRule.Precedence ||
						allowAllRule != nil && rule != allowAllRule &&
							(rule.Precedence < allowAllRule.Precedence ||
								canShortCircuit && rule.Precedence == allowAllRule.Precedence)
				})

				if len(rules) < nRules && debugEnabled {
					logger.Debug("Pruned rules due to wildcard rules on the port ",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, portKey.port,
						logfields.Count, nRules-len(rules),
					)
				}
			}

			// No rule for this port matches any remote identity.
			// In this case, just don't generate any PortNetworkPolicy for this
			// port.
			if len(rules) == 0 {
				if debugEnabled {
					logger.Debug("Skipping PortNetworkPolicy due to no matching remote identities",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, portKey.port,
					)
				}
				continue
			}

			if len(rules) > 1 {
				envoypolicy.SortPortNetworkPolicyRules(rules)
			} else if len(rules) == 1 && isEmptyRule(rules[0]) {
				rules = nil
			}

			// NPDS supports port ranges.
			portPolicy := &cilium.PortNetworkPolicy{
				Port:     uint32(portKey.port),
				EndPort:  uint32(portKey.endPort),
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules:    rules,
			}
			PerPortPolicies = append(PerPortPolicies, portPolicy)
		}

		// Skip remaining tiers if there is a wildcard port/selector rule and no pass
		// verdicts
		if wildcardSelectorPrecedence > 0 && !havePassRules {
			if debugEnabled {
				logger.Debug("Short circuiting later tiers due to wildcard rule",
					logfields.EndpointID, ep.GetID(),
					logfields.TrafficDirection, dir,
					logfields.PolicyPrecedence, wildcardSelectorPrecedence,
				)
			}
			break // lower tiers are skipped
		}
	}

	if len(PerPortPolicies) == 0 {
		return nil
	}

	return envoypolicy.SortPortNetworkPolicies(PerPortPolicies)
}

// getWildcardPortNetworkPolicyRules returns the rules for port 0, which
// will be considered after port-specific rules.
// Returns the set of rules, and if any of them was a deny/allow all rule, and the highest priority
// of any deny/allow all rule, if any.
func GetWildcardPortNetworkPolicyRules(ep endpoint.EndpointUpdater,
	snapshot policy.SelectorSnapshot, tierBasePriority, tierLastPriority policyTypes.Priority,
	selectors policy.L7DataMap, useFullTLSContext, useSDS bool, policySecretsNamespace string, logger *slog.Logger, l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator,
) (rules []*cilium.PortNetworkPolicyRule, havePassRules bool, wildcardPrecedence policyTypes.Precedence) {
	// selections are pre-sorted, so sorting is only needed if merging selections from multiple
	// selectors

	// Simplified path for one selector, loop to get the sole selector
	if len(selectors) == 1 {
		for sel, psp := range selectors {
			isPass := psp.IsPass()
			var rule *cilium.PortNetworkPolicyRule
			if psp.IsRedirect() {
				rule, _ = GetPortNetworkPolicyRule(ep, snapshot, sel, psp,
					tierBasePriority, tierLastPriority,
					useFullTLSContext, useSDS, policySecretsNamespace, l7RulesTranslator, logger)
				if rule == nil {
					return nil, false, 0
				}
			} else {
				rule = InitPortNetworkPolicyRule(psp, tierBasePriority, tierLastPriority, logger)
			}
			rules = append(rules, rule)
			if sel.IsWildcard() {
				precedence := policyTypes.Precedence(rule.Precedence)
				if psp.IsRedirect() {
					// a wildcard selector / wildcard port rule with a redirect
					// is not considered an allow-all rule (as the listener can
					// restrict the allowed traffic), but it still suppresses
					// lower-priority rules. For this priority comparison the
					// listener priority information is masked away.
					return rules, isPass, precedence.AllowPrecedence()
				}
				return rules, isPass, precedence
			}
			selections := sel.GetSelectionsAt(snapshot)
			if len(selections) == 0 {
				// No remote policies would match this rule. Discard it.
				return nil, false, 0
			}
			rule.RemotePolicies = selections.AsUint32Slice()
			return rules, isPass, 0
		}
	}

	// Collect selections for each precedence level
	denies := make(map[policyTypes.Precedence][]uint32, len(selectors))
	allows := make(map[policyTypes.Precedence][]uint32, len(selectors))
	passes := make(map[policyTypes.CachedSelector]*policy.PerSelectorPolicy)
	var wildcardPolicy *policy.PerSelectorPolicy
	var haveWildcardPolicy bool

	var redirects map[policyTypes.CachedSelector]*policy.PerSelectorPolicy

	for sel, psp := range selectors {
		precedence := psp.GetPrecedence()

		// handle redirects separately
		if psp.IsRedirect() {
			// redirect is always an Allow rule, never a Deny or Pass
			if sel.IsWildcard() {
				// Wildcard selector rule with a redirect. Mask off listener
				// priority to suppress only lower-priority rules.
				precedence := precedence.AllowPrecedence()
				if precedence > wildcardPrecedence {
					wildcardPrecedence = precedence
				}
			}
			if redirects == nil {
				redirects = make(map[policyTypes.CachedSelector]*policy.PerSelectorPolicy)
			}
			redirects[sel] = psp
			continue
		}

		// keep track of the highest precedence wildcard rule
		if sel.IsWildcard() {
			if precedence > wildcardPrecedence {
				wildcardPrecedence = precedence
				wildcardPolicy = psp // can be nil
				haveWildcardPolicy = true
			}
			continue
		}

		selections := sel.GetSelectionsAt(snapshot)
		if len(selections) == 0 {
			continue // non-wildcard rules selects nothing, skip
		}

		switch psp.GetVerdict() {
		case policyTypes.Deny:
			denies[precedence] = append(denies[precedence], selections.AsUint32Slice()...)
		case policyTypes.Allow:
			allows[precedence] = append(allows[precedence], selections.AsUint32Slice()...)
		case policyTypes.Pass:
			passes[sel] = psp
		}
	}

	// add the wildcard rule
	if haveWildcardPolicy {
		rule := InitPortNetworkPolicyRule(wildcardPolicy, tierBasePriority, tierLastPriority, logger)
		rules = append(rules, rule)
		havePassRules = wildcardPolicy.IsPass()
	}

	// add non-wildcard rules of higher precedence than the wildcard rule
	for precedence, denies := range denies {
		if precedence > wildcardPrecedence {
			slices.Sort(denies)
			denies = slices.Compact(denies)

			rules = append(rules, &cilium.PortNetworkPolicyRule{
				Precedence:     uint32(precedence),
				Verdict:        DenyVerdict,
				RemotePolicies: denies,
			})
		}
	}
	for precedence, allows := range allows {
		if precedence > wildcardPrecedence {
			slices.Sort(allows)
			allows = slices.Compact(allows)

			rules = append(rules, &cilium.PortNetworkPolicyRule{
				Precedence:     uint32(precedence),
				RemotePolicies: allows,
			})
		}
	}

	for sel, psp := range redirects {
		if logger.Enabled(context.Background(), slog.LevelDebug) {
			logger.Debug("Wildcard redirect PortNetworkPolicyRule",
				logfields.EndpointID, ep.GetID(),
				logfields.Version, snapshot,
				logfields.Port, "0",
				logfields.ProxyRedirect, psp.L7Parser,
				logfields.Listener, psp.Listener,
				logfields.ListenerPriority, psp.ListenerPriority,
			)
		}
		rule, _ := GetPortNetworkPolicyRule(ep, snapshot, sel, psp,
			tierBasePriority, tierLastPriority,
			useFullTLSContext, useSDS, policySecretsNamespace, l7RulesTranslator, logger)
		if rule != nil && policyTypes.Precedence(rule.Precedence) > wildcardPrecedence {
			rules = append(rules, rule)
		}
	}

	for sel, psp := range passes {
		rule := InitPortNetworkPolicyRule(psp, tierBasePriority, tierLastPriority, logger)
		if policyTypes.Precedence(rule.Precedence) > wildcardPrecedence {
			if !sel.IsWildcard() {
				rule.RemotePolicies = sel.GetSelectionsAt(snapshot).AsUint32Slice()
				if len(rule.RemotePolicies) == 0 {
					// skip non-wildcard that selects nothing
					continue
				}
			}
			rules = append(rules, rule)
			havePassRules = true
		}
	}

	return rules, havePassRules, wildcardPrecedence
}

var errOutOfTierPriority = errors.New("Rule priority is invalid for the tier")

// InitPortNetworkPolicyRule returns a new PortNetworkPolicyRule with Precedence and Verdict fields
// initialized. RemotePolicies field is left empty, which is only good for a wildcard identity rule.
func InitPortNetworkPolicyRule(psp *policy.PerSelectorPolicy, tierBasePriority, tierLastPriority policyTypes.Priority, logger *slog.Logger) *cilium.PortNetworkPolicyRule {
	priority := psp.GetPriority()
	if priority < tierBasePriority || priority > tierLastPriority {
		logger.Error(errOutOfTierPriority.Error(),
			logfields.TierBasePriority, tierBasePriority,
			logfields.Priority, priority,
			logfields.TierLastPriority, tierLastPriority,
			logfields.Stacktrace, hclog.Stacktrace())
	}
	verdict := psp.GetVerdict()

	precedence := psp.GetPrecedence()

	var passPrecedence policyTypes.Precedence
	if verdict == policyTypes.Pass {
		passPrecedence = tierLastPriority.ToPassPrecedence()
	}

	return newPortNetworkPolicyRule(verdict, precedence, passPrecedence)
}

func isEmptyRuleButPrecedence(rule *cilium.PortNetworkPolicyRule) bool {
	return rule.Verdict == nil && rule.RemotePolicies == nil &&
		rule.Name == "" && rule.ProxyId == 0 && rule.L7Proto == "" && rule.L7 == nil &&
		rule.DownstreamTlsContext == nil && rule.UpstreamTlsContext == nil &&
		rule.ServerNames == nil
}

// isEmptyRule returns true if the rule has all its values as zero values.
func isEmptyRule(rule *cilium.PortNetworkPolicyRule) bool {
	return rule.Precedence == 0 && isEmptyRuleButPrecedence(rule)
}

func newPortNetworkPolicyRule(verdict policyTypes.Verdict, precedence, passPrecedence policyTypes.Precedence) *cilium.PortNetworkPolicyRule {
	r := &cilium.PortNetworkPolicyRule{
		Precedence: uint32(precedence),
	}
	if verdict == policyTypes.Deny {
		r.Verdict = DenyVerdict
	}
	if verdict == policyTypes.Pass {
		r.Verdict = &cilium.PortNetworkPolicyRule_PassPrecedence{
			PassPrecedence: uint32(passPrecedence),
		}
	}
	// r.RemotePolicies intentionally left empty (matches all peers)
	return r
}

func GetCiliumHttpFilter(accessLogPath string) *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "cilium.l7policy",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: ToAny(&cilium.L7Policy{
				AccessLogPath:  accessLogPath,
				Denied_403Body: option.Config.HTTP403Message,
			}),
		},
	}
}

func GetUpstreamCodecFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "envoy.filters.http.upstream_codec",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: ToAny(&envoy_upstream_codec.UpstreamCodec{}),
		},
	}
}

func GetHttpFilterChainProto(clusterName string, tls bool, isIngress bool, accessLogPath string, config xdsServerConfig) *envoy_config_listener.FilterChain {
	requestTimeout := int64(config.httpRequestTimeout)       // seconds
	idleTimeout := int64(config.httpIdleTimeout)             // seconds
	maxGRPCTimeout := int64(config.httpMaxGRPCTimeout)       // seconds
	streamIdleTimeout := int64(config.httpStreamIdleTimeout) // seconds
	numRetries := uint32(config.httpRetryCount)
	retryTimeout := int64(config.httpRetryTimeout) // seconds
	xffNumTrustedHops := config.proxyXffNumTrustedHopsEgress
	if isIngress {
		xffNumTrustedHops = config.proxyXffNumTrustedHopsIngress
	}

	hcmConfig := &envoy_config_http.HttpConnectionManager{
		StatPrefix: "proxy",
		UpgradeConfigs: []*envoy_config_http.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
		UseRemoteAddress:  &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:     true,
		XffNumTrustedHops: xffNumTrustedHops,
		HttpFilters: []*envoy_config_http.HttpFilter{
			GetCiliumHttpFilter(accessLogPath),
			{
				Name: "envoy.filters.http.router",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: ToAny(&envoy_extensions_filters_http_router_v3.Router{}),
				},
			},
		},
		InternalAddressConfig: &envoy_config_http.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  GetInternalListenerCIDRs(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()),
		},
		StreamIdleTimeout: &durationpb.Duration{Seconds: streamIdleTimeout}, // 0 == disabled
		RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route.RouteConfiguration{
				VirtualHosts: []*envoy_config_route.VirtualHost{{
					Name:    "default_route",
					Domains: []string{"*"},
					Routes: []*envoy_config_route.Route{{
						Match: &envoy_config_route.RouteMatch{
							PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"},
							Grpc:          &envoy_config_route.RouteMatch_GrpcRouteMatchOptions{},
						},
						Action: &envoy_config_route.Route_Route{
							Route: &envoy_config_route.RouteAction{
								ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout: &durationpb.Duration{Seconds: requestTimeout},
								MaxStreamDuration: &envoy_config_route.RouteAction_MaxStreamDuration{
									GrpcTimeoutHeaderMax: &durationpb.Duration{Seconds: maxGRPCTimeout},
								},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrapperspb.UInt32Value{Value: numRetries},
									PerTryTimeout: &durationpb.Duration{Seconds: retryTimeout},
								},
							},
						},
					}, {
						Match: &envoy_config_route.RouteMatch{
							PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: "/"},
						},
						Action: &envoy_config_route.Route_Route{
							Route: &envoy_config_route.RouteAction{
								ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{
									Cluster: clusterName,
								},
								Timeout: &durationpb.Duration{Seconds: requestTimeout},
								// IdleTimeout: &durationpb.Duration{Seconds: idleTimeout},
								RetryPolicy: &envoy_config_route.RetryPolicy{
									RetryOn:       "5xx",
									NumRetries:    &wrapperspb.UInt32Value{Value: numRetries},
									PerTryTimeout: &durationpb.Duration{Seconds: retryTimeout},
								},
							},
						},
					}},
				}},
			},
		},
	}

	if config.httpNormalizePath {
		hcmConfig.NormalizePath = &wrapperspb.BoolValue{Value: true}
		hcmConfig.MergeSlashes = true
		hcmConfig.PathWithEscapedSlashesAction = envoy_config_http.HttpConnectionManager_UNESCAPE_AND_REDIRECT
	}

	// Idle timeout can only be specified if non-zero
	if idleTimeout > 0 {
		hcmConfig.GetRouteConfig().VirtualHosts[0].Routes[1].GetRoute().IdleTimeout = &durationpb.Duration{Seconds: idleTimeout}
	}

	chain := &envoy_config_listener.FilterChain{
		Filters: []*envoy_config_listener.Filter{{
			Name: "cilium.network",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: ToAny(&cilium.NetworkFilter{}),
			},
		}, {
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: ToAny(hcmConfig),
			},
		}},
	}

	if tls {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			TransportProtocol: "tls",
		}
		chain.TransportSocket = &envoy_config_core.TransportSocket{
			Name: "cilium.tls_wrapper",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: ToAny(&cilium.DownstreamTlsWrapperContext{}),
			},
		}
	}

	return chain
}

// GetTcpFilterChainProto creates a TCP filter chain with the Cilium network filter.
func GetTcpFilterChainProto(clusterName string, tls bool, accessLogPath string) *envoy_config_listener.FilterChain {
	var filters []*envoy_config_listener.Filter

	// 1. Add Cilium Network filter.
	ciliumConfig := &cilium.NetworkFilter{
		AccessLogPath: accessLogPath,
	}

	filters = append(filters, &envoy_config_listener.Filter{
		Name: "cilium.network",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: ToAny(ciliumConfig),
		},
	})

	// 2. Add the TCP proxy filter.
	filters = append(filters, &envoy_config_listener.Filter{
		Name: "envoy.filters.network.tcp_proxy",
		ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: ToAny(&envoy_config_tcp.TcpProxy{
				StatPrefix: "tcp_proxy",
				ClusterSpecifier: &envoy_config_tcp.TcpProxy_Cluster{
					Cluster: clusterName,
				},
			}),
		},
	})

	chain := &envoy_config_listener.FilterChain{
		Filters: filters,
	}

	if tls {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			TransportProtocol: "tls",
		}
		chain.TransportSocket = &envoy_config_core.TransportSocket{
			Name: "cilium.tls_wrapper",
			ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
				TypedConfig: ToAny(&cilium.DownstreamTlsWrapperContext{}),
			},
		}
	} else {
		chain.FilterChainMatch = &envoy_config_listener.FilterChainMatch{
			// must have transport match for non-TLS,
			// otherwise TLS inspector will be automatically inserted
			TransportProtocol: "raw_buffer",
		}
	}

	return chain
}
