package xdsnew

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_upstream_codec "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/pkg/container/versioned"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// allowAllPortNetworkPolicy is a PortNetworkPolicy that allows all traffic
	// to any L4 port.
	allowAllTCPPortNetworkPolicyNew = &cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		Protocol: envoy_config_core.SocketAddress_TCP,
	}
	allowAllPortNetworkPolicyNew = []*cilium.PortNetworkPolicy{
		// Allow all TCP traffic to any port.
		allowAllTCPPortNetworkPolicyNew,
		// Allow all UDP/SCTP traffic to any port.
		// UDP/SCTP rules not sent to Envoy for now.
	}
)

const (
	CiliumXDSClusterName = "xds-grpc-cilium"
)

type Resource interface {
	proto.Message
}

func ToAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}

func GetCiliumHttpFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "cilium.l7policy",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: ToAny(&cilium.L7Policy{
				AccessLogPath:  util.GetAccessLogSocketPath(util.GetSocketDir(option.Config.RunDir)),
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

func getPublicListenerAddress(port uint16, ipv4, ipv6 bool) *envoy_config_core.Address {
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

func getListenerFilter(isIngress bool, useOriginalSourceAddr bool, proxyPort uint16, lingerConfig int) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                isIngress,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   false,
		ProxyId:                  uint32(proxyPort),
		IpcacheName:              ipcache.Name,
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

func getL7Rules(l7Rules []api.PortRuleL7, l7Proto string) *cilium.L7NetworkPolicyRules {
	allowRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	denyRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	useEnvoyMetadataMatcher := strings.HasPrefix(l7Proto, "envoy.")

	for _, l7 := range l7Rules {
		if useEnvoyMetadataMatcher {
			envoyFilterName := l7Proto
			rule := &cilium.L7NetworkPolicyRule{MetadataRule: make([]*envoy_type_matcher.MetadataMatcher, 0, len(l7))}
			denyRule := false
			for k, v := range l7 {
				switch k {
				case "action":
					switch v {
					case "deny":
						denyRule = true
					}
				default:
					// map key to path segments and value to value matcher
					// For now only one path segment is allowed
					segments := strings.Split(k, "/")
					var path []*envoy_type_matcher.MetadataMatcher_PathSegment
					for _, key := range segments {
						path = append(path, &envoy_type_matcher.MetadataMatcher_PathSegment{
							Segment: &envoy_type_matcher.MetadataMatcher_PathSegment_Key{Key: key},
						})
					}
					var value *envoy_type_matcher.ValueMatcher
					if len(v) == 0 {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_PresentMatch{
								PresentMatch: true,
							},
						}
					} else {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_ListMatch{
								ListMatch: &envoy_type_matcher.ListMatcher{
									MatchPattern: &envoy_type_matcher.ListMatcher_OneOf{
										OneOf: &envoy_type_matcher.ValueMatcher{
											MatchPattern: &envoy_type_matcher.ValueMatcher_StringMatch{
												StringMatch: &envoy_type_matcher.StringMatcher{
													MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
														Exact: v,
													},
													IgnoreCase: false,
												},
											},
										},
									},
								},
							},
						}
					}
					rule.MetadataRule = append(rule.MetadataRule, &envoy_type_matcher.MetadataMatcher{
						Filter: envoyFilterName,
						Path:   path,
						Value:  value,
					})
				}
			}
			if denyRule {
				denyRules = append(denyRules, rule)
			} else {
				allowRules = append(allowRules, rule)
			}
		} else {
			// proxylib go extension key/value policy
			rule := &cilium.L7NetworkPolicyRule{Rule: make(map[string]string, len(l7))}
			maps.Copy(rule.Rule, l7)
			allowRules = append(allowRules, rule)
		}
	}

	rules := &cilium.L7NetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.L7AllowRules = allowRules
	}
	if len(denyRules) > 0 {
		rules.L7DenyRules = denyRules
	}
	return rules
}

func getKafkaL7Rules(l7Rules []kafka.PortRule) *cilium.KafkaNetworkPolicyRules {
	allowRules := make([]*cilium.KafkaNetworkPolicyRule, 0, len(l7Rules))
	for _, kr := range l7Rules {
		rule := &cilium.KafkaNetworkPolicyRule{
			ApiVersion: kr.GetAPIVersion(),
			ApiKeys:    kr.GetAPIKeys(),
			ClientId:   kr.ClientID,
			Topic:      kr.Topic,
		}
		allowRules = append(allowRules, rule)
	}

	rules := &cilium.KafkaNetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.KafkaRules = allowRules
	}
	return rules
}

var CiliumXDSConfigSourceNew = &envoy_config_core.ConfigSource{
	InitialFetchTimeout: &durationpb.Duration{Seconds: 30},
	ResourceApiVersion:  envoy_config_core.ApiVersion_V3,
	ConfigSourceSpecifier: &envoy_config_core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &envoy_config_core.ApiConfigSource{
			ApiType:                   envoy_config_core.ApiConfigSource_GRPC,
			TransportApiVersion:       envoy_config_core.ApiVersion_V3,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*envoy_config_core.GrpcService{
				{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: CiliumXDSClusterName,
						},
					},
				},
			},
		},
	},
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

	// Host proxy uses "127.0.0.1" as the nodeID
	nodeIDs = append(nodeIDs, "127.0.0.1")
	// Require additional ACK from proxylib if policy has proxylib redirects
	// Note that if a previous policy had a proxylib redirect and this one does not,
	// we only wait for the ACK from the main Envoy node ID.
	if policy.HasProxylibRedirect() {
		// Proxylib uses "127.0.0.2" as the nodeID
		nodeIDs = append(nodeIDs, "127.0.0.2")
	}
	return nodeIDs
}

func GetNetworkPolicy(ep endpoint.EndpointUpdater, names []string, l4Policy *policy.L4Policy,
	ingressPolicyEnforced, egressPolicyEnforced, useFullTLSContext, useSDS bool, policySecretsNamespace string,
) *cilium.NetworkPolicy {
	p := &cilium.NetworkPolicy{
		EndpointIps:      names,
		EndpointId:       ep.GetID(),
		ConntrackMapName: "global",
	}

	var ingressMap policy.L4PolicyMap
	var egressMap policy.L4PolicyMap
	if l4Policy != nil {
		ingressMap = l4Policy.Ingress.PortRules
		egressMap = l4Policy.Egress.PortRules
	}
	p.IngressPerPortPolicies = GetDirectionNetworkPolicy(ep, ingressMap, ingressPolicyEnforced, useFullTLSContext, useSDS, "ingress", policySecretsNamespace)
	p.EgressPerPortPolicies = GetDirectionNetworkPolicy(ep, egressMap, egressPolicyEnforced, useFullTLSContext, useSDS, "egress", policySecretsNamespace)

	return p
}

func GetPortNetworkPolicyRule(ep endpoint.EndpointUpdater, version *versioned.VersionHandle, sel policy.CachedSelector, l7Rules *policy.PerSelectorPolicy, useFullTLSContext, useSDS bool, policySecretsNamespace string) (*cilium.PortNetworkPolicyRule, bool) {
	r := &cilium.PortNetworkPolicyRule{
		Deny: l7Rules.GetDeny(),
	}

	wildcard := sel.IsWildcard()

	// Optimize the policy if the endpoint selector is a wildcard by
	// keeping remote policies list empty to match all remote policies.
	if !wildcard {
		selections := sel.GetSelections(version)

		// No remote policies would match this rule. Discard it.
		if len(selections) == 0 {
			return nil, true
		}

		r.RemotePolicies = selections.AsUint32Slice()
	}

	if l7Rules == nil {
		// L3/L4 only rule, everything in L7 is allowed && no TLS
		return r, true
	}

	// Deny rules never have L7 rules and can not be short-circuited (i.e., rule evaluation
	// after an allow rule must continue to find the possibly applicable deny rule).
	if l7Rules.GetDeny() {
		return r, false
	}

	// Pass redirect port as proxy ID if the rule has an explicit listener reference.
	// This makes this rule to be ignored on any listener that does not have a matching
	// proxy ID.
	if l7Rules.Listener != "" {
		r.ProxyId = uint32(ep.GetListenerProxyPort(l7Rules.Listener))
	}

	// If secret synchronization is disabled, policySecretsNamespace will be the empty string.
	//
	// In that case, useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well,
	// which can lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
	// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS.
	//
	// If secret synchronization is enabled, useFullTLSContext is unused, as SDS handling can handle Secrets with extra
	// keys correctly.
	if l7Rules.TerminatingTLS != nil {
		r.DownstreamTlsContext = toEnvoyTerminatingTLSContext(l7Rules.TerminatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}
	if l7Rules.OriginatingTLS != nil {
		r.UpstreamTlsContext = toEnvoyOriginatingTLSContext(l7Rules.OriginatingTLS, policySecretsNamespace, useSDS, useFullTLSContext)
	}

	if len(l7Rules.ServerNames) > 0 {
		r.ServerNames = make([]string, 0, len(l7Rules.ServerNames))
		for sni := range l7Rules.ServerNames {
			r.ServerNames = append(r.ServerNames, sni)
		}
		slices.Sort(r.ServerNames)
	}

	// Assume none of the rules have side-effects so that rule evaluation can
	// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
	// is set to 'false' below if any rules with side effects are encountered,
	// causing all the applicable rules to be evaluated instead.
	canShortCircuit := true
	switch l7Rules.L7Parser {
	case policy.ParserTypeHTTP:
		// 'r.L7' is an interface which must not be set to a typed 'nil',
		// so check if we have any rules
		if len(l7Rules.HTTP) > 0 {
			// Use L7 rules computed earlier?
			var httpRules *cilium.HttpNetworkPolicyRules
			if l7Rules.EnvoyHTTPRules() != nil {
				httpRules = l7Rules.EnvoyHTTPRules()
				canShortCircuit = l7Rules.CanShortCircuit()
			} else {
				httpRules, canShortCircuit = s.l7RulesTranslator.GetEnvoyHTTPRules(&l7Rules.L7Rules, "")
			}
			r.L7 = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: httpRules,
			}
		}

	case policy.ParserTypeKafka:
		// Kafka is implemented as an Envoy Go Extension
		if len(l7Rules.Kafka) > 0 {
			// L7 rules are not sorted
			r.L7Proto = l7Rules.L7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_KafkaRules{
				KafkaRules: getKafkaL7Rules(l7Rules.Kafka),
			}
		}

	case policy.ParserTypeDNS:
		// TODO: Support DNS. For now, just ignore any DNS L7 rule.

	default:
		// Assume unknown parser types use a Key-Value Pair policy
		if len(l7Rules.L7) > 0 {
			// L7 rules are not sorted
			r.L7Proto = l7Rules.L7Parser.String()
			r.L7 = &cilium.PortNetworkPolicyRule_L7Rules{
				L7Rules: getL7Rules(l7Rules.L7, r.L7Proto),
			}
		}
	}

	return r, canShortCircuit
}

// getWildcardNetworkPolicyRules returns the rules for port 0, which
// will be considered after port-specific rules.
func GetWildcardNetworkPolicyRules(version *versioned.VersionHandle, selectors policy.L7DataMap) (rules []*cilium.PortNetworkPolicyRule) {
	// selections are pre-sorted, so sorting is only needed if merging selections from multiple selectors
	if len(selectors) == 1 {
		for sel, l7 := range selectors {
			if sel.IsWildcard() {
				return append(rules, &cilium.PortNetworkPolicyRule{
					Deny: l7.GetDeny(),
				})
			}
			selections := sel.GetSelections(version)
			if len(selections) == 0 {
				// No remote policies would match this rule. Discard it.
				return nil
			}
			return append(rules, &cilium.PortNetworkPolicyRule{
				Deny:           l7.GetDeny(),
				RemotePolicies: selections.AsUint32Slice(),
			})
		}
	}

	// Get selections for each selector and count how many there are
	allowSlices := make([][]uint32, 0, len(selectors))
	denySlices := make([][]uint32, 0, len(selectors))
	wildcardAllowFound := false
	wildcardDenyFound := false
	var allowCount, denyCount int
	for sel, l7 := range selectors {
		if sel.IsWildcard() {
			if l7.GetDeny() {
				wildcardDenyFound = true
				break
			} else {
				wildcardAllowFound = true
			}
		}

		if l7.IsRedirect() {
			// Issue a warning if this port-0 rule is a redirect.
			// Deny rules don't support L7 therefore for the deny case
			// l7.IsRedirect() will always return false.
			s.logger.Warn("L3-only rule for selector surprisingly requires proxy redirection!", logfields.Selector, sel)
		}

		selections := sel.GetSelections(version)
		if len(selections) == 0 {
			continue
		}
		if l7.GetDeny() {
			denyCount += len(selections)
			denySlices = append(denySlices, selections.AsUint32Slice())
		} else {
			allowCount += len(selections)
			allowSlices = append(allowSlices, selections.AsUint32Slice())
		}
	}

	if wildcardDenyFound {
		return append(rules, &cilium.PortNetworkPolicyRule{
			Deny: true,
		})
	}
	if len(denySlices) > 0 {
		// allocate slice and copy selected identities
		denies := make([]uint32, 0, denyCount)
		for _, selections := range denySlices {
			denies = append(denies, selections...)
		}
		slices.Sort(denies)
		denies = slices.Compact(denies)

		rules = append(rules, &cilium.PortNetworkPolicyRule{
			Deny:           true,
			RemotePolicies: denies,
		})
	}

	if wildcardAllowFound {
		rules = append(rules, &cilium.PortNetworkPolicyRule{})
	} else if len(allowSlices) > 0 {
		// allocate slice and copy selected identities
		allows := make([]uint32, 0, allowCount)
		for _, selections := range allowSlices {
			allows = append(allows, selections...)
		}
		slices.Sort(allows)
		allows = slices.Compact(allows)

		rules = append(rules, &cilium.PortNetworkPolicyRule{
			RemotePolicies: allows,
		})
	}

	return rules
}

func GetDirectionNetworkPolicy(ep endpoint.EndpointUpdater, l4Policy policy.L4PolicyMap, policyEnforced bool, useFullTLSContext, useSDS bool, dir string, policySecretsNamespace string) []*cilium.PortNetworkPolicy {
	// TODO: integrate visibility with enforced policy
	if !policyEnforced {
		// Always allow all ports
		return []*cilium.PortNetworkPolicy{allowAllTCPPortNetworkPolicyNew}
	}

	if l4Policy == nil || l4Policy.Len() == 0 {
		return nil
	}

	version := ep.GetPolicyVersionHandle()

	PerPortPolicies := make([]*cilium.PortNetworkPolicy, 0, l4Policy.Len())
	wildcardAllowAll := false
	wildcardDenyAll := false

	// Check for wildcard port policy first
	addWildcardRules := func(l4 *policy.L4Filter) {
		if l4 == nil {
			return
		}

		wildcardRules := GetWildcardNetworkPolicyRules(version, l4.PerSelectorPolicies)

		for _, rule := range wildcardRules {
			s.logger.Debug("Wildcard PortNetworkPolicyRule matching remote IDs",
				logfields.EndpointID, ep.GetID(),
				logfields.Version, version,
				logfields.TrafficDirection, dir,
				logfields.Port, "0",
				logfields.IsDeny, rule.Deny,
				logfields.PolicyID, rule.RemotePolicies,
			)

			if len(rule.RemotePolicies) == 0 {
				if rule.Deny {
					// Got an deny-all rule, which short-circuits all of
					// the other rules.
					wildcardDenyAll = true
				} else {
					// Got an allow-all rule, which can short-circuit all of
					// the other rules.
					wildcardAllowAll = true
				}
			}
		}

		if len(wildcardRules) > 0 {
			PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
				Port:     0,
				EndPort:  0,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules:    envoypolicy.SortPortNetworkPolicyRules(wildcardRules),
			})
		} else {
			s.logger.Debug("Skipping wildcard PortNetworkPolicy due to no matching remote identities",
				logfields.EndpointID, ep.GetID(),
				logfields.TrafficDirection, dir,
				logfields.Port, "0",
			)
		}
	}

	addWildcardRules(l4Policy.ExactLookup("0", 0, u8proto.ANY.String()))
	addWildcardRules(l4Policy.ExactLookup("0", 0, u8proto.TCP.String()))

	if !wildcardDenyAll {
		l4Policy.ForEach(func(l4 *policy.L4Filter) bool {
			var protocol envoy_config_core.SocketAddress_Protocol
			switch l4.U8Proto {
			case u8proto.TCP, u8proto.ANY:
				protocol = envoy_config_core.SocketAddress_TCP
			default:
				// Other protocol rules not sent to Envoy for now.
				return true
			}

			port := l4.Port
			if port == 0 && l4.PortName != "" {
				port = ep.GetNamedPort(l4.Ingress, l4.PortName, l4.U8Proto)
			}

			// Skip if a named port can not be resolved (yet)
			// wildcard port already taken care of above
			if port == 0 {
				return true
			}

			rules := make([]*cilium.PortNetworkPolicyRule, 0, len(l4.PerSelectorPolicies))

			// Assume none of the rules have side-effects so that rule evaluation can
			// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
			// is set to 'false' below if any rules with side effects are encountered,
			// causing all the applicable rules to be evaluated instead.
			// Also set to 'false' if any deny rules exist.
			canShortCircuit := true
			var allowAllRule *cilium.PortNetworkPolicyRule
			var denyAllRule *cilium.PortNetworkPolicyRule

			for sel, l7 := range l4.PerSelectorPolicies {
				rule, cs := GetPortNetworkPolicyRule(ep, version, sel, l7, useFullTLSContext, useSDS, policySecretsNamespace)
				if rule != nil {
					if !cs {
						canShortCircuit = false
					}

					s.logger.Debug("PortNetworkPolicyRule matching remote IDs",
						logfields.EndpointID, ep.GetID(),
						logfields.Version, version,
						logfields.TrafficDirection, dir,
						logfields.Port, port,
						logfields.ProxyPort, rule.ProxyId,
						logfields.PolicyID, rule.RemotePolicies,
						logfields.ServerNames, rule.ServerNames,
					)

					if rule.Deny && len(rule.RemotePolicies) == 0 {
						// Got an deny-all rule, which short-circuits all of
						// the other rules on this port.
						denyAllRule = rule
						rules = []*cilium.PortNetworkPolicyRule{denyAllRule}
						break
					}

					if len(rule.RemotePolicies) == 0 && rule.L7 == nil && rule.DownstreamTlsContext == nil && rule.UpstreamTlsContext == nil && len(rule.ServerNames) == 0 && rule.ProxyId == 0 {
						// Got an allow-all rule, which can short-circuit all of
						// the other rules on this port.
						allowAllRule = rule
					}
					rules = append(rules, rule)
				}
			}

			// No rule for this port matches any remote identity.
			// In this case, just don't generate any PortNetworkPolicy for this
			// port.
			if len(rules) == 0 {
				s.logger.Debug("Skipping PortNetworkPolicy due to no matching remote identities",
					logfields.EndpointID, ep.GetID(),
					logfields.TrafficDirection, dir,
					logfields.Port, port,
				)
				return true
			}

			// Short-circuit rules if a rule allows all and all other rules can be short-circuited
			if denyAllRule == nil && canShortCircuit {
				if wildcardAllowAll {
					s.logger.Debug("Short circuiting HTTP rules due to wildcard allowing all and no other rules needing attention",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, port,
					)
					return true
				}
				if allowAllRule != nil {
					s.logger.Debug("Short circuiting HTTP rules due to rule allowing all and no other rules needing attention",
						logfields.EndpointID, ep.GetID(),
						logfields.TrafficDirection, dir,
						logfields.Port, port,
					)
					rules = nil
				}
			}

			// NPDS supports port ranges.
			PerPortPolicies = append(PerPortPolicies, &cilium.PortNetworkPolicy{
				Port:     uint32(port),
				EndPort:  uint32(l4.EndPort),
				Protocol: protocol,
				Rules:    envoypolicy.SortPortNetworkPolicyRules(rules),
			})
			return true
		})
	}
	if len(PerPortPolicies) == 0 || len(PerPortPolicies) == 0 && wildcardAllowAll {
		return nil
	}

	return envoypolicy.SortPortNetworkPolicies(PerPortPolicies)
}
