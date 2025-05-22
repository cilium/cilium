// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
)

type EnvoyL7RulesTranslator interface {
	GetEnvoyHTTPRules(l7Rules *policyapi.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool)
}

type envoyL7RulesTranslator struct {
	logger        *slog.Logger
	secretManager certificatemanager.SecretManager
}

func NewEnvoyL7RulesTranslator(logger *slog.Logger, secretManager certificatemanager.SecretManager) EnvoyL7RulesTranslator {
	return &envoyL7RulesTranslator{
		logger:        logger,
		secretManager: secretManager,
	}
}

func (r *envoyL7RulesTranslator) GetEnvoyHTTPRules(l7Rules *policyapi.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	if len(l7Rules.HTTP) > 0 { // Just cautious. This should never be false.
		// Assume none of the rules have side-effects so that rule evaluation can
		// be stopped as soon as the first allowing rule is found. 'canShortCircuit'
		// is set to 'false' below if any rules with side effects are encountered,
		// causing all the applicable rules to be evaluated instead.
		canShortCircuit := true
		httpRules := make([]*cilium.HttpNetworkPolicyRule, 0, len(l7Rules.HTTP))
		for _, l7 := range l7Rules.HTTP {
			rule, cs := r.getHTTPRule(&l7, ns)
			httpRules = append(httpRules, rule)
			if !cs {
				canShortCircuit = false
			}
		}
		SortHTTPNetworkPolicyRules(httpRules)
		return &cilium.HttpNetworkPolicyRules{
			HttpRules: httpRules,
		}, canShortCircuit
	}

	return nil, true
}

func (r *envoyL7RulesTranslator) getHTTPRule(h *policyapi.PortRuleHTTP, ns string) (*cilium.HttpNetworkPolicyRule, bool) {
	// Count the number of header matches we need
	cnt := len(h.Headers) + len(h.HeaderMatches)
	if h.Path != "" {
		cnt++
	}
	if h.Method != "" {
		cnt++
	}
	if h.Host != "" {
		cnt++
	}

	headers := make([]*envoy_config_route.HeaderMatcher, 0, cnt)
	if h.Path != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":path",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Path,
						},
					},
				},
			},
		})
	}
	if h.Method != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":method",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Method,
						},
					},
				},
			},
		})
	}
	if h.Host != "" {
		headers = append(headers, &envoy_config_route.HeaderMatcher{
			Name: ":authority",
			HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher.StringMatcher{
					MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher.RegexMatcher{
							Regex: h.Host,
						},
					},
				},
			},
		})
	}
	for _, hdr := range h.Headers {
		strs := strings.SplitN(hdr, " ", 2)
		if len(strs) == 2 {
			// Remove ':' in "X-Key: true"
			key := strings.TrimRight(strs[0], ":")
			// Header presence and matching (literal) value needed.
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name: key,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher.StringMatcher{
						MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
							Exact: strs[1],
						},
					},
				},
			})
		} else {
			// Only header presence needed
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name:                 strs[0],
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
			})
		}
	}

	headerMatches := make([]*cilium.HeaderMatch, 0, len(h.HeaderMatches))
	for _, hdr := range h.HeaderMatches {
		var mismatch_action cilium.HeaderMatch_MismatchAction
		switch hdr.Mismatch {
		case policyapi.MismatchActionLog:
			mismatch_action = cilium.HeaderMatch_CONTINUE_ON_MISMATCH
		case policyapi.MismatchActionAdd:
			mismatch_action = cilium.HeaderMatch_ADD_ON_MISMATCH
		case policyapi.MismatchActionDelete:
			mismatch_action = cilium.HeaderMatch_DELETE_ON_MISMATCH
		case policyapi.MismatchActionReplace:
			mismatch_action = cilium.HeaderMatch_REPLACE_ON_MISMATCH
		default:
			mismatch_action = cilium.HeaderMatch_FAIL_ON_MISMATCH
		}
		// Fetch the secret
		value, err := r.getSecretString(hdr, ns)
		if err != nil {
			r.logger.Warn("Failed fetching K8s Secret, header match will fail", logfields.Error, err)
			// Envoy treats an empty exact match value as matching ANY value; adding
			// InvertMatch: true here will cause this rule to NEVER match.
			headers = append(headers, &envoy_config_route.HeaderMatcher{
				Name: hdr.Name,
				HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher.StringMatcher{
						MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
							Exact: "",
						},
					},
				},
				InvertMatch: true,
			})
		} else if value != "" {
			// Inline value provided.
			// Header presence and matching (literal) value needed.
			if mismatch_action == cilium.HeaderMatch_FAIL_ON_MISMATCH {
				// fail on mismatch gets converted for regular HeaderMatcher
				headers = append(headers, &envoy_config_route.HeaderMatcher{
					Name: hdr.Name,
					HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
						StringMatch: &envoy_type_matcher.StringMatcher{
							MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
								Exact: value,
							},
						},
					},
				})
			} else {
				r.logger.Debug("HeaderMatches: Adding header", logfields.Name, hdr.Name)
				headerMatches = append(headerMatches, &cilium.HeaderMatch{
					MismatchAction: mismatch_action,
					Name:           hdr.Name,
					Value:          value,
				})
			}
		} else if hdr.Secret == nil {
			// No inline value and no secret.
			// Header presence for FAIL_ON_MISMSTCH or matching empty value otherwise needed.
			if mismatch_action == cilium.HeaderMatch_FAIL_ON_MISMATCH {
				// Only header presence needed
				headers = append(headers, &envoy_config_route.HeaderMatcher{
					Name:                 hdr.Name,
					HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
				})
			} else {
				r.logger.Debug("HeaderMatches: Adding header for an empty value", logfields.Name, hdr.Name)
				headerMatches = append(headerMatches, &cilium.HeaderMatch{
					MismatchAction: mismatch_action,
					Name:           hdr.Name,
				})
			}
		} else {
			// A secret is set, so we transform to an SDS value.
			// cilium-envoy takes care of treating this as a presence match if the
			// secret exists with an empty value.
			r.logger.Debug("HeaderMatches: Adding header because SDS value is required", logfields.Name, hdr.Name)
			headerMatches = append(headerMatches, &cilium.HeaderMatch{
				MismatchAction: mismatch_action,
				Name:           hdr.Name,
				ValueSdsSecret: namespacedNametoSyncedSDSSecretName(types.NamespacedName{
					Namespace: hdr.Secret.Namespace,
					Name:      hdr.Secret.Name,
				}, r.secretManager.GetSecretSyncNamespace()),
			})
		}
	}
	if len(headers) == 0 {
		headers = nil
	} else {
		SortHeaderMatchers(headers)
	}
	if len(headerMatches) == 0 {
		headerMatches = nil
	} else {
		// Optimally we should sort the headerMatches to avoid
		// updating the policy if only the order of the rules
		// has changed. Right now, when 'headerMatches' is a
		// slice (rather than a map) the order only changes if
		// the order of the rules in the imported policies
		// changes, so there is minimal likelihood of
		// unnecessary policy updates.

		// SortHeaderMatches(headerMatches)
	}

	return &cilium.HttpNetworkPolicyRule{Headers: headers, HeaderMatches: headerMatches}, len(headerMatches) == 0
}

func (r *envoyL7RulesTranslator) getSecretString(hdr *policyapi.HeaderMatch, ns string) (string, error) {
	value := ""
	var err error
	if hdr.Secret != nil {
		value, err = r.secretManager.GetSecretString(context.TODO(), hdr.Secret, ns)
	}
	// Only use Value if secret was not obtained
	if value == "" && hdr.Value != "" {
		value = hdr.Value
		if err != nil {
			r.logger.Debug("HeaderMatches: Using a default value due to k8s secret not being available", logfields.Error, err)
			err = nil
		}
	}

	return value, err
}

func namespacedNametoSyncedSDSSecretName(namespacedName types.NamespacedName, policySecretsNamespace string) string {
	if policySecretsNamespace == "" {
		return fmt.Sprintf("%s/%s", namespacedName.Namespace, namespacedName.Name)
	}
	return fmt.Sprintf("%s/%s-%s", policySecretsNamespace, namespacedName.Namespace, namespacedName.Name)
}
