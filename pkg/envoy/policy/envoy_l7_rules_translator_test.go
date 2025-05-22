// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/policy/api"
)

var PortRuleHTTP1 = &api.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2: value", "header1"},
}

var ExpectedHeaders1 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":authority",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "foo.cilium.io",
					},
				},
			},
		},
	},
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "GET",
					},
				},
			},
		},
	},
	{
		Name: ":path",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "/foo",
					},
				},
			},
		},
	},
	{
		Name:                 "header1",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true},
	},
	{
		Name: "header2",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
					Exact: "value",
				},
			},
		},
	},
}

var PortRuleHeaderMatchSecret = &api.PortRuleHTTP{
	HeaderMatches: []*api.HeaderMatch{
		{
			Mismatch: "",
			Name:     "VeryImportantHeader",
			Secret: &api.Secret{
				Name:      "secretName",
				Namespace: "cilium-secrets",
			},
		},
	},
}

var expectedHeadersPortRuleHeaderMatchSecretNilSecretManager = []*envoy_config_route.HeaderMatcher{
	{
		Name: "VeryImportantHeader",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
					Exact: "",
				},
			},
		},
		InvertMatch: true,
	},
}

var expectedHeadersPortRuleHeaderMatchInline = []*envoy_config_route.HeaderMatcher{
	{
		Name: "VeryImportantHeader",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
					Exact: "somevalue",
				},
			},
		},
	},
}

var expectedHeaderMatchesPortRuleHeaderMatchSDS = []*cilium.HeaderMatch{
	{
		Name:           "VeryImportantHeader",
		ValueSdsSecret: "cilium-secrets/secretName",
	},
}

var expectedHeadersPortRuleHeaderMatchSDS []*envoy_config_route.HeaderMatcher

var PortRuleHeaderMatchSecretLogOnMismatch = &api.PortRuleHTTP{
	HeaderMatches: []*api.HeaderMatch{
		{
			Mismatch: api.MismatchActionLog,
			Name:     "VeryImportantHeader",
			Secret: &api.Secret{
				Name:      "secretName",
				Namespace: "cilium-secrets",
			},
		},
	},
}

var expectedHeaderMatchesLogOnMismatchPortRuleHeaderMatchSDS = []*cilium.HeaderMatch{
	{
		Name:           "VeryImportantHeader",
		ValueSdsSecret: "cilium-secrets/secretName",
		MismatchAction: cilium.HeaderMatch_CONTINUE_ON_MISMATCH,
	},
}

func TestGetHTTPRule_NotFoundBySecretManager(t *testing.T) {
	translator := &envoyL7RulesTranslator{logger: hivetest.Logger(t), secretManager: certificatemanager.NewMockSecretManagerNotFound()}
	obtained, canShortCircuit := translator.getHTTPRule(PortRuleHTTP1, "")
	require.Equal(t, ExpectedHeaders1, obtained.Headers)
	require.True(t, canShortCircuit)

	result, canShortCircuit := translator.getHTTPRule(PortRuleHeaderMatchSecret, "")
	require.Equal(t, expectedHeadersPortRuleHeaderMatchSecretNilSecretManager, result.Headers)
	require.True(t, canShortCircuit)
}

func TestGetHTTPRule_Inline(t *testing.T) {
	translator := &envoyL7RulesTranslator{logger: hivetest.Logger(t), secretManager: certificatemanager.NewMockSecretManagerInline()}
	result, canShortCircuit := translator.getHTTPRule(PortRuleHeaderMatchSecret, "")
	require.Equal(t, expectedHeadersPortRuleHeaderMatchInline, result.Headers)
	require.True(t, canShortCircuit)
}

func TestGetHTTPRule_SDS(t *testing.T) {
	translator := &envoyL7RulesTranslator{logger: hivetest.Logger(t), secretManager: certificatemanager.NewMockSecretManagerSDS()}
	result, canShortCircuit := translator.getHTTPRule(PortRuleHeaderMatchSecret, "")
	require.Equal(t, expectedHeadersPortRuleHeaderMatchSDS, result.Headers)
	require.False(t, canShortCircuit)
	require.Equal(t, expectedHeaderMatchesPortRuleHeaderMatchSDS, result.HeaderMatches)

	result, canShortCircuit = translator.getHTTPRule(PortRuleHeaderMatchSecretLogOnMismatch, "")
	require.Nil(t, result.Headers)
	require.False(t, canShortCircuit)
	require.Equal(t, expectedHeaderMatchesLogOnMismatchPortRuleHeaderMatchSDS, result.HeaderMatches)
}
