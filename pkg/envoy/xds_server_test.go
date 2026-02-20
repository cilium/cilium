// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/envoy/test"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/spanstat"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

var (
	IPv4Addr = "10.1.1.1"

	ep = &test.ProxyUpdaterMock{
		Id:   1000,
		Ipv4: "10.0.0.1",
		Ipv6: "f00d::1",
	}
)

type listenerProxyUpdaterMock struct {
	*test.ProxyUpdaterMock
	listenerProxyPorts map[string]uint16
}

func (m *listenerProxyUpdaterMock) GetListenerProxyPort(listener string) uint16 {
	return m.listenerProxyPorts[listener]
}

func (m *listenerProxyUpdaterMock) PolicyDebug(string, ...any) {}

func (m *listenerProxyUpdaterMock) IsHost() bool { return false }

func (m *listenerProxyUpdaterMock) PreviousMapState() *policy.MapState { return nil }

func (m *listenerProxyUpdaterMock) RegenerateIfAlive(*regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

type dummyPolicyStats struct {
	waitingForPolicyRepository spanstat.SpanStat
	policyCalculation          spanstat.SpanStat
}

func (s *dummyPolicyStats) WaitingForPolicyRepository() *spanstat.SpanStat {
	return &s.waitingForPolicyRepository
}

func (s *dummyPolicyStats) SelectorPolicyCalculation() *spanstat.SpanStat {
	return &s.policyCalculation
}

var PortRuleHTTP1 = &api.PortRuleHTTP{
	Path:    "/foo",
	Method:  "GET",
	Host:    "foo.cilium.io",
	Headers: []string{"header2: value", "header1"},
}

var PortRuleHTTP2 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "PUT",
}

var PortRuleHTTP2HeaderMatch = &api.PortRuleHTTP{
	Path:          "/bar",
	Method:        "PUT",
	HeaderMatches: []*api.HeaderMatch{{Mismatch: api.MismatchActionReplace, Name: "user-agent", Value: "dummy-agent"}},
}

var PortRuleHTTP3 = &api.PortRuleHTTP{
	Path:   "/bar",
	Method: "GET",
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

var ExpectedHeaders2 = []*envoy_config_route.HeaderMatcher{
	{
		Name: ":method",
		HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher.StringMatcher{
				MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher.RegexMatcher{
						Regex: "PUT",
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
						Regex: "/bar",
					},
				},
			},
		},
	},
}

var ExpectedHeaderMatches2 = []*cilium.HeaderMatch{
	{
		MismatchAction: cilium.HeaderMatch_REPLACE_ON_MISMATCH,
		Name:           "user-agent",
		Value:          "dummy-agent",
	},
}

var ExpectedHeaders3 = []*envoy_config_route.HeaderMatcher{
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
						Regex: "/bar",
					},
				},
			},
		},
	},
}

var (
	dummySelectorCacheUser = &testpolicy.DummySelectorCacheUser{}

	IdentityCache = identity.IdentityMap{
		1001: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
		1002: labels.LabelArray{
			labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
			labels.NewLabel("version", "v2", labels.LabelSourceK8s),
		},
		1003: labels.LabelArray{
			labels.NewLabel("app", "cassandra", labels.LabelSourceK8s),
			labels.NewLabel("version", "v1", labels.LabelSourceK8s),
		},
	}
	// slogloggercheck: the default logger is enough for tests.
	testSelectorCache = policy.NewSelectorCache(logging.DefaultSlogLogger, IdentityCache)

	wildcardCachedSelector, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, api.WildcardEndpointSelector)

	EndpointSelector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
	)
	cachedSelector1, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, EndpointSelector1)

	// EndpointSelector1 with FromRequires("k8s:version=v2") folded in
	RequiresV2Selector1 = api.NewESFromLabels(
		labels.NewLabel("app", "etcd", labels.LabelSourceK8s),
		labels.NewLabel("version", "v2", labels.LabelSourceK8s),
	)
	cachedRequiresV2Selector1, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, RequiresV2Selector1)

	EndpointSelector2 = api.NewESFromLabels(
		labels.NewLabel("version", "v1", labels.LabelSourceK8s),
	)
	cachedSelector2, _ = testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, EndpointSelector2)
)

var L7Rules12 = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}},
}

var denyPerSelectorPolicy = &policy.PerSelectorPolicy{Verdict: types.Deny}

var L7Rules12Deny = &policy.PerSelectorPolicy{
	Verdict:  types.Deny,
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2}},
}

var L7Rules12HeaderMatch = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1, *PortRuleHTTP2HeaderMatch}},
}

var L7Rules1 = &policy.PerSelectorPolicy{
	L7Parser: policy.ParserTypeHTTP,
	L7Rules:  api.L7Rules{HTTP: []api.PortRuleHTTP{*PortRuleHTTP1}},
}

var ExpectedHttpRule1 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule12 = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedHttpRule122HeaderMatch = &cilium.PortNetworkPolicyRule_HttpRules{
	HttpRules: &cilium.HttpNetworkPolicyRules{
		HttpRules: []*cilium.HttpNetworkPolicyRule{
			{Headers: ExpectedHeaders2, HeaderMatches: ExpectedHeaderMatches2},
			{Headers: ExpectedHeaders1},
		},
	},
}

var ExpectedPortNetworkPolicyRule12 = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule12Precedence = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule12Deny = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxDenyPrecedence),
	Verdict:        DenyVerdict,
	RemotePolicies: []uint32{1001, 1002},
}

var ExpectedPortNetworkPolicyRule12DenyPrecedence = &cilium.PortNetworkPolicyRule{
	Verdict:        DenyVerdict,
	RemotePolicies: []uint32{1001, 1002},
	Precedence:     uint32(policyTypes.MaxDenyPrecedence),
}

var ExpectedPortNetworkPolicyRule12Wildcard = &cilium.PortNetworkPolicyRule{
	Precedence: uint32(policyTypes.MaxAllowPrecedence + 1),
	L7:         ExpectedHttpRule12,
}

var ExpectedPortNetworkPolicyRule122HeaderMatch = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule122HeaderMatch,
}

var ExpectedPortNetworkPolicyRule122HeaderMatchPrecedence = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1001, 1002},
	L7:             ExpectedHttpRule122HeaderMatch,
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedPortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
	RemotePolicies: []uint32{1001, 1003},
	L7:             ExpectedHttpRule1,
}

var ExpectedPortNetworkPolicyRule1Precedence = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1001, 1003},
	L7:             ExpectedHttpRule1,
	Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
}

var ExpectedPortNetworkPolicyRule1Wildcard = &cilium.PortNetworkPolicyRule{
	L7: ExpectedHttpRule1,
}

var L4PolicyMap1 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: L7Rules12,
		},
	},
})

var L4PolicyMap1HeaderMatch = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: L7Rules12HeaderMatch,
		},
	},
})

var L4PolicyMap1RequiresV2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1:           L7Rules1,
			cachedRequiresV2Selector1: L7Rules12,
		},
	},
})

var L4PolicyMap2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"8080/TCP": {
		Port:     8080,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector2: L7Rules1,
		},
	},
})

var L4PolicyMap1Deny2 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"8080/TCP": {
		Port:     8080,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: denyPerSelectorPolicy,
			cachedSelector2: L7Rules1,
		},
	},
})

var L4PolicyMap3 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: L7Rules12,
		},
	},
})

// L4PolicyMap4 is an L4-only policy, with no L7 rules.
var L4PolicyMap4 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
})

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5 = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{L7Rules: api.L7Rules{}},
		},
	},
})

// L4PolicyMap5 is an L4-only policy, with no L7 rules.
var L4PolicyMap5LowestPriority = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				Priority: policyTypes.LowestPriority,
				L7Rules:  api.L7Rules{},
			},
		},
	},
})

// L4PolicyMapSNI is an L4-only policy, with SNI enforcement
var L4PolicyMapSNI = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				ServerNames: policy.NewStringSet([]string{
					"jarno.cilium.rocks",
					"ab.cd.com",
				}),
			},
		},
	},
})

var ExpectedPerPortPoliciesSNI = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				Precedence:  uint32(policyTypes.MaxAllowPrecedence),
				ServerNames: []string{"ab.cd.com", "jarno.cilium.rocks"},
			},
		},
	},
}

// L4PassPolicy is a policy with a pass verdict
var L4PassPolicy = &policy.L4Policy{
	Ingress: policy.NewL4DirectionPolicyForTest(L4PolicyMapPass,
		[]types.Priority{0, 0x2000}),
}

var L4PolicyMapPass = policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
	"0/TCP": {
		Tier:     0,
		Port:     0,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{
				Priority: 0,
				Verdict:  policyTypes.Pass,
			},
			wildcardCachedSelector: &policy.PerSelectorPolicy{
				Priority: 40,
				Verdict:  policyTypes.Deny,
			},
		},
	},
	"443/TCP": {
		Tier:     1,
		Port:     443,
		Protocol: api.ProtoTCP,
		PerSelectorPolicies: policy.L7DataMap{
			cachedSelector1: &policy.PerSelectorPolicy{
				Priority: 50,
			},
		},
	},
})

var ExpectedPerPortPoliciesPass = []*cilium.PortNetworkPolicy{
	{
		Port:     0,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: 0xffe00000,
				},
				RemotePolicies: []uint32{1001, 1002},
				Precedence:     0xffffff00,
			},
			{
				Verdict:    DenyVerdict,
				Precedence: 0xffffd7ff, // ~40
			},
		},
	},
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			{
				RemotePolicies: []uint32{1001, 1002},
				Precedence:     0xffffcd01, // ~50
			},
		},
	},
}

var ExpectedPerPortPolicies1 = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1,
		},
	},
}

var ExpectedPerPortPolicies1Deny2 = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12Deny,
			ExpectedPortNetworkPolicyRule1,
		},
	},
}

var ExpectedPerPortPolicies1Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     8080,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule1Wildcard,
		},
	},
}

var ExpectedPerPortPolicies122HeaderMatch = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule122HeaderMatch,
		},
	},
}

var ExpectedPerPortPolicies12 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12,
		},
	},
}

var ExpectedPerPortPolicies12Wildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{
			ExpectedPortNetworkPolicyRule12Wildcard,
		},
	},
}

var ExpectedPerPortPolicies12RequiresV2 = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			L7:             ExpectedHttpRule1,
		}, {
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1002},
			L7:             ExpectedHttpRule12,
		}},
	},
}

var ExpectedPerPortPolicies = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence),
			RemotePolicies: []uint32{1001, 1002},
		}},
	},
}

var ExpectedPerPortPoliciesWildcard = []*cilium.PortNetworkPolicy{
	{
		Port:     80,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.MaxAllowPrecedence),
		}},
	},
}

var L4Deny2Policy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1Deny2},
}

var L4Policy4 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap4},
}

var L4Policy5 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap5},
}

var L4HeaderMatchPolicy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1HeaderMatch},
}

var L4SNIPolicy = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMapSNI},
}

var L4Policy1 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
}

var L4Policy1RequiresV2 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap1RequiresV2},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
}

var L4Policy2 = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: L4PolicyMap3},
	Egress:  policy.L4DirectionPolicy{PortRules: L4PolicyMap2},
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

func Test_getWildcardNetworkPolicyRules(t *testing.T) {
	xds := testXdsServer(t)
	version := testSelectorCache.GetSelectorSnapshot()

	t.Run("allow_wildcard_and_specific_rules", func(t *testing.T) {
		perSelectorPoliciesWithWildcard := policy.L7DataMap{
			cachedSelector1:           nil,
			cachedRequiresV2Selector1: nil,
			wildcardCachedSelector:    nil,
		}

		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, perSelectorPoliciesWithWildcard, false, false, "")
		require.Equal(t, []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.MaxAllowPrecedence),
		}}, obtained)
		require.False(t, isPass)
		require.NotZero(t, wildcardSelectorPrecedence)
		require.True(t, wildcardSelectorPrecedence.IsAllow())
	})

	t.Run("non_wildcard_allow_and_deny_rules_are_grouped", func(t *testing.T) {
		// both cachedSelector2 and cachedSelector2 select identity 1001, but duplicates must have been removed
		perSelectorPolicies := policy.L7DataMap{
			cachedSelector2:           nil,
			cachedSelector1:           denyPerSelectorPolicy,
			cachedRequiresV2Selector1: nil,
		}

		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, perSelectorPolicies, false, false, "")
		require.Equal(t, []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxDenyPrecedence),
			Verdict:        DenyVerdict,
			RemotePolicies: []uint32{1001, 1002},
		}, {
			Precedence:     uint32(policyTypes.MaxAllowPrecedence),
			RemotePolicies: []uint32{1001, 1002, 1003},
		}}, obtained)
		require.False(t, isPass)
		require.Zero(t, wildcardSelectorPrecedence)
	})

	t.Run("single_selector_wildcard_pass_sets_have_pass_and_precedence", func(t *testing.T) {
		passPriority := policyTypes.Priority(7)
		passPolicy := &policy.PerSelectorPolicy{
			Priority: passPriority,
			Verdict:  types.Pass,
		}

		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			wildcardCachedSelector: passPolicy,
		}, false, false, "")

		require.Equal(t, []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(passPriority.ToPassPrecedence()),
			Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
				PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
			},
		}}, obtained)
		require.True(t, isPass)
		require.Equal(t, passPriority.ToPassPrecedence(), wildcardSelectorPrecedence)
		require.True(t, wildcardSelectorPrecedence.IsPass())
	})

	t.Run("grouped_wildcard_pass_keeps_same_priority_allow_and_deny", func(t *testing.T) {
		passPriority := policyTypes.Priority(9)
		allowPriority := passPriority
		denyPriority := passPriority

		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			wildcardCachedSelector: {
				Priority: passPriority,
				Verdict:  types.Pass,
			},
			cachedSelector1: {
				Priority: allowPriority,
			},
			cachedSelector2: {
				Priority: denyPriority,
				Verdict:  types.Deny,
			},
		}, false, false, "")

		require.True(t, isPass)
		require.Equal(t, passPriority.ToPassPrecedence(), wildcardSelectorPrecedence)
		require.Len(t, obtained, 3)
		require.Contains(t, obtained, &cilium.PortNetworkPolicyRule{
			Precedence: uint32(passPriority.ToPassPrecedence()),
			Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
				PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
			},
		})
		require.Contains(t, obtained, &cilium.PortNetworkPolicyRule{
			Precedence:     uint32(allowPriority.ToAllowPrecedence()),
			RemotePolicies: []uint32{1001, 1002},
		})
		require.Contains(t, obtained, &cilium.PortNetworkPolicyRule{
			Precedence:     uint32(denyPriority.ToDenyPrecedence()),
			Verdict:        DenyVerdict,
			RemotePolicies: []uint32{1001, 1003},
		})
	})

	t.Run("grouped_non_wildcard_pass_with_empty_selection_is_skipped", func(t *testing.T) {
		noneCachedSelector, _ := testSelectorCache.AddIdentitySelectorForTest(dummySelectorCacheUser, api.EndpointSelectorNone)

		obtained, isPass, wildcardSelectorPrecedence := xds.getWildcardPortNetworkPolicyRules(ep, version, policyTypes.HighestPriority, policyTypes.LowestPriority, policy.L7DataMap{
			cachedSelector1: {
				Priority: policyTypes.Priority(3),
			},
			noneCachedSelector: {
				Priority: policyTypes.Priority(2),
				Verdict:  types.Pass,
			},
		}, false, false, "")

		require.Equal(t, []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.Priority(3).ToAllowPrecedence()),
			RemotePolicies: []uint32{1001, 1002},
		}}, obtained)
		require.False(t, isPass)
		require.Zero(t, wildcardSelectorPrecedence)
	})
}

func TestGetPortNetworkPolicyRule(t *testing.T) {
	xds := testXdsServer(t)

	version := testSelectorCache.GetSelectorSnapshot()

	obtained, canShortCircuit := xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule12, obtained)
	require.True(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule12Deny, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule122HeaderMatch, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.LowestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule1, obtained)
	require.True(t, canShortCircuit)

	// With precedence

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule12Precedence, obtained)
	require.True(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12Deny, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule12DenyPrecedence, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1, L7Rules12HeaderMatch, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule122HeaderMatchPrecedence, obtained)
	require.False(t, canShortCircuit)

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector2, L7Rules1, policyTypes.HighestPriority, policyTypes.LowestPriority, false, false, "")
	require.Equal(t, ExpectedPortNetworkPolicyRule1Precedence, obtained)
	require.True(t, canShortCircuit)

	// with pass verdict

	obtained, canShortCircuit = xds.getPortNetworkPolicyRule(ep, version, cachedSelector1,
		&policy.PerSelectorPolicy{Verdict: types.Pass, Priority: 0xffff},
		0xffff, 0x1ffff, false, false, "")
	require.Equal(t, &cilium.PortNetworkPolicyRule{
		Precedence:     0xff000000,
		Verdict:        &cilium.PortNetworkPolicyRule_PassPrecedence{PassPrecedence: 0xfe000000},
		RemotePolicies: []uint32{1001, 1002},
	}, obtained)
	require.True(t, canShortCircuit)
}

func TestGetDirectionNetworkPolicy(t *testing.T) {
	// L4+L7
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy1.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPolicies12, obtained)

	// L4+L7 with header mods
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4HeaderMatchPolicy1.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPolicies122HeaderMatch, obtained)

	// L4+L7
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy1.Egress, true, false, false, "egress", "")
	require.Equal(t, ExpectedPerPortPolicies1, obtained)

	// L4+L7 with Deny L3
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Deny2Policy1.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPolicies1Deny2, obtained)

	// L4-only
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy4.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPolicies, obtained)

	// L4-only
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4Policy5.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPoliciesWildcard, obtained)

	// L4-only with SNI
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4SNIPolicy.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPoliciesSNI, obtained)

	// with pass verdict
	obtained = xds.getDirectionNetworkPolicy(ep, selectors, &L4PassPolicy.Ingress, true, false, false, "ingress", "")
	require.Equal(t, ExpectedPerPortPoliciesPass, obtained)

}

func TestGetDirectionNetworkPolicyWildcardPass(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()

	t.Run("wildcard_pass_does_not_short_circuit_later_tiers", func(t *testing.T) {
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Tier:     0,
				Port:     0,
				Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: policyTypes.HighestPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"443/TCP": {
				Tier:     1,
				Port:     443,
				Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: policyTypes.Priority(0x100),
					},
				},
			},
		}), []types.Priority{0, 0x100})

		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "")
		require.Equal(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(policyTypes.HighestPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.Priority(0xff).ToPassPrecedence()),
				},
			}},
		}, {
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:     uint32(policyTypes.Priority(0x100).ToAllowPrecedence()),
				RemotePolicies: []uint32{1001, 1002},
			}},
		}}, obtained)
	})

	t.Run("wildcard_pass_keeps_same_priority_port_rules", func(t *testing.T) {
		passPriority := policyTypes.HighestPriority
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Port:     0,
				Protocol: api.ProtoAny,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: passPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"80/TCP": {
				Port:     80,
				Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: passPriority,
					},
					cachedSelector2: {
						Priority: passPriority,
						Verdict:  types.Deny,
					},
				},
			},
		}), []types.Priority{0})

		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "")
		require.Equal(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(passPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
				},
			}},
		}, {
			Port:     80,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:     uint32(passPriority.ToDenyPrecedence()),
				Verdict:        DenyVerdict,
				RemotePolicies: []uint32{1001, 1003},
			}, {
				Precedence:     uint32(passPriority.ToAllowPrecedence()),
				RemotePolicies: []uint32{1001, 1002},
			}},
		}}, obtained)
	})

	t.Run("wildcard_pass_suppresses_lower_priority_port_rules", func(t *testing.T) {
		passPriority := policyTypes.HighestPriority
		l4DirectionPolicy := &policy.L4DirectionPolicy{}
		*l4DirectionPolicy = policy.NewL4DirectionPolicyForTest(policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"0/TCP": {
				Port:     0,
				Protocol: api.ProtoAny,
				PerSelectorPolicies: policy.L7DataMap{
					wildcardCachedSelector: {
						Priority: passPriority,
						Verdict:  types.Pass,
					},
				},
			},
			"80/TCP": {
				Port:     80,
				Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: {
						Priority: passPriority + 1,
					},
					cachedSelector2: {
						Priority: passPriority + 2,
						Verdict:  types.Deny,
					},
				},
			},
		}), []types.Priority{0})

		obtained := xds.getDirectionNetworkPolicy(ep, selectors, l4DirectionPolicy, true, false, false, "ingress", "")
		require.Equal(t, []*cilium.PortNetworkPolicy{{
			Port:     0,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence: uint32(passPriority.ToPassPrecedence()),
				Verdict: &cilium.PortNetworkPolicyRule_PassPrecedence{
					PassPrecedence: uint32(policyTypes.LowestPriority.ToPassPrecedence()),
				},
			}},
		}}, obtained)
	})
}

func TestGetDirectionNetworkPolicyWildcardRedirect(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()

	const listener1ProxyPort = uint16(19001)
	redirectEP := &listenerProxyUpdaterMock{
		ProxyUpdaterMock: &test.ProxyUpdaterMock{
			Id:   ep.Id,
			Ipv4: ep.Ipv4,
			Ipv6: ep.Ipv6,
		},
		listenerProxyPorts: map[string]uint16{
			"listener1": listener1ProxyPort,
		},
	}

	testCases := []struct {
		name             string
		redirectProtocol api.L4Proto
		redirectPriority policyTypes.Priority
		port80Policy     *policy.PerSelectorPolicy
		expected         []*cilium.PortNetworkPolicy
	}{
		{
			name:             "tcp_same_priority_keeps_port_rule",
			redirectProtocol: api.ProtoTCP,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.HighestPriority},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
				{
					Port:     80,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence:     uint32(policyTypes.HighestPriority.ToAllowPrecedence()),
						RemotePolicies: []uint32{1001, 1002},
					}},
				},
			},
		},
		{
			name:             "tcp_higher_priority_suppresses_port_rule",
			redirectProtocol: api.ProtoTCP,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.Priority(1)},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
			},
		},
		{
			name:             "any_protocol_redirect_is_sent_to_envoy_as_tcp",
			redirectProtocol: api.ProtoAny,
			redirectPriority: policyTypes.HighestPriority,
			port80Policy:     &policy.PerSelectorPolicy{Priority: policyTypes.HighestPriority},
			expected: []*cilium.PortNetworkPolicy{
				{
					Port:     0,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
						ProxyId:    uint32(listener1ProxyPort),
					}},
				},
				{
					Port:     80,
					Protocol: envoy_config_core.SocketAddress_TCP,
					Rules: []*cilium.PortNetworkPolicyRule{{
						Precedence:     uint32(policyTypes.HighestPriority.ToAllowPrecedence()),
						RemotePolicies: []uint32{1001, 1002},
					}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			redirectPolicy := &policy.PerSelectorPolicy{
				Priority:         tc.redirectPriority,
				L7Parser:         policy.ParserTypeCRD,
				Listener:         "listener1",
				ListenerPriority: policy.ListenerPriorityCRD,
			}

			l4DirectionPolicy := &policy.L4DirectionPolicy{
				PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
					"0/" + string(tc.redirectProtocol): {
						Port:     0,
						Protocol: tc.redirectProtocol,
						PerSelectorPolicies: policy.L7DataMap{
							wildcardCachedSelector: redirectPolicy,
						},
					},
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						PerSelectorPolicies: policy.L7DataMap{
							cachedSelector1: tc.port80Policy,
						},
					},
				}),
			}

			obtained := xds.getDirectionNetworkPolicy(redirectEP, selectors, l4DirectionPolicy, true, false, false, "ingress", "")
			require.Equal(t, tc.expected, obtained)
		})
	}
}

func TestCNPWildcardPortListenerRedirectToEnvoy(t *testing.T) {
	logger := hivetest.Logger(t)
	xds := testXdsServer(t)

	localIdentity := identity.NewIdentity(9001, labels.LabelArray{
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s),
	}.Labels())

	idMgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		identity.IdentityMap{localIdentity.ID: localIdentity.LabelArray},
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idMgr,
		testpolicy.NewPolicyMetricsNoop(),
	)
	idMgr.Add(localIdentity)
	t.Cleanup(func() {
		idMgr.Remove(localIdentity)
	})

	cnpRule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=a")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
			},
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{
					Port:     "0",
					Protocol: api.ProtoAny,
				}},
				Listener: &api.Listener{
					EnvoyConfig: &api.EnvoyConfig{
						Kind: "CiliumEnvoyConfig",
						Name: "test-cec",
					},
					Name: "listener1",
				},
			}},
		}},
	}
	require.NoError(t, cnpRule.Sanitize())
	repo.MustAddList(api.Rules{cnpRule})

	selPolicy, _, err := repo.GetSelectorPolicy(localIdentity, 0, &dummyPolicyStats{}, ep.GetID())
	require.NoError(t, err)

	const listenerProxyPort = uint16(19001)
	const qualifiedListener = "default/test-cec/listener1"
	redirectEP := &listenerProxyUpdaterMock{
		ProxyUpdaterMock: &test.ProxyUpdaterMock{
			Id:   ep.Id,
			Ipv4: ep.Ipv4,
			Ipv6: ep.Ipv6,
		},
		listenerProxyPorts: map[string]uint16{
			qualifiedListener: listenerProxyPort,
		},
	}

	epp := selPolicy.DistillPolicy(logger, redirectEP, nil)
	t.Cleanup(func() {
		epp.Detach(logger)
	})

	obtained := xds.getDirectionNetworkPolicy(
		redirectEP,
		epp.GetPolicySelectors(),
		&epp.SelectorPolicy.L4Policy.Egress,
		true,
		false,
		false,
		"egress",
		"",
	)

	require.Equal(t, []*cilium.PortNetworkPolicy{{
		Port:     0,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence: uint32(policyTypes.HighestPriority.ToPrecedenceWithListenerPriority(false, true, policy.ListenerPriorityCRD)),
			ProxyId:    uint32(listenerProxyPort),
		}},
	}}, obtained)
}

func TestGetNetworkPolicy(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy1, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyWildcard(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12Wildcard,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyDeny(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyWildcardDeny(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyNil(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, nil, true, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: nil,
		EgressPerPortPolicies:  nil,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyIngressNotEnforced(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy2, false, true, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: allowAllPortNetworkPolicy,
		EgressPerPortPolicies:  ExpectedPerPortPolicies1,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

func TestGetNetworkPolicyEgressNotEnforced(t *testing.T) {
	xds := testXdsServer(t)
	selectors := testSelectorCache.GetSelectorSnapshot()
	obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, L4Policy1RequiresV2, true, false, false, false, "")
	expected := &cilium.NetworkPolicy{
		EndpointIps:            []string{IPv4Addr},
		EndpointId:             uint64(ep.GetID()),
		IngressPerPortPolicies: ExpectedPerPortPolicies12RequiresV2,
		EgressPerPortPolicies:  allowAllPortNetworkPolicy,
		ConntrackMapName:       "global",
	}
	require.Equal(t, expected, obtained)
}

var fullValuesTLSContext = &policy.TLSContext{
	TrustedCA:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTrustedCAOriginatingTLSContext = &policy.TLSContext{
	TrustedCA: "foo",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTerminationDetailsTLSContext = &policy.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var fullValuesTLSContextFromFile = &policy.TLSContext{
	TrustedCA:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	FromFile:         true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTrustedCAOriginatingTLSContextFromFile = &policy.TLSContext{
	TrustedCA: "foo",
	FromFile:  true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

var onlyTerminationDetailsTLSContextFromFile = &policy.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
	FromFile:         true,
	Secret: k8sTypes.NamespacedName{
		Name:      "testsecret",
		Namespace: "testnamespace",
	},
}

// newL4PolicyTLSEgress is a small helper to reduce boilerplate.
func newL4PolicyTLSEgress(tls *policy.TLSContext) *policy.L4Policy {
	return &policy.L4Policy{
		Egress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"443/TCP": {
				Port: 443, Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: &policy.PerSelectorPolicy{
						L7Parser:       "tls",
						OriginatingTLS: tls,
					},
				},
			},
		})},
	}
}

var L4PolicyTLSEgressFullValues = newL4PolicyTLSEgress(fullValuesTLSContext)

var L4PolicyTLSEgressFullValuesFromFile = newL4PolicyTLSEgress(fullValuesTLSContextFromFile)

var L4PolicyTLSEgressOnlyTrustedCA = newL4PolicyTLSEgress(onlyTrustedCAOriginatingTLSContext)

var L4PolicyTLSEgressOnlyTrustedCAFromFile = newL4PolicyTLSEgress(onlyTrustedCAOriginatingTLSContextFromFile)

func newEgressPortNetworkPolicyReturnVal(tls *cilium.TLSContext) []*cilium.PortNetworkPolicy {
	return []*cilium.PortNetworkPolicy{
		{
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:         uint32(policyTypes.MaxAllowPrecedence + 1),
				RemotePolicies:     []uint32{1001, 1002},
				UpstreamTlsContext: tls,
			}},
		},
	}
}

var ciliumTLSContextOnlyValidatingSDSDetails = &cilium.TLSContext{
	ValidationContextSdsSecret: "cilium-secrets/testnamespace-testsecret",
}

var ciliumTLSContextOnlySDSDetails = &cilium.TLSContext{
	TlsSdsSecret: "cilium-secrets/testnamespace-testsecret",
}

var ciliumTLSContextOnlyTrustedCa = &cilium.TLSContext{
	TrustedCa: "foo",
}

var ciliumTLSContextAllDetails = &cilium.TLSContext{
	TrustedCa:        "foo",
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
}

var ciliumTLSContextOnlyTerminationDetails = &cilium.TLSContext{
	CertificateChain: "certchain",
	PrivateKey:       "privatekey",
}

var ExpectedPerPortPoliciesTLSEgress = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyValidatingSDSDetails)

var ExpectedPerPortPoliciesTLSEgressNoSync = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyTrustedCa)

var ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext = newEgressPortNetworkPolicyReturnVal(ciliumTLSContextAllDetails)

func newL4PolicyTLSIngress(tls *policy.TLSContext) *policy.L4Policy {
	return &policy.L4Policy{
		Ingress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
			"443/TCP": {
				Port: 443, Protocol: api.ProtoTCP,
				PerSelectorPolicies: policy.L7DataMap{
					cachedSelector1: &policy.PerSelectorPolicy{
						L7Parser:       "tls",
						TerminatingTLS: tls,
					},
				},
			},
		})},
	}
}

var L4PolicyTLSIngressFullValues = newL4PolicyTLSIngress(fullValuesTLSContext)

var L4PolicyTLSIngressFullValuesFromFile = newL4PolicyTLSIngress(fullValuesTLSContextFromFile)

var L4PolicyTLSIngressOnlyTerminationDetails = newL4PolicyTLSIngress(onlyTerminationDetailsTLSContext)

var L4PolicyTLSIngressOnlyTerminationDetailsFromFile = newL4PolicyTLSIngress(onlyTerminationDetailsTLSContextFromFile)

func newIngressPortNetworkPolicyReturnVal(tls *cilium.TLSContext) []*cilium.PortNetworkPolicy {
	return []*cilium.PortNetworkPolicy{
		{
			Port:     443,
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				Precedence:           uint32(policyTypes.MaxAllowPrecedence + 1),
				RemotePolicies:       []uint32{1001, 1002},
				DownstreamTlsContext: tls,
			}},
		},
	}
}

var ExpectedPerPortPoliciesTLSIngress = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextOnlySDSDetails)

var ExpectedPerPortPoliciesTLSIngressNoSync = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextOnlyTerminationDetails)

var ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext = newIngressPortNetworkPolicyReturnVal(ciliumTLSContextAllDetails)

var L4PolicyTLSFullContext = &policy.L4Policy{
	Ingress: policy.L4DirectionPolicy{PortRules: policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"443/TCP": {
			Port: 443, Protocol: api.ProtoTCP,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector1: &policy.PerSelectorPolicy{
					L7Parser: "tls",
					TerminatingTLS: &policy.TLSContext{
						CertificateChain: "terminatingCertchain",
						PrivateKey:       "terminatingKey",
						TrustedCA:        "terminatingCA",
						Secret: k8sTypes.NamespacedName{
							Name:      "terminating-tls",
							Namespace: "tlsns",
						},
					},
					OriginatingTLS: &policy.TLSContext{
						CertificateChain: "originatingCertchain",
						PrivateKey:       "originatingKey",
						TrustedCA:        "originatingCA",
						Secret: k8sTypes.NamespacedName{
							Name:      "originating-tls",
							Namespace: "tlsns",
						},
					},
				},
			},
			Ingress: true,
		},
	})},
}

var ExpectedPerPortPoliciesTLSFullContext = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "terminatingCertchain",
				PrivateKey:       "terminatingKey",
				TrustedCa:        "terminatingCA",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "originatingCertchain",
				PrivateKey:       "originatingKey",
				TrustedCa:        "originatingCA",
			},
		}},
	},
}

var ExpectedPerPortPoliciesTLSNotFullContext = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				CertificateChain: "terminatingCertchain",
				PrivateKey:       "terminatingKey",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				TrustedCa: "originatingCA",
			},
		}},
	},
}

var ExpectedPerPortPoliciesBothWaysTLSSDS = []*cilium.PortNetworkPolicy{
	{
		Port:     443,
		Protocol: envoy_config_core.SocketAddress_TCP,
		Rules: []*cilium.PortNetworkPolicyRule{{
			Precedence:     uint32(policyTypes.MaxAllowPrecedence + 1),
			RemotePolicies: []uint32{1001, 1002},
			DownstreamTlsContext: &cilium.TLSContext{
				TlsSdsSecret: "cilium-secrets/tlsns-terminating-tls",
			},
			UpstreamTlsContext: &cilium.TLSContext{
				ValidationContextSdsSecret: "cilium-secrets/tlsns-originating-tls",
			},
		}},
	},
}

func TestGetNetworkPolicyTLSInterception(t *testing.T) {
	type args struct {
		inputPolicy            *policy.L4Policy
		useFullTLSContext      bool
		useSDS                 bool
		policySecretsNamespace string
	}

	tests := []struct {
		name        string
		args        args
		wantEgress  []*cilium.PortNetworkPolicy
		wantIngress []*cilium.PortNetworkPolicy
	}{
		{
			name: "Egress Originating TLS Fully Populated with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgress,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgress,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCA,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSyncUseFullContext,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Fully Populated, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Egress Originating TLS Only TrustedCA, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSEgressOnlyTrustedCAFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  ExpectedPerPortPoliciesTLSEgressNoSync,
			wantIngress: nil,
		},
		{
			name: "Ingress Terminating TLS Fully Populated with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngress,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValues,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details with secret sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngress,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync, secretsNamespace",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetails,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSyncUseFullContext,
		},
		{
			name: "Ingress Terminating TLS Fully Populated, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressFullValuesFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details with secret sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, UseFullTLSContext, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Ingress Terminating TLS Only Termination details, no sync, fromFile",
			args: args{
				inputPolicy:            L4PolicyTLSIngressOnlyTerminationDetailsFromFile,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSIngressNoSync,
		},
		{
			name: "Both directions, full details, with sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 true,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesBothWaysTLSSDS,
		},
		{
			name: "Both directions, full details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "cilium-secrets",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSNotFullContext,
		},
		// These next two tests check what happens when no sync is enabled, and useFullTLSContext is either true or false
		// (i.e., don't implement buggy behaviour).
		// When useFullTLSContext is false, we correctly strip out the CA for a terminatingTLS/downstreamTls and the
		// cert/key on originatingTLS/upstreamTls. Leaving them in can result in incorrect behaviour from Envoy when using
		// Cilium L7 policy that's not done via SDS, see https://github.com/cilium/cilium/issues/31761 for
		// full details.
		//
		// When Secret Sync and SDS are in use, the use of the TlsSdsSecret and ValidationContextSdsSecret mean that
		// SDS is not susceptible to that bug.
		{
			name: "Both directions, full details, no sync",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      false,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSNotFullContext,
		},
		{
			name: "Both directions, full details, no sync, usefullcontext",
			args: args{
				inputPolicy:            L4PolicyTLSFullContext,
				useFullTLSContext:      true,
				useSDS:                 false,
				policySecretsNamespace: "",
			},
			wantEgress:  nil,
			wantIngress: ExpectedPerPortPoliciesTLSFullContext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xds := testXdsServer(t)
			selectors := testSelectorCache.GetSelectorSnapshot()
			obtained := xds.getNetworkPolicy(ep, selectors, []string{IPv4Addr}, tt.args.inputPolicy, true, true, tt.args.useFullTLSContext, tt.args.useSDS, tt.args.policySecretsNamespace)
			expected := &cilium.NetworkPolicy{
				EndpointIps:            []string{IPv4Addr},
				EndpointId:             uint64(ep.GetID()),
				IngressPerPortPolicies: tt.wantIngress,
				EgressPerPortPolicies:  tt.wantEgress,
				ConntrackMapName:       "global",
			}
			require.Equal(t, expected, obtained)
		})
	}
}

func Test_getPublicListenerAddress(t *testing.T) {
	type args struct {
		port uint16
		ipv4 bool
		ipv6 bool
	}
	tests := []struct {
		name string
		args args
		want *envoy_config_core.Address
	}{
		{
			name: "IPv4 only",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: false,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "0.0.0.0",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
					},
				},
			},
		},
		{
			name: "IPv6 only",
			args: args{
				port: 80,
				ipv4: false,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "::",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
					},
				},
			},
		},
		{
			name: "IPv4 and IPv6",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: &envoy_config_core.Address_SocketAddress{
					SocketAddress: &envoy_config_core.SocketAddress{
						Protocol:      envoy_config_core.SocketAddress_TCP,
						Address:       "::",
						PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
						Ipv4Compat:    true,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPublicListenerAddress(tt.args.port, tt.args.ipv4, tt.args.ipv6)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getLocalListenerAddresses(t *testing.T) {
	v4Local := &envoy_config_core.Address_SocketAddress{
		SocketAddress: &envoy_config_core.SocketAddress{
			Protocol:      envoy_config_core.SocketAddress_TCP,
			Address:       "127.0.0.1",
			PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
		},
	}

	v6Local := &envoy_config_core.Address_SocketAddress{
		SocketAddress: &envoy_config_core.SocketAddress{
			Protocol:      envoy_config_core.SocketAddress_TCP,
			Address:       "::1",
			PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(80)},
		},
	}
	type args struct {
		port uint16
		ipv4 bool
		ipv6 bool
	}
	tests := []struct {
		name           string
		args           args
		want           *envoy_config_core.Address
		wantAdditional []*envoy_config_listener.AdditionalAddress
	}{
		{
			name: "IPv4 only",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: false,
			},
			want: &envoy_config_core.Address{
				Address: v4Local,
			},
		},
		{
			name: "IPv6 only",
			args: args{
				port: 80,
				ipv4: false,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: v6Local,
			},
		},
		{
			name: "IPv4 and IPv6",
			args: args{
				port: 80,
				ipv4: true,
				ipv6: true,
			},
			want: &envoy_config_core.Address{
				Address: v4Local,
			},
			wantAdditional: []*envoy_config_listener.AdditionalAddress{{Address: &envoy_config_core.Address{Address: v6Local}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotAdditional := GetLocalListenerAddresses(tt.args.port, tt.args.ipv4, tt.args.ipv6)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantAdditional, gotAdditional)
		})
	}
}

func testXdsServer(t *testing.T) *xdsServer {
	logger := hivetest.Logger(t)
	return &xdsServer{
		logger:            logger,
		l7RulesTranslator: envoypolicy.NewEnvoyL7RulesTranslator(logger, nil),
	}
}
