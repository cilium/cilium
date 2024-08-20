// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestSetPortRulesForID(t *testing.T) {
	re.InitRegexCompileLRU(1)
	rules := policy.L7DataMap{}
	epID := uint64(1)
	pea := perEPAllow{}
	cache := make(regexCache)
	udpProtoPort8053 := restore.MakeV2PortProto(8053, u8proto.UDP)

	rules[new(MockCachedSelector)] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium.io."},
				{MatchPattern: "*.cilium.io."},
			},
		},
	}

	err := pea.setPortRulesForID(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 1, len(cache))

	selector2 := new(MockCachedSelector)
	rules[selector2] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium2.io."},
				{MatchPattern: "*.cilium2.io."},
				{MatchPattern: "*.cilium3.io."},
			},
		},
	}

	err = pea.setPortRulesForID(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 2, len(cache))

	delete(rules, selector2)
	err = pea.setPortRulesForID(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 1, len(cache))

	err = pea.setPortRulesForID(cache, epID, udpProtoPort8053, nil)
	require.Equal(t, nil, err)
	require.Equal(t, 0, len(cache))

	rules[selector2] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium2.io."},
				{MatchPattern: "*.cilium2.io."},
				{MatchPattern: "-invalid-pattern("},
				{MatchPattern: "*.cilium3.io."},
			},
		},
	}
	err = pea.setPortRulesForID(cache, epID, udpProtoPort8053, rules)

	require.Error(t, err)
	require.Equal(t, 0, len(cache))
}

func TestSetPortRulesForIDFromUnifiedFormat(t *testing.T) {
	re.InitRegexCompileLRU(1)
	rules := make(CachedSelectorREEntry)
	epID := uint64(1)
	pea := perEPAllow{}
	cache := make(regexCache)
	udpProtoPort8053 := restore.MakeV2PortProto(8053, u8proto.UDP)
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")

	err := pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 1, len(cache))

	selector2 := new(MockCachedSelector)
	rules[selector2] = regexp.MustCompile("^sub[.]cilium[.]io")
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 2, len(cache))

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 1, len(cache))

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, nil)
	require.Equal(t, nil, err)
	require.Equal(t, 0, len(cache))

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, rules)
	require.Equal(t, nil, err)
	require.Equal(t, 1, len(cache))

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, udpProtoPort8053, nil)
	require.Equal(t, nil, err)
	require.Equal(t, 0, len(cache))
}

func TestGeneratePattern(t *testing.T) {
	l7 := &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
			{MatchName: "example.name."},
			{MatchName: "example.com."},
			{MatchName: "demo.io."},
			{MatchName: "demoo.tld."},
			{MatchPattern: "*pattern.com"},
			{MatchPattern: "*.*.*middle.*"},
		}},
	}
	matching := []string{"example.name.", "example.com.", "demo.io.", "demoo.tld.", "testpattern.com.", "pattern.com.", "a.b.cmiddle.io."}
	notMatching := []string{"eexample.name.", "eexample.com.", "vdemo.io.", "demo.ioo.", "emoo.tld.", "test.ppattern.com.", "b.cmiddle.io."}

	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	pattern := GeneratePattern(l7)

	regex, err := re.CompileRegex(pattern)
	require.Equal(t, nil, err)

	for _, fqdn := range matching {
		require.Truef(t, regex.MatchString(fqdn), "expected fqdn %q to match, but it did not", fqdn)
	}
	for _, fqdn := range notMatching {
		require.Falsef(t, regex.MatchString(fqdn), "expected fqdn %q to not match, but it did", fqdn)
	}

	pattern = GeneratePattern(
		&policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
				{MatchPattern: "domo.io."},
				{MatchPattern: "*"},
			}},
		})

	regex, err = re.CompileRegex(pattern)
	require.Equal(t, nil, err)

	// Ensure all fqdns match a policy with a wildcard
	for _, fqdn := range append(matching, notMatching...) {
		require.Truef(t, regex.MatchString(fqdn), "expected fqdn %q to match with wildcard policy, but it did not", fqdn)
	}

	pattern = GeneratePattern(&policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{},
	})

	regex, err = re.CompileRegex(pattern)
	require.Equal(t, nil, err)

	// Ensure all fqdns match a policy without any dns-rules
	for _, fqdn := range append(matching, notMatching...) {
		require.Truef(t, regex.MatchString(fqdn), "expected fqdn %q to match with wildcard policy, but it did not", fqdn)
	}

	pattern = GeneratePattern(&policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{}},
	})
	regex, err = re.CompileRegex(pattern)
	require.Equal(t, nil, err)

	// Ensure all fqdns match a policy without any dns-rules
	for _, fqdn := range append(matching, notMatching...) {
		require.Truef(t, regex.MatchString(fqdn), "expected fqdn %q to match with wildcard policy, but it did not", fqdn)
	}
}

func TestGeneratePatternTrailingDot(t *testing.T) {
	dnsName := "example.name"
	dnsPattern := "*.example.name"
	generatePattern := func(name, pattern string) string {
		l7 := &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
				{MatchName: name},
				{MatchPattern: pattern},
			}},
		}
		return GeneratePattern(l7)

	}
	require.EqualValues(t, generatePattern(dns.FQDN(dnsPattern), dns.FQDN(dnsName)), generatePattern(dnsPattern, dnsName))

}

type MockCachedSelector struct {
	key string
}

func (m MockCachedSelector) GetSelections() identity.NumericIdentitySlice {
	return nil
}

func (m MockCachedSelector) GetMetadataLabels() labels.LabelArray {
	panic("implement me")
}

func (m MockCachedSelector) Selects(_ identity.NumericIdentity) bool {
	return false
}

func (m MockCachedSelector) IsWildcard() bool {
	return false
}

func (m MockCachedSelector) IsNone() bool {
	return false
}

func (m MockCachedSelector) String() string {
	return m.key
}
