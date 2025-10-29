// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestCIDRRuleToCIDRSelectors(t *testing.T) {
	oldv4 := option.Config.EnableIPv4
	oldv6 := option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4 = oldv4
		option.Config.EnableIPv6 = oldv6
	})

	selectors := func(needKeys ...string) Selectors {
		out := Selectors{}
		for _, k := range needKeys {
			var ps *CIDRSelector

			lbl := labels.ParseSelectLabel(k)

			// CIDR Selector key string uses the original form without transforming ':'
			// characters in IPv6 addresses,
			key := lbl.String()

			cidrPrefix := labels.LabelSourceCIDR + ":"
			if strings.HasPrefix(k, cidrPrefix) {
				lbl2, err := labels.IPStringToLabel(k[len(cidrPrefix):])
				require.NoError(t, err)
				lbl.Key = lbl2.Key
			}

			if lbl.Value != "" {
				ps = &CIDRSelector{
					key: fmt.Sprintf("&LabelSelector{MatchLabels:map[string]string{%s.%s: %s,},MatchExpressions:[]LabelSelectorRequirement{},}", lbl.Source, lbl.Key, lbl.Value),
					requirements: Requirements{
						NewEqualsRequirement(lbl),
					},
				}
			} else {
				ps = &CIDRSelector{
					key: key,
					requirements: Requirements{
						NewExistRequirement(lbl),
					},
				}
			}
			out = append(out, ps)
		}
		return out
	}

	tt := []struct {
		name                   string
		rule                   api.CIDRRule
		expected               Selectors
		enableIPv4, enableIPv6 bool
		matchesLabels          []string
		notMatchesLabels       []string
	}{
		{
			name:       "basic cidr",
			rule:       api.CIDRRule{Cidr: "1.2.3.4/32"},
			expected:   selectors("cidr:1.2.3.4/32"),
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:1.2.3.4/32"},
			notMatchesLabels: []string{"cidr:1.2.3.5/32"},
		},
		{
			name: "except",
			rule: api.CIDRRule{Cidr: "1.0.0.0/8", ExceptCIDRs: []api.CIDR{"1.2.3.4/32"}},
			expected: Selectors{&CIDRSelector{
				key: "cidr:1.0.0.0/8-[1.2.3.4/32]",
				requirements: Requirements{
					NewExistRequirement(labels.NewLabel("1.0.0.0/8", "", labels.LabelSourceCIDR)),
					NewExceptRequirement(labels.NewLabel("1.2.3.4/32", "", labels.LabelSourceCIDR)),
				},
			}},
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:1.2.0.0/16"},
			notMatchesLabels: []string{"cidr:1.2.3.4/32"},
		},
		{
			name:       "cidr group",
			rule:       api.CIDRRule{CIDRGroupRef: "foo"},
			expected:   selectors("cidrgroup:io.cilium.policy.cidrgroupname/foo"),
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidrgroup:io.cilium.policy.cidrgroupname/foo"},
			notMatchesLabels: []string{"cidrgroup:io.cilium.policy.cidrgroupname/bar"},
		},
		{
			name: "cidr group with exception",
			rule: api.CIDRRule{CIDRGroupRef: "foo", ExceptCIDRs: []api.CIDR{"1.1.1.1/32"}},
			expected: Selectors{&CIDRSelector{
				key: "cidrgroup:io.cilium.policy.cidrgroupname/foo-[1.1.1.1/32]",
				requirements: Requirements{
					NewExistRequirement(labels.NewLabel("io.cilium.policy.cidrgroupname/foo", "", labels.LabelSourceCIDRGroup)),
					NewExceptRequirement(labels.NewLabel("1.1.1.1/32", "", labels.LabelSourceCIDR)),
				},
			}},
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidrgroup:io.cilium.policy.cidrgroupname/foo"},
			notMatchesLabels: []string{"cidr:1.1.1.1/32", "cidrgroup:io.cilium.policy.cidrgroupname/bar"},
		},
		{
			name: "cidr group ls",
			rule: api.CIDRRule{CIDRGroupSelector: api.EndpointSelector{LabelSelector: &v1.LabelSelector{
				MatchLabels: map[string]v1.MatchLabelsValue{"foo": "bar"},
			}}},
			expected:   selectors("cidrgroup:foo=bar"),
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidrgroup:foo=bar"},
			notMatchesLabels: []string{"cidr:1.1.1.1/32", "cidrgroup:foo=baz"},
		},
		{
			name: "cidr group ls with exceptions",
			rule: api.CIDRRule{CIDRGroupSelector: api.EndpointSelector{LabelSelector: &v1.LabelSelector{
				MatchLabels: map[string]v1.MatchLabelsValue{"foo": "bar"},
			}}, ExceptCIDRs: []api.CIDR{"1.1.1.1/32", "192.168.0.0/16"}},
			expected: Selectors{&CIDRSelector{
				key: "&LabelSelector{MatchLabels:map[string]string{cidrgroup.foo: bar,},MatchExpressions:[]LabelSelectorRequirement{},}-[1.1.1.1/32,192.168.0.0/16]",
				requirements: Requirements{
					NewEqualsRequirement(labels.NewLabel("foo", "bar", labels.LabelSourceCIDRGroup)),
					NewExceptRequirement(labels.NewLabel("1.1.1.1/32", "", labels.LabelSourceCIDR)),
					NewExceptRequirement(labels.NewLabel("192.168.0.0/16", "", labels.LabelSourceCIDR)),
				},
			}},
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidrgroup:foo=bar"},
			notMatchesLabels: []string{"cidr:1.1.1.1/32", "cidr:192.1681.1.1/32", "cidrgroup:foo=baz"},
		},
		{
			name:       "world v4 ss",
			rule:       api.CIDRRule{Cidr: "0.0.0.0/0"},
			expected:   selectors("cidr:0.0.0.0/0"),
			enableIPv4: true, enableIPv6: false,
			matchesLabels:    []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
			notMatchesLabels: []string{"cidr:::/0", "cidr:::1/128"},
		},
		{
			name:       "world v4 ds",
			rule:       api.CIDRRule{Cidr: "0.0.0.0/0"},
			expected:   selectors("cidr:0.0.0.0/0"),
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
			notMatchesLabels: []string{"cidr:::/0", "cidr:::1/128"},
		},
		{
			name:       "world v6 ss",
			rule:       api.CIDRRule{Cidr: "::/0"},
			expected:   selectors("cidr:::/0"),
			enableIPv4: false, enableIPv6: true,
			matchesLabels:    []string{"cidr:::/0", "cidr:::1/128"},
			notMatchesLabels: []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
		},
		{
			name:       "world v6 ds",
			rule:       api.CIDRRule{Cidr: "::/0"},
			expected:   selectors("cidr:::/0"),
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:::/0", "cidr:::1/128"},
			notMatchesLabels: []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
		},
		{
			name: "world v4 ds except",
			rule: api.CIDRRule{Cidr: "0.0.0.0/0", ExceptCIDRs: []api.CIDR{"1.2.3.4/32"}},
			expected: Selectors{&CIDRSelector{
				key: "cidr:0.0.0.0/0-[1.2.3.4/32]",
				requirements: Requirements{
					NewExistRequirement(labels.NewLabel("0.0.0.0/0", "", labels.LabelSourceCIDR)),
					NewExceptRequirement(labels.NewLabel("1.2.3.4/32", "", labels.LabelSourceCIDR)),
				},
			}},
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
			notMatchesLabels: []string{"cidr:::/0", "cidr:::1/128", "cidr:1.2.3.4/32"},
		},
		{
			name: "world v4 ds multiple exceptions",
			rule: api.CIDRRule{Cidr: "0.0.0.0/0", ExceptCIDRs: []api.CIDR{"1.2.3.4/32", "10.1.1.0/24"}},
			expected: Selectors{&CIDRSelector{
				key: "cidr:0.0.0.0/0-[1.2.3.4/32,10.1.1.0/24]",
				requirements: Requirements{
					NewExistRequirement(labels.NewLabel("0.0.0.0/0", "", labels.LabelSourceCIDR)),
					NewExceptRequirement(labels.NewLabel("1.2.3.4/32", "", labels.LabelSourceCIDR)),
					NewExceptRequirement(labels.NewLabel("10.1.1.0/24", "", labels.LabelSourceCIDR)),
				},
			}},
			enableIPv4: true, enableIPv6: true,
			matchesLabels:    []string{"cidr:1.1.1.1/32", "cidr:192.168.1.1/32"},
			notMatchesLabels: []string{"cidr:::/0", "cidr:::1/128", "cidr:1.2.3.4/32", "cidr:10.1.1.5/32"},
		},
	}

	logger := hivetest.Logger(t)

	for _, test := range tt {
		t.Run(test.name, func(t *testing.T) {
			option.Config.EnableIPv6 = test.enableIPv6
			option.Config.EnableIPv4 = test.enableIPv4

			if test.rule.CIDRGroupSelector.LabelSelector != nil {
				test.rule.CIDRGroupSelector.SanitizeWithKeyExtender(labels.GetSourcePrefixKeyExtender(labels.LabelSourceCIDRGroupKeyPrefix))
			}
			result := ToSelectors(api.CIDRRuleSlice{test.rule})
			require.Equal(t, test.expected, result, test.name)

			for _, l := range test.matchesLabels {
				lblArr := labels.NewLabelArrayFromSortedList(l)
				if !result.Matches(logger, lblArr) {
					t.Fatalf("Expected to match %+v, but did not", lblArr)
				}
			}
			for _, l := range test.notMatchesLabels {
				lblArr := labels.NewLabelArrayFromSortedList(l)
				if result.Matches(logger, lblArr) {
					t.Fatalf("Expected not to match %+v, but did", lblArr)
				}
			}
		})
	}
}

func benchmarkMatchesSetup(match string, count int) (*LabelSelector, labels.LabelArray) {
	stringLabels := []string{}
	for i := range count {
		stringLabels = append(stringLabels, fmt.Sprintf("%d", i))
	}
	lbls := labels.NewLabelsFromModel(stringLabels)
	return NewLabelSelectorFromLabels(lbls.ToSlice()...), labels.ParseLabelArray(match)
}

func BenchmarkMatchesValid1000(b *testing.B) {
	ls, match := benchmarkMatchesSetup("42", 1000)
	logger := hivetest.Logger(b)
	b.ReportAllocs()

	for b.Loop() {
		MatchesRequirements(logger, ls.requirements, match)
	}
}

func BenchmarkMatchesInvalid1000(b *testing.B) {
	ls, match := benchmarkMatchesSetup("foo", 1000)
	logger := hivetest.Logger(b)
	b.ReportAllocs()

	for b.Loop() {
		MatchesRequirements(logger, ls.requirements, match)
	}
}

func BenchmarkMatchesValid1000Parallel(b *testing.B) {
	ls, match := benchmarkMatchesSetup("42", 1000)
	logger := hivetest.Logger(b)
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			MatchesRequirements(logger, ls.requirements, match)
		}
	})
}

func BenchmarkMatchesInvalid1000Parallel(b *testing.B) {
	ls, match := benchmarkMatchesSetup("foo", 1000)
	logger := hivetest.Logger(b)
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			MatchesRequirements(logger, ls.requirements, match)
		}
	})
}
