// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/utils"
)

func OriginForTest(m map[CachedSelector]labels.LabelArrayList) map[CachedSelector]ruleOrigin {
	res := make(map[CachedSelector]ruleOrigin, len(m))
	for cs, lbls := range m {
		res[cs] = makeRuleOrigin(lbls, nil)
	}
	return res
}

func OriginLogsForTest(m map[CachedSelector]string) map[CachedSelector]ruleOrigin {
	res := make(map[CachedSelector]ruleOrigin, len(m))
	for cs, log := range m {
		res[cs] = makeSingleRuleOrigin(nil, log)
	}
	return res
}

func TestRuleOrigin(t *testing.T) {
	lbls1 := labels.NewLabelsFromSortedList("k8s:a=1;k8s:b=1").LabelArray()
	lbls2 := labels.NewLabelsFromSortedList("k8s:a=2;k8s:b=2").LabelArray()

	ro := makeSingleRuleOrigin(lbls1, "log1")
	require.ElementsMatch(t, labels.LabelArrayList{lbls1}, ro.Value().LabelArray())
	require.ElementsMatch(t, []string{"log1"}, ro.Value().log.List())

	ro = ro.Merge(makeSingleRuleOrigin(lbls2, "log2"))
	require.ElementsMatch(t, labels.LabelArrayList{lbls1, lbls2}, ro.Value().LabelArray())
	require.ElementsMatch(t, []string{"log1", "log2"}, ro.Value().log.List())

	ro = ro.Merge(makeSingleRuleOrigin(lbls2, "log2"))
	require.ElementsMatch(t, labels.LabelArrayList{lbls1, lbls2}, ro.Value().LabelArray())
	require.ElementsMatch(t, []string{"log1", "log2"}, ro.Value().log.List())
}

func TestOriginMerge(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// A can access B with TCP on port 80 with HTTP GET on path "/"
	rule1 := api.Rule{
		Log: api.LogConfig{
			Value: "rule1",
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}
	// A can access B with TCP on port 80 without HTTP requirements
	rule2 := api.Rule{
		Log: api.LogConfig{
			Value: "rule2",
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	entries := utils.RulesToPolicyEntries(api.Rules{&rule1, &rule2})
	// set priorities so that rule2 overrides rule1
	entries[0].Priority = 1

	// Expected incorrectly has rule origin from both rules!
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		Ingress: false,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil,
		},
		RuleOrigin: OriginLogsForTest(map[CachedSelector]string{
			td.cachedSelectorB: "rule2",
		}),
	}})

	td.policyMapEqualsPolicyEntries(t, nil, expected, entries...)
}
