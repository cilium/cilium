// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestParseCiliumRule(t *testing.T) {
	logger := hivetest.Logger(t)

	name := "test-policy"
	namespace := "default"
	clusterName := "test-cluster"
	uid := k8sTypes.UID("test-uid-123")

	nsLabel := labels.ParseSelectLabel(fmt.Sprintf("%s=%s", podPrefixLbl, namespace))
	testLabels := labels.ParseSelectLabelArray("k8s:app=test")

	ruleLabels := ParseToCiliumLabels(namespace, name, uid, nil)
	clusterwideRuleLabels := ParseToCiliumLabels("", name, uid, nil)
	ruleLabelsWithTestLabels := ParseToCiliumLabels(namespace, name, uid, testLabels)

	testES := api.NewESFromLabels(labels.ParseSelectLabel("foo=bar"))
	testESWithAnySource := api.NewESFromLabels(labels.ParseSelectLabel("any:foo=bar"))
	testESWithCustomSource := api.NewESFromLabels(labels.ParseSelectLabel("test:foo=bar"))
	testESWithAnySourceAndNS := api.NewESFromLabels(labels.ParseSelectLabel("any:foo=bar"), nsLabel)

	testLogConfig := api.LogConfig{Value: "test"}

	tests := []struct {
		name        string
		clusterwide bool
		arg         api.Rule
		want        types.PolicyEntries
	}{
		{
			name: "Empty rule",
			arg:  api.Rule{},
			want: types.PolicyEntries{},
		},
		{
			name: "Rule with EndpointSelector",
			arg: api.Rule{
				EndpointSelector: testES,
				Ingress:          []api.IngressRule{{}},
			},
			want: types.PolicyEntries{{
				Subject:     types.NewLabelSelector(testESWithAnySourceAndNS),
				Node:        false,
				Labels:      ruleLabels,
				DefaultDeny: true,
				Ingress:     true,
				Deny:        false,
				L3:          types.Selectors{},
				L4:          api.PortRules{},
			}},
		},
		{
			name: "Rule with Labels and EndpointSelector",
			arg: api.Rule{
				Labels:           testLabels,
				EndpointSelector: testES,
				Ingress:          []api.IngressRule{{}},
			},
			want: types.PolicyEntries{{
				Subject:     types.NewLabelSelector(testESWithAnySourceAndNS),
				Node:        false,
				Labels:      ruleLabelsWithTestLabels,
				DefaultDeny: true,
				Ingress:     true,
				Deny:        false,
				L3:          types.Selectors{},
				L4:          api.PortRules{},
			}},
		},
		{
			name:        "Clusterwide rule with EndpointSelector",
			clusterwide: true,
			arg: api.Rule{
				EndpointSelector: testESWithCustomSource,
				Ingress:          []api.IngressRule{{}},
			},
			want: types.PolicyEntries{{
				Subject:     types.NewLabelSelector(testESWithCustomSource),
				Node:        false,
				Labels:      clusterwideRuleLabels,
				DefaultDeny: true,
				Ingress:     true,
				Deny:        false,
				L3:          types.Selectors{},
				L4:          api.PortRules{},
			}},
		},
		{
			name: "Rule with NodeSelector",
			arg: api.Rule{
				NodeSelector: testES,
				Ingress:      []api.IngressRule{{}},
			},
			want: types.PolicyEntries{{
				Subject:     types.NewLabelSelector(testESWithAnySource),
				Node:        true,
				Labels:      ruleLabels,
				DefaultDeny: true,
				Ingress:     true,
				Deny:        false,
				L3:          types.Selectors{},
				L4:          api.PortRules{},
			}},
		},
		{
			name: "Rule with log config",
			arg: api.Rule{
				EndpointSelector: testES,
				Ingress:          []api.IngressRule{{}},
				Log:              testLogConfig,
			},
			want: types.PolicyEntries{{
				Subject:     types.NewLabelSelector(testESWithAnySourceAndNS),
				Node:        false,
				Labels:      ruleLabels,
				DefaultDeny: true,
				Ingress:     true,
				Deny:        false,
				Log:         testLogConfig,
				L3:          types.Selectors{},
				L4:          api.PortRules{},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := namespace
			if tt.clusterwide {
				ns = ""
			}
			entries := ParseCiliumRule(logger, clusterName, ns, name, uid, &tt.arg)
			require.Equal(t, tt.want, entries)
		})
	}
}
