// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy/api"
)

// es builds an EndpointSelector from match labels and match-expression keys
// using the "exists" operator.
func es(matchLabels map[string]string, exprKeys ...string) api.EndpointSelector {
	ls := &slim_metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
	for _, k := range exprKeys {
		ls.MatchExpressions = append(ls.MatchExpressions, slim_metav1.LabelSelectorRequirement{
			Key:      k,
			Operator: slim_metav1.LabelSelectorOpExists,
		})
	}
	return api.EndpointSelector{LabelSelector: ls}
}

func Test_checkExcludedLabels(t *testing.T) {
	log = hivetest.Logger(t)
	// Custom "!excluded" prefix keeps the test independent of the default filter.
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(log, []string{"!excluded"}, nil, ""))

	ingress := []api.IngressRule{{IngressCommonRule: api.IngressCommonRule{
		FromEndpoints: []api.EndpointSelector{es(map[string]string{"app": "frontend"})},
	}}}

	tests := []struct {
		name    string
		policy  parseable
		wantKey string // "" means no finding expected
		wantErr bool   // a non-advisory error (parse failure)
	}{
		{
			name: "CNP endpoint selector",
			policy: &cilium_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "warn", Namespace: "default"},
				Spec:       &api.Rule{EndpointSelector: es(map[string]string{"excluded/zone": "z"}), Ingress: ingress},
			},
			wantKey: "excluded/zone",
		},
		{
			name: "CNP ingress selector",
			policy: &cilium_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "warn-ingress", Namespace: "default"},
				Spec: &api.Rule{
					EndpointSelector: es(map[string]string{"app": "web"}),
					Ingress: []api.IngressRule{{IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{es(map[string]string{"excluded/region": "r"})},
					}}},
				},
			},
			wantKey: "excluded/region",
		},
		{
			name: "clean CNP reports nothing",
			policy: &cilium_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "clean", Namespace: "default"},
				Spec:       &api.Rule{EndpointSelector: es(map[string]string{"app": "web"}), Ingress: ingress},
			},
		},
		{
			name: "CCNP endpoint selector",
			policy: &cilium_v2.CiliumClusterwideNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ccnp-warn"},
				Spec:       &api.Rule{EndpointSelector: es(map[string]string{"excluded/zone": "z"}), Ingress: ingress},
			},
			wantKey: "excluded/zone",
		},
		{
			name: "clean CCNP reports nothing",
			policy: &cilium_v2.CiliumClusterwideNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ccnp-clean"},
				Spec:       &api.Rule{EndpointSelector: es(map[string]string{"app": "web"}), Ingress: ingress},
			},
		},
		{
			// No ingress/egress -> Parse() rejects it.
			name: "unparseable policy surfaces the parse error",
			policy: &cilium_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "norules", Namespace: "default"},
				Spec:       &api.Rule{EndpointSelector: es(map[string]string{"app": "x"})},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkExcludedLabels(tt.policy)
			switch {
			case tt.wantErr:
				require.Error(t, err)
				require.NotErrorIs(t, err, errExcludedLabels)
			case tt.wantKey == "":
				require.NoError(t, err)
			default:
				require.ErrorIs(t, err, errExcludedLabels)
				require.Contains(t, err.Error(), tt.wantKey)
			}
		})
	}
}

func Test_excludedSelectorKeys(t *testing.T) {
	// Register a custom "!excluded" ignore prefix so the test is independent of
	// the default filter expressions in pkg/labelsfilter/filter.go.
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), []string{"!excluded"}, nil, ""))

	tests := []struct {
		name     string
		selector api.EndpointSelector
		want     []string
	}{
		{
			name:     "excluded label in matchLabels is excluded",
			selector: es(map[string]string{"excluded/zone": "us-east-1a"}),
			want:     []string{"excluded/zone"},
		},
		{
			name:     "excluded label with explicit k8s source is excluded",
			selector: es(map[string]string{"k8s:excluded/region": "us-east-1"}),
			want:     []string{"excluded/region"},
		},
		{
			name:     "excluded label in matchExpressions is excluded",
			selector: es(nil, "excluded/zone"),
			want:     []string{"excluded/zone"},
		},
		{
			name:     "non-excluded label is kept",
			selector: es(map[string]string{"allowed/name": "nginx"}),
			want:     nil,
		},
		{
			name: "mixed selector only reports the excluded key",
			selector: es(map[string]string{
				"excluded/zone": "us-east-1a",
				"app":           "backend",
			}),
			want: []string{"excluded/zone"},
		},
		{
			name:     "nil label selector returns nothing",
			selector: api.EndpointSelector{},
			want:     nil,
		},
		{
			name:     "empty (wildcard) selector returns nothing",
			selector: es(nil),
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := excludedSelectorKeys(tt.selector)
			require.Equal(t, tt.want, got)
		})
	}
}
