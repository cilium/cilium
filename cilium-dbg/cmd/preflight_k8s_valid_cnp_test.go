// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy/api"
)

func newCNP(name string, spec map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
		"spec":       spec,
	}}
}

func mockLister(items ...unstructured.Unstructured) policyLister {
	return func(context.Context, string) (*unstructured.UnstructuredList, error) {
		return &unstructured.UnstructuredList{Items: items}, nil
	}
}

func TestValidatePolicies(t *testing.T) {
	log = hivetest.Logger(t)
	// Custom "!excluded" prefix keeps the test independent of the default filter.
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(log, []string{"!excluded"}, nil, ""))

	ingress := []any{map[string]any{
		"fromEndpoints": []any{map[string]any{"matchLabels": map[string]any{"app": "frontend"}}},
	}}

	excludedCNP := newCNP("warn", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"excluded/zone": "z"}},
		"ingress":          ingress,
	})
	cleanCNP := newCNP("clean", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"ingress":          ingress,
	})
	// No ingress/egress -> Parse() rejects it ("rule must have at least one of ...").
	noRulesCNP := newCNP("norules", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
	})

	okValidate := func(*unstructured.Unstructured) error { return nil }

	t.Run("excluded label is detected", func(t *testing.T) {
		excluded, err := validatePolicies(context.Background(),
			mockLister(excludedCNP), okValidate, parseCNPRules, "CiliumNetworkPolicy")
		require.NoError(t, err)
		require.True(t, excluded)
	})

	t.Run("clean policy reports nothing", func(t *testing.T) {
		excluded, err := validatePolicies(context.Background(),
			mockLister(cleanCNP), okValidate, parseCNPRules, "CiliumNetworkPolicy")
		require.NoError(t, err)
		require.False(t, excluded)
	})

	t.Run("validation error is returned but labels are still checked", func(t *testing.T) {
		failValidate := func(*unstructured.Unstructured) error { return errors.New("invalid") }
		excluded, err := validatePolicies(context.Background(),
			mockLister(excludedCNP), failValidate, parseCNPRules, "CiliumNetworkPolicy")
		require.Error(t, err)
		require.True(t, excluded)
	})

	t.Run("one excluded among several policies", func(t *testing.T) {
		excluded, err := validatePolicies(context.Background(),
			mockLister(cleanCNP, excludedCNP), okValidate, parseCNPRules, "CiliumNetworkPolicy")
		require.NoError(t, err)
		require.True(t, excluded)
	})

	t.Run("unparseable policy returns an error", func(t *testing.T) {
		excluded, err := validatePolicies(context.Background(),
			mockLister(noRulesCNP), okValidate, parseCNPRules, "CiliumNetworkPolicy")
		require.Error(t, err)
		require.False(t, excluded)
	})
}

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

func TestExcludedSelectorKeys(t *testing.T) {
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
