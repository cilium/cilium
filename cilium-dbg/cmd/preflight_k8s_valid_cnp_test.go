// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

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
