// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestLabelSelectorToRequirements(t *testing.T) {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "NotIn",
				Values:   []string{"default"},
			},
		},
	}

	expRequirements := Requirements{}
	req := NewRequirement("any.foo", selection.Equals, []string{"bar"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("any.foo", selection.NotIn, []string{"default"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("k8s.baz", selection.Equals, []string{"alice"})
	expRequirements = append(expRequirements, req)

	require.Equal(t, expRequirements, LabelSelectorToRequirements(labelSelector))
}

func TestUnsanitizedLabelSelectorToRequirements(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector *slim_metav1.LabelSelector
		wantErr       bool
	}{
		{
			name: "no source prefix - simple keys in matchLabels",
			labelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "bar",
					"name": "test",
				},
			},
		},
		{
			name: "no source prefix - dotted key in matchLabels",
			labelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":    "my-app",
					"app.kubernetes.io/part-of": "platform",
				},
			},
		},
		{
			name: "no source prefix - matchExpressions only",
			labelSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "app", Operator: slim_metav1.LabelSelectorOpExists},
					{Key: "app.kubernetes.io/name", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"my-app", "other-app"}},
					{Key: "env", Operator: slim_metav1.LabelSelectorOpNotIn, Values: []string{"default"}},
				},
			},
		},
		{
			name: "with source prefix - matchLabels",
			labelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:app":                       "bar",
					"any:env":                       "prod",
					"k8s:app.kubernetes.io/part-of": "testing",
				},
			},
		},
		{
			name: "with source prefix - matchExpressions",
			labelSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "k8s:app", Operator: slim_metav1.LabelSelectorOpExists},
					{Key: "any:name", Operator: slim_metav1.LabelSelectorOpNotIn, Values: []string{"default"}},
					{Key: "k8s:app.kubernetes.io/part-of", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"testing", "staging"}},
				},
			},
		},
		{
			name: "matchLabels and matchExpressions",
			labelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":     "bar",
					"k8s:env": "prod",
				},
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "app.kubernetes.io/name", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"my-app"}},
					{Key: "any:version", Operator: slim_metav1.LabelSelectorOpExists},
				},
			},
		},
		{
			name: "invalid label key in matchLabels",
			labelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s:key:bad": "bar",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid label key in matchExpressions",
			labelSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "key!bad", Operator: slim_metav1.LabelSelectorOpExists},
					{Key: "k8s:key:bad", Operator: slim_metav1.LabelSelectorOpExists},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid operator in matchExpressions",
			labelSelector: &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{Key: "app", Operator: "InvalidOp"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnsanitizedLabelSelectorToRequirements(tt.labelSelector)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			es := api.EndpointSelector{LabelSelector: tt.labelSelector.DeepCopy()}
			require.NoError(t, es.Sanitize())
			expected := LabelSelectorToRequirements(es.LabelSelector)

			require.Equal(t, expected, result)
		})
	}
}
