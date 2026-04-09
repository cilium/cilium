// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestCheckEndpointSelectorNamespace(t *testing.T) {
	tests := []struct {
		name      string
		rule      *api.Rule
		namespace string
		wantErr   bool
	}{
		{
			name: "no namespace label in selector",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   false,
		},
		{
			name: "matching namespace in selector",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"k8s:io.kubernetes.pod.namespace": "foo",
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   false,
		},
		{
			name: "mismatched namespace in selector",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"k8s:io.kubernetes.pod.namespace": "bar",
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   true,
		},
		{
			name: "nil label selector",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: nil,
				},
			},
			namespace: "foo",
			wantErr:   false,
		},
		{
			name: "cluster-wide policy with namespace in selector",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"k8s:io.kubernetes.pod.namespace": "foo",
						},
					},
				},
			},
			namespace: "",
			wantErr:   false,
		},
		{
			name: "namespace via match expression",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "k8s:io.kubernetes.pod.namespace",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"bar"},
							},
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   true,
		},
		{
			name: "matching namespace via match expression",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "k8s:io.kubernetes.pod.namespace",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{"foo"},
							},
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   false,
		},
		{
			name: "other label with namespace-like key is not affected",
			rule: &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"any:io.kubernetes.pod.namespace": "bar",
						},
					},
				},
			},
			namespace: "foo",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkEndpointSelectorNamespace(tt.rule, tt.namespace)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
