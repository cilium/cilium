// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestValidateCNPEndpointSelectorNamespace(t *testing.T) {
	testCases := []struct {
		name        string
		namespace   string
		matchLabels map[string]string
		wantErr     bool
	}{
		{
			name:        "selector matches another namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": "bar"},
			wantErr:     true,
		},
		{
			name:        "selector matches own namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": "foo"},
			wantErr:     false,
		},
		{
			name:        "selector without namespace match",
			namespace:   "foo",
			matchLabels: map[string]string{"app": "demo-app"},
			wantErr:     false,
		},
		{
			name:        "unprefixed namespace key matching another namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"io.kubernetes.pod.namespace": "bar"},
			wantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: tc.matchLabels,
					},
				},
				Ingress: []api.IngressRule{{}},
			}
			require.NoError(t, spec.ValidateAndSanitize())

			err := validateCNPEndpointSelectorNamespace(tc.namespace, spec)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, "CiliumNetworkPolicy")
				require.ErrorContains(t, err, "endpointSelector")
				require.ErrorContains(t, err, "namespace")
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("nil spec", func(t *testing.T) {
		require.NoError(t, validateCNPEndpointSelectorNamespace("foo", nil))
	})

	t.Run("nil endpoint selector", func(t *testing.T) {
		spec := &api.Rule{
			Ingress: []api.IngressRule{{}},
		}
		require.NoError(t, validateCNPEndpointSelectorNamespace("foo", spec))
	})

	t.Run("matchExpressions In with multiple namespaces", func(t *testing.T) {
		spec := &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s:io.kubernetes.pod.namespace",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"foo", "bar"},
						},
					},
				},
			},
			Ingress: []api.IngressRule{{}},
		}
		require.NoError(t, spec.ValidateAndSanitize())
		require.Error(t, validateCNPEndpointSelectorNamespace("foo", spec))
	})
}
