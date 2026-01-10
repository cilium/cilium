// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
)

func TestSelectsAllEndpoints(t *testing.T) {
	// Empty endpoint selector slice does NOT equate to a wildcard.
	selectorSlice := EndpointSelectorSlice{}
	require.False(t, selectorSlice.SelectsAllEndpoints())

	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector}
	require.True(t, selectorSlice.SelectsAllEndpoints())

	// Entity "reserved:all" maps to WildcardEndpointSelector
	selectorSlice = EntitySlice{EntityAll}.GetAsEndpointSelectors()
	require.True(t, selectorSlice.SelectsAllEndpoints())

	// Slice that contains wildcard and other selectors still selects all endpoints.
	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector, NewESFromLabels(labels.ParseSelectLabel("bar"))}
	require.True(t, selectorSlice.SelectsAllEndpoints())

	selectorSlice = EndpointSelectorSlice{NewESFromLabels(labels.ParseSelectLabel("bar")), NewESFromLabels(labels.ParseSelectLabel("foo"))}
	require.False(t, selectorSlice.SelectsAllEndpoints())
}

func TestEndpointSelectorMarshalling(t *testing.T) {
	tests := []struct {
		name                string
		inputJSON           string
		expected            EndpointSelector
		sanitizedExepected  EndpointSelector
		sanitizedOutputJSON string
		expectedErr         bool
	}{
		{
			// For empty EndpointSelector we implicitly set the LabelSelector as non-nil
			// during Unmarshalling. This is done to differentiate between Endpoint and Node
			// selectors in policyapi.Rule. Since we have omitempty set on these json tags,
			// only the field(Node/Endpoint Selector) which is present in the JSON input
			// will be Unmarshalled, which helps us identify for which of these two selectors
			// the LabelSelector field is nil and what the user intent was.
			name:      "Empty JSON",
			inputJSON: `{}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector:             &slim_metav1.LabelSelector{},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{}`,
			expectedErr:         false,
		},
		{
			name:      "MatchLabels with no source",
			inputJSON: `{"matchLabels":{"app":"frontend"}}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "frontend"},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"any.app": "frontend"},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{any.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchLabels":{"any:app":"frontend"}}`,
			expectedErr:         false,
		},
		{
			name:      "MatchLabels with source `k8s`",
			inputJSON: `{"matchLabels":{"k8s:app":"frontend"}}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s:app": "frontend"},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s.app": "frontend"},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{k8s.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchLabels":{"k8s:app":"frontend"}}`,
			expectedErr:         false,
		},
		{
			name:      "MatchExpressions with no source",
			inputJSON: `{"matchExpressions":[{"key":"role","operator":"In","values":["database"]}]}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "any.role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{LabelSelectorRequirement{Key:any.role,Operator:In,Values:[database],},},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchExpressions":[{"key":"any:role","operator":"In","values":["database"]}]}`,
			expectedErr:         false,
		},
		{
			name:      "MatchExpressions with source `k8s`",
			inputJSON: `{"matchExpressions":[{"key":"k8s:role","operator":"In","values":["database"]}]}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s:role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{LabelSelectorRequirement{Key:k8s.role,Operator:In,Values:[database],},},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchExpressions":[{"key":"k8s:role","operator":"In","values":["database"]}]}`,
			expectedErr:         false,
		},
		{
			name:      "Invalid JSON",
			inputJSON: `{"matchLabels": {"app": "frontend"`,
			expected:  EndpointSelector{},
			sanitizedExepected: EndpointSelector{
				LabelSelector:             &slim_metav1.LabelSelector{},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{}`,
			expectedErr:         true,
		},
		{
			name:      "MatchLabels and MatchExpression with no source",
			inputJSON: `{"matchLabels":{"app":"frontend"},"matchExpressions":[{"key":"role","operator":"In","values":["database"]}]}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"any.app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "any.role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{any.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{LabelSelectorRequirement{Key:any.role,Operator:In,Values:[database],},},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchLabels":{"any:app":"frontend"},"matchExpressions":[{"key":"any:role","operator":"In","values":["database"]}]}`,
			expectedErr:         false,
		},
		{
			name:      "MatchLabels and MatchExpression with k8s source",
			inputJSON: `{"matchLabels":{"k8s:app":"frontend"},"matchExpressions":[{"key":"k8s:role","operator":"In","values":["database"]}]}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s:app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s:role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s.app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s.role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{k8s.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{LabelSelectorRequirement{Key:k8s.role,Operator:In,Values:[database],},},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchLabels":{"k8s:app":"frontend"},"matchExpressions":[{"key":"k8s:role","operator":"In","values":["database"]}]}`,
			expectedErr:         false,
		},
		{
			name:      "MatchLabels and MatchExpression with mixed source",
			inputJSON: `{"matchLabels":{"k8s:app":"frontend"},"matchExpressions":[{"key":"role","operator":"In","values":["database"]}]}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s:app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
			},
			sanitizedExepected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s.app": "frontend"},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "any.role",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"database"},
						},
					},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{k8s.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{LabelSelectorRequirement{Key:any.role,Operator:In,Values:[database],},},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedOutputJSON: `{"matchLabels":{"k8s:app":"frontend"},"matchExpressions":[{"key":"any:role","operator":"In","values":["database"]}]}`,
			expectedErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := EndpointSelector{}

			err := json.Unmarshal([]byte(tt.inputJSON), &es)
			if tt.expectedErr {
				require.ErrorContains(t, err, "unexpected end of JSON input")
				require.Equal(t, tt.expected, es)

				err = es.Sanitize()
				require.NoError(t, err)
				require.Equal(t, tt.sanitizedExepected, es, "Sanitized EndpointSelector")

				marshalledData, err := json.Marshal(es)
				require.NoError(t, err)
				require.Equalf(t, tt.sanitizedOutputJSON, string(marshalledData), "Marshalled Sanitized EndpointSelector")
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, es, "UnMarshalled EndpointSelector")

			esMarshalled, err := json.Marshal(es)
			require.NoError(t, err)
			require.Equalf(t, tt.inputJSON, string(esMarshalled), "Marshalled EndpointSelector")

			err = es.Sanitize()
			require.NoError(t, err)
			require.Equal(t, tt.sanitizedExepected, es, "Sanitized EndpointSelector")

			err = es.Sanitize()
			require.NoError(t, err)
			require.Equal(t, tt.sanitizedExepected, es, "Idempotent EndpointSelector sanitization")

			esSanitizedMarshalled, err := json.Marshal(es)
			require.NoError(t, err)
			require.Equalf(t, tt.sanitizedOutputJSON, string(esSanitizedMarshalled), "Marshalled sanitized EndpointSelector")

			sanitizedEs := EndpointSelector{}
			err = json.Unmarshal(esSanitizedMarshalled, &sanitizedEs)
			require.NoError(t, err)
			err = sanitizedEs.Sanitize()
			require.NoError(t, err)
			require.Equal(t, tt.sanitizedExepected, sanitizedEs, "Idempotent EndpointSelector sanitization and marshalling")
		})
	}
}

func TestEndpointSelectorSanitize(t *testing.T) {
	tests := []struct {
		name       string
		input      EndpointSelector
		expected   EndpointSelector
		shouldFail bool
	}{
		{
			"Empty EndpointSelector",
			EndpointSelector{},
			NewESFromK8sLabelSelector(""),
			false,
		},
		{
			"MatchLabels EndpointSelector",
			EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "frontend"},
				},
			},
			NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"any.app": "frontend"},
			}),
			false,
		},
		{
			"MatchLabels EndpointSelector with source",
			EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s:app": "frontend"},
				},
			},
			NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s.app": "frontend"},
			}),
			false,
		},
		{
			"EndpointSelector from Cilium Labels",
			NewESFromLabels(labels.Label{Key: "app", Source: "k8s", Value: "frontend"}),
			NewESFromK8sLabelSelector("", &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s.app": "frontend"},
			}),
			false,
		},
		{
			"Invalid LabelSelector",
			EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s:k8s:app": "frontend"},
				},
			},
			EndpointSelector{},
			true,
		},
		{
			"Idempotent Sanitize",
			EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s.app": "frontend"},
				},
				sanitized: true,
			},
			EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"k8s.app": "frontend"},
				},
				sanitized: true,
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Sanitize()
			if tt.shouldFail {
				require.False(t, tt.input.sanitized)
				require.ErrorContains(t, err, "invalid label selector")
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, tt.input)
		})
	}
}
