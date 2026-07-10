// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getFields(t *testing.T) {
	tests := []struct {
		name      string
		structure map[string]any
		expected  []string
		err       error
	}{
		{
			name:      "nil structure",
			structure: nil,
			expected:  []string{},
			err:       nil,
		},
		{
			name: "empty structure",
			structure: map[string]any{
				"": "",
			},
			expected: []string{""},
			err:      nil,
		},
		{
			name: "simple structure",
			structure: map[string]any{
				"spec": "",
			},
			expected: []string{"spec"},
			err:      nil,
		},
		{
			name: "nested structure",
			structure: map[string]any{
				"spec": map[string]any{
					"more":   "",
					"fields": "",
					"another": map[string]any{
						"field": "",
					},
				},
			},
			expected: []string{"spec.more", "spec.fields", "spec.another.field"},
			err:      nil,
		},
		{
			name: `contains "matchLabels"`,
			structure: map[string]any{
				"spec": map[string]any{
					"endpointSelector": map[string]any{
						"matchLabels": map[string]any{
							"app": "",
						},
					},
				},
			},
			expected: []string{"spec.endpointSelector.matchLabels"},
			err:      nil,
		},
		{
			name: `contains multiple labels inside multiple "matchLabels"`,
			structure: map[string]any{
				"spec": map[string]any{
					"endpointSelector": map[string]any{
						"matchLabels": map[string]any{
							"app":      "",
							"key":      "",
							"operator": "",
						},
					},
				},
			},
			expected: []string{"spec.endpointSelector.matchLabels"},
			err:      nil,
		},
		{
			name: `contains multiple labels inside "matchLabels" based on real policy`,
			structure: map[string]any{
				"specs": []any{
					map[string]any{
						"description": "Policy to test multiple rules in a single file",
						"endpointSelector": map[string]any{
							"matchLabels": map[string]any{
								"app":     "",
								"version": "",
							},
						},
						"ingress": []any{
							map[string]any{
								"fromEndpoints": []any{
									map[string]any{
										"matchLabels": map[string]any{
											"app":     "",
											"track":   "",
											"version": "",
										},
									},
								},
							},
						},
					},
					map[string]any{
						"endpointSelector": map[string]any{
							"matchLabels": map[string]any{
								"app":     "details",
								"track":   "stable",
								"version": "v1",
							},
						},
						"ingress": []any{
							map[string]any{
								"fromEndpoints": []any{
									map[string]any{
										"matchLabels": map[string]any{
											"app":     "productpage",
											"track":   "stable",
											"version": "v1",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"specs.0.description",
				"specs.0.endpointSelector.matchLabels",
				"specs.1.endpointSelector.matchLabels",
				"specs.0.ingress.0.fromEndpoints.0.matchLabels",
				"specs.1.ingress.0.fromEndpoints.0.matchLabels"},
			err: nil,
		},
		{
			name: `contains "matchLabels" and "matchExpressions" based on real policy`,
			structure: map[string]any{
				"spec": map[string]any{
					"description": "Policy to test matchExpressions key",
					"endpointSelector": map[string]any{
						"matchLabels": map[string]any{
							"id": "app1",
						},
					},
					"ingress": []any{
						map[string]any{
							"fromEndpoints": []any{
								map[string]any{
									"matchExpressions": []any{
										map[string]any{
											"key":      "",
											"operator": "Exists",
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"spec.description", "spec.endpointSelector.matchLabels",
				"spec.ingress.0.fromEndpoints.0.matchExpressions"},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)

		got, err := getFields(tt.structure)
		require.Equal(t, err, tt.err)

		slices.Sort(tt.expected) // Must sort to check slice equality
		slices.Sort(got)
		require.Equal(t, tt.expected, got)
	}
}
