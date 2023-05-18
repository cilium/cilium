// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"sort"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func (s *CNPValidationSuite) Test_getFields(c *C) {
	tests := []struct {
		name      string
		structure map[string]interface{}
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
			structure: map[string]interface{}{
				"": "",
			},
			expected: []string{""},
			err:      nil,
		},
		{
			name: "simple structure",
			structure: map[string]interface{}{
				"spec": "",
			},
			expected: []string{"spec"},
			err:      nil,
		},
		{
			name: "nested structure",
			structure: map[string]interface{}{
				"spec": map[string]interface{}{
					"more":   "",
					"fields": "",
					"another": map[string]interface{}{
						"field": "",
					},
				},
			},
			expected: []string{"spec.more", "spec.fields", "spec.another.field"},
			err:      nil,
		},
		{
			name: `contains "matchLabels"`,
			structure: map[string]interface{}{
				"spec": map[string]interface{}{
					"endpointSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
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
			structure: map[string]interface{}{
				"spec": map[string]interface{}{
					"endpointSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
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
			structure: map[string]interface{}{
				"specs": []interface{}{
					map[string]interface{}{
						"description": "Policy to test multiple rules in a single file",
						"endpointSelector": map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"app":     "",
								"version": "",
							},
						},
						"ingress": []interface{}{
							map[string]interface{}{
								"fromEndpoints": []interface{}{
									map[string]interface{}{
										"matchLabels": map[string]interface{}{
											"app":     "",
											"track":   "",
											"version": "",
										},
									},
								},
							},
						},
					},
					map[string]interface{}{
						"endpointSelector": map[string]interface{}{
							"matchLabels": map[string]interface{}{
								"app":     "details",
								"track":   "stable",
								"version": "v1",
							},
						},
						"ingress": []interface{}{
							map[string]interface{}{
								"fromEndpoints": []interface{}{
									map[string]interface{}{
										"matchLabels": map[string]interface{}{
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
			structure: map[string]interface{}{
				"spec": map[string]interface{}{
					"description": "Policy to test matchExpressions key",
					"endpointSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"id": "app1",
						},
					},
					"ingress": []interface{}{
						map[string]interface{}{
							"fromEndpoints": []interface{}{
								map[string]interface{}{
									"matchExpressions": []interface{}{
										map[string]interface{}{
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
		c.Log(tt.name)

		got, err := getFields(tt.structure)
		c.Assert(tt.err, checker.DeepEquals, err)

		sort.Strings(tt.expected) // Must sort to check slice equality
		sort.Strings(got)
		c.Assert(tt.expected, checker.DeepEquals, got)
	}
}
