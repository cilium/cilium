// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/time"
)

func TestCompareFlowLogConfigs(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Minute)

	cases := []struct {
		name          string
		currentConfig *FlowLogConfig
		newConfig     *FlowLogConfig
		expectEqual   bool
	}{
		{
			name:          "should equal for same path",
			currentConfig: &FlowLogConfig{FilePath: "path"},
			newConfig:     &FlowLogConfig{FilePath: "path"},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different path",
			currentConfig: &FlowLogConfig{FilePath: "path"},
			newConfig:     &FlowLogConfig{FilePath: "other"},
			expectEqual:   false,
		},
		{
			name:          "should equal for same end date",
			currentConfig: &FlowLogConfig{End: &now},
			newConfig:     &FlowLogConfig{End: &now},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different end date",
			currentConfig: &FlowLogConfig{End: &now},
			newConfig:     &FlowLogConfig{End: &future},
			expectEqual:   false,
		},
		{
			name:          "should equal for same fieldmask",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"a", "b"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same fieldmask in different order",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"b", "a"}},
			expectEqual:   true,
		},
		{
			name:          "should not equal for different fieldmask",
			currentConfig: &FlowLogConfig{FieldMask: []string{"a", "b"}},
			newConfig:     &FlowLogConfig{FieldMask: []string{"c", "b"}},
			expectEqual:   false,
		},
		{
			name: "should equal for same include filters in different order",
			currentConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different include filters",
			currentConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{IncludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name: "should equal for same exclude filters in different order",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should not equal for different exclude filters",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					SourcePod: []string{"kube-system/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name:        "should equal for null current config and null new config",
			expectEqual: true,
		},
		{
			name:        "should not equal for null current config and not null new config",
			newConfig:   &FlowLogConfig{},
			expectEqual: false,
		},
		{
			name:          "should not equal for not null current config and null new config",
			currentConfig: &FlowLogConfig{},
			expectEqual:   false,
		},
		{
			name: "should not equal when current filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
				nil,
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			expectEqual: false,
		},
		{
			name: "should not equal when new filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				{
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
					SourcePod: []string{"default/"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			expectEqual: false,
		},
		{
			name: "should equal when current and new filters are nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
			}},
			expectEqual: true,
		},
		{
			name: "should equal when current and new filters have nils",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				nil,
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
				nil,
			}},
			expectEqual: true,
		},
		{
			name: "should equal when nil is substituted by empty instance",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{nil},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{{}},
				},
			}},
			expectEqual: true,
		},
		{
			name: "should equal when empty instance is substituted by nil",
			currentConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{{}},
				},
			}},
			newConfig: &FlowLogConfig{ExcludeFilters: FlowFilters{
				{
					TcpFlags: []*flow.TCPFlags{nil},
				},
			}},
			expectEqual: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentConfig.equals(tc.newConfig)
			assert.Equal(t, tc.expectEqual, result)
		})
	}
}
