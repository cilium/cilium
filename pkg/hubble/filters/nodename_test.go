// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func TestNodeFilter(t *testing.T) {
	tests := []struct {
		name            string
		nodeName        []string
		wantErr         bool
		wantErrContains string
		want            map[string]bool
	}{
		{
			name: "no_filter",
			want: map[string]bool{
				"default/k8s1": true,
				"k8s1":         true,
				"":             true, // with no filter, even empty node names match
			},
		},
		{
			name:     "everything",
			nodeName: []string{"/"},
			want: map[string]bool{
				"default/k8s1": true,
				"k8s1":         true,
				"":             false, // with a filter, empty node names never match
			},
		},
		{
			name:     "literal_cluster_pattern",
			nodeName: []string{"cluster-name/"},
			want: map[string]bool{
				"cluster-name/k8s1": true,
				"cluster-name/k8s2": true,
				"default/k8s1":      false,
				"k8s1":              false,
			},
		},
		{
			name:     "literal_node_pattern",
			nodeName: []string{"k8s1"},
			want: map[string]bool{
				"default/k8s1": true,
				"default/k8s2": false,
				"k8s1":         true,
			},
		},
		{
			name:     "literal_node_patterns",
			nodeName: []string{"k8s1", "runtime1"},
			want: map[string]bool{
				"default/k8s1":     true,
				"default/k8s2":     false,
				"default/runtime1": true,
				"k8s1":             true,
			},
		},
		{
			name:     "node_wildcard_pattern",
			nodeName: []string{"k8s*"},
			want: map[string]bool{
				"default/k8s1":     true,
				"default/runtime1": false,
				"k8s1":             true,
			},
		},
		{
			name:     "cluster_wildcard_pattern",
			nodeName: []string{"cluster-*/k8s1"},
			want: map[string]bool{
				"cluster-1/k8s1": true,
				"cluster-1/k8s2": false,
				"default/k8s1":   false,
				"k8s1":           false,
			},
		},
		{
			name:     "cluster_pattern_and_node_wildcard_pattern",
			nodeName: []string{"cluster-name/*.com"},
			want: map[string]bool{
				"cluster-name/foo.com":     true,
				"cluster-name/foo.bar.com": true,
				"cluster-name/foo.com.org": false,
				"default/foo.com":          false,
				"k8s1":                     false,
			},
		},
		{
			name:            "invalid_empty_pattern",
			nodeName:        []string{""},
			wantErr:         true,
			wantErrContains: "empty pattern",
		},
		{
			name:            "invalid_cluster_pattern",
			nodeName:        []string{"cluster|name/"},
			wantErr:         true,
			wantErrContains: "invalid rune in pattern",
		},
		{
			name:            "invalid_node_pattern",
			nodeName:        []string{"cluster-name/node|name"},
			wantErr:         true,
			wantErrContains: "invalid rune in pattern",
		},
		{
			name:            "too_many_slashes",
			nodeName:        []string{"cluster-name/node-name/more"},
			wantErr:         true,
			wantErrContains: "too many slashes in pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := []*flowpb.FlowFilter{
				{
					EventType: []*flowpb.EventTypeFilter{
						{
							Type: api.MessageTypeAccessLog,
						},
					},
					NodeName: tt.nodeName,
				},
			}
			fl, err := BuildFilterList(context.Background(), ff, []OnBuildFilter{&NodeNameFilter{}})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			for nodeName, want := range tt.want {
				ev := &v1.Event{
					Event: &flowpb.Flow{
						EventType: &flowpb.CiliumEventType{
							Type: api.MessageTypeAccessLog,
						},
						NodeName: nodeName,
					},
				}
				assert.Equal(t, want, fl.MatchOne(ev), nodeName)
			}
		})
	}
}
