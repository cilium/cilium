// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
)

func TestNodeFilter(t *testing.T) {
	type test struct {
		name    string
		include [][]string
		exclude [][]string
		wantErr bool
		want    map[string]bool
	}

	tests := []test{
		{
			name: "empty",
			want: map[string]bool{
				"runtime1": true,
			},
		},
		{
			name: "empty",
			want: map[string]bool{
				"runtime1": true,
			},
		},
		{
			name: "include",
			include: [][]string{
				{"runtime1"},
			},
			want: map[string]bool{
				"runtime1": true,
				"k8s1":     false,
			},
		},
		{
			name: "two_includes",
			include: [][]string{
				{"runtime1"},
				{"k8s1"},
			},
			want: map[string]bool{
				"runtime1": true,
				"k8s1":     true,
				"k8s2":     false,
			},
		},
		{
			name: "include_pattern",
			include: [][]string{
				{"*s*"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     true,
				"k8s2":     true,
			},
		},
		{
			name: "include_doublestar_pattern",
			include: [][]string{
				{"cluster-name/**.com"},
			},
			want: map[string]bool{
				"cluster-name/foo.com":     true,
				"cluster-name/foo.bar.com": true,
				"cluster-name/foo.com.org": false,
			},
		},
		{
			name: "exclude",
			exclude: [][]string{
				{"runtime1"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     true,
			},
		},
		{
			name: "include_and_exclude",
			include: [][]string{
				{"*"},
			},
			exclude: [][]string{
				{"*1"},
			},
			want: map[string]bool{
				"runtime1": false,
				"k8s1":     false,
				"k8s2":     true,
			},
		},
		{
			name: "bad_include_pattern",
			include: [][]string{
				{"["},
			},
			wantErr: true,
			want: map[string]bool{
				"runtime1": false,
			},
		},
		{
			name: "bad_exclude_pattern",
			exclude: [][]string{
				{"["},
			},
			wantErr: true,
			want: map[string]bool{
				"runtime1": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			include := makeFlowFilters(tt.include)
			exclude := makeFlowFilters(tt.exclude)
			nodeNameFilter, err := NewNodeNameFilter(include, exclude)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, nodeNameFilter)
				return
			}

			assert.NoError(t, err)
			for nodeName, want := range tt.want {
				assert.Equal(t, want, nodeNameFilter.Match(nodeName))
			}
		})
	}
}

func TestCompileNodeNamePatterns(t *testing.T) {
	type test struct {
		name    string
		nodess  [][]string
		wantErr bool
		wantNil bool
		want    string
	}

	tests := []test{
		{
			name:    "empty1",
			wantNil: true,
		},
		{
			name:    "empty2",
			nodess:  [][]string{},
			wantNil: true,
		},
		{
			name: "empty3",
			nodess: [][]string{
				{},
			},
			wantNil: true,
		},
		{
			name: "literal",
			nodess: [][]string{
				{"runtime1"},
			},
			want: `\A(?:runtime1)\z`,
		},
		{
			name: "literals1",
			nodess: [][]string{
				{"runtime1", "test-cluster/k8s1"},
			},
			want: `\A(?:runtime1|test-cluster/k8s1)\z`,
		},
		{
			name: "literals2",
			nodess: [][]string{
				{"runtime1"},
				{"test-cluster/k8s1"},
			},
			want: `\A(?:runtime1|test-cluster/k8s1)\z`,
		},
		{
			name: "doublestar",
			nodess: [][]string{
				{"cluster-name/**"},
			},
			want: `\A(?:cluster-name/(?:[\-0-9a-z]+(?:\.(?:[\-0-9a-z]+))*))\z`,
		},
		{
			name: "complex_pattern",
			nodess: [][]string{
				{"runtime1.domain.com"},
				{"test-cluster/k8s*"},
			},
			want: `\A(?:runtime1\.domain\.com|test-cluster/k8s[\-0-9a-z]*)\z`,
		},
		{
			name: "invalid_rune",
			nodess: [][]string{
				{"_"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileNodeNamePatterns(makeFlowFilters(tt.nodess))
			switch {
			case tt.wantErr:
				assert.Error(t, err)
				assert.Nil(t, got)
			case tt.wantNil:
				assert.NoError(t, err)
				assert.Nil(t, got)
			default:
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

// makeFlowFilters creates slice of flowpb.FlowFilters from a slice of string
// slices.
func makeFlowFilters(nodeNames [][]string) []*flowpb.FlowFilter {
	flowFilters := make([]*flowpb.FlowFilter, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		ff := &flowpb.FlowFilter{
			NodeName: nodeName,
		}
		flowFilters = append(flowFilters, ff)
	}
	return flowFilters
}
