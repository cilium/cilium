// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package template

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRender(t *testing.T) {
	randGen = rand.New(rand.NewPCG(0, 0))

	type args struct {
		data any
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "trim suffix",
			args: args{
				data: struct {
					ExternalTarget string
				}{
					ExternalTarget: "one.one.one.one.",
				},
			},
		},
		{
			name: "ip to cidr",
			args: args{
				data: struct {
					ExternalCIDR string
					ExternalIP   string
				}{
					ExternalCIDR: "10.0.0.0/16",
					ExternalIP:   "10.0.0.2",
				},
			},
		},
		{
			name: "generate dns match pattern",
			args: args{
				data: struct {
					ExternalTarget      string
					ExternalTargetOther string
				}{
					ExternalTarget:      "one.one.one.one.",
					ExternalTargetOther: "k8s.io.",
				},
			},
			want: "out-default.yaml",
		},
		{
			name: "generate dns match pattern",
			args: args{
				data: struct {
					ExternalTarget      string
					ExternalTargetOther string
				}{
					ExternalTarget:      "test.foo-bar.example.default.svc.cluster.local.",
					ExternalTargetOther: "test.bar-baz.example.external.svc.cluster.local",
				},
			},
		},
	}
	for _, tt := range tests {
		testOutFile := "out.yaml"
		if len(tt.want) > 0 {
			testOutFile = tt.want
		}

		t.Run(fmt.Sprintf("%s_%s", tt.name, testOutFile), func(t *testing.T) {
			testDir := fmt.Sprintf("testdata/%s", strings.ReplaceAll(tt.name, " ", "_"))
			tmpl, err := os.ReadFile(fmt.Sprintf("%s/in.yaml", testDir))
			require.NoError(t, err)

			got, err := Render(string(tmpl), tt.args.data)
			require.NoError(t, err)

			expected, err := os.ReadFile(fmt.Sprintf("%s/%s", testDir, testOutFile))
			require.NoError(t, err)
			require.YAMLEq(t, string(expected), got)
		})
	}
}

func TestSplitCommonSuffix(t *testing.T) {
	tests := []struct {
		name       string
		first      string
		second     string
		wantPrefix []string
		wantSuffix []string
	}{
		{
			name:       "Partial common suffix",
			first:      "a.b.c.d.",
			second:     "x.y.c.d",
			wantPrefix: []string{"a", "b"},
			wantSuffix: []string{"c", "d"},
		},
		{
			name:       "No common suffix",
			first:      "a.b",
			second:     "c.d.",
			wantPrefix: []string{"a", "b"},
			wantSuffix: []string{},
		},
		{
			name:       "Full match (first is suffix of second)",
			first:      "c.d",
			second:     "a.b.c.d.",
			wantPrefix: []string{},
			wantSuffix: []string{"c", "d"},
		},
		{
			name:       "Identical slices",
			first:      "a.b.",
			second:     "a.b",
			wantPrefix: []string{},
			wantSuffix: []string{"a", "b"},
		},
		{
			name:       "One slice is empty",
			first:      "a.b",
			second:     "",
			wantPrefix: []string{"a", "b"},
			wantSuffix: []string{},
		},
		{
			name:       "Both slices are empty",
			first:      "",
			second:     "",
			wantPrefix: []string{},
			wantSuffix: []string{},
		},
		{
			name:       "Common elements but not at the end",
			first:      "a.common.b",
			second:     "x.common.y",
			wantPrefix: []string{"a", "common", "b"},
			wantSuffix: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotSuffix := SplitCommonSuffix(tt.first, tt.second, ".")
			require.Equal(t, tt.wantPrefix, gotPrefix)
			require.Equal(t, tt.wantSuffix, gotSuffix)
		})
	}
}
