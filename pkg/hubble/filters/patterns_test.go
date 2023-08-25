// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileFQDNPattern(t *testing.T) {
	tests := []struct {
		name            string
		fqdnPatterns    []string
		wantErr         bool
		wantErrContains string
		want            string
	}{
		{
			name:            "empty",
			fqdnPatterns:    []string{""},
			wantErr:         true,
			wantErrContains: "empty pattern",
		},
		{
			name:         "simple",
			fqdnPatterns: []string{"cilium.io"},
			want:         `\A(?:cilium\.io)\z`,
		},
		{
			name:         "multiple",
			fqdnPatterns: []string{"cilium.io", "ebpf.io"},
			want:         `\A(?:cilium\.io|ebpf\.io)\z`,
		},
		{
			name:         "star",
			fqdnPatterns: []string{"*.cilium.io"},
			want:         `\A(?:[-.0-9a-z]*\.cilium\.io)\z`,
		},
		{
			name:         "trailing_dot",
			fqdnPatterns: []string{"cilium.io."},
			want:         `\A(?:cilium\.io)\z`,
		},
		{
			name:         "spaces",
			fqdnPatterns: []string{"  cilium.io  "},
			want:         `\A(?:cilium\.io)\z`,
		},
		{
			name:         "upper_case",
			fqdnPatterns: []string{"CILIUM.IO"},
			want:         `\A(?:cilium\.io)\z`,
		},
		{
			name:         "spaces_trailing_dot_upper_case",
			fqdnPatterns: []string{"  CILIUM.IO.  "},
			want:         `\A(?:cilium\.io)\z`,
		},
		{
			name:         "underscores",
			fqdnPatterns: []string{"_ldap._tcp.example.com"},
			want:         `\A(?:_ldap\._tcp\.example\.com)\z`,
		},
		{
			name:            "empty_after_trim",
			fqdnPatterns:    []string{"  .  "},
			wantErr:         true,
			wantErrContains: "empty pattern",
		},
		{
			name:            "invalid rune",
			fqdnPatterns:    []string{"?"},
			wantErr:         true,
			wantErrContains: "invalid rune in pattern",
		},
		{
			name:            "multiple_trailing_dots",
			fqdnPatterns:    []string{"cilium.io.."},
			wantErr:         true,
			wantErrContains: "multiple trailing dots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileFQDNPattern(tt.fqdnPatterns)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestCompileNodeNamePatterns(t *testing.T) {
	type test struct {
		name             string
		nodeNamePatterns []string
		wantErr          bool
		wantErrContains  string
		want             string
	}

	tests := []test{
		{
			name:             "all",
			nodeNamePatterns: []string{"/"},
			want:             `\A(?:(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*)/(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*))\z`,
		},
		{
			name:             "node_pattern_only",
			nodeNamePatterns: []string{"runtime1"},
			want:             `\A(?:(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*)/runtime1)\z`,
		},
		{
			name:             "cluster_pattern_only",
			nodeNamePatterns: []string{"cluster-name/"},
			want:             `\A(?:cluster-name/(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*))\z`,
		},
		{
			name:             "wildcard_node_pattern",
			nodeNamePatterns: []string{"k8s*"},
			want:             `\A(?:(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*)/k8s[-.0-9a-z]*)\z`,
		},
		{
			name:             "multiple_patterns",
			nodeNamePatterns: []string{"runtime1", "test-cluster/k8s1"},
			want:             `\A(?:(?:[-0-9_a-z]+(?:\.[-0-9_a-z]+)*)/runtime1|test-cluster/k8s1)\z`,
		},
		{
			name:             "empty_pattern",
			nodeNamePatterns: []string{""},
			wantErr:          true,
			wantErrContains:  "empty pattern",
		},
		{
			name:             "invalid_rune_in_node_pattern",
			nodeNamePatterns: []string{"?"},
			wantErr:          true,
			wantErrContains:  "invalid rune in pattern",
		},
		{
			name:             "invalid_rune_in_cluster_pattern",
			nodeNamePatterns: []string{"?/"},
			wantErr:          true,
			wantErrContains:  "invalid rune in pattern",
		},
		{
			name:             "too_many_slashes",
			nodeNamePatterns: []string{"default/runtime1/k8s1"},
			wantErr:          true,
			wantErrContains:  "too many slashes in pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileNodeNamePattern(tt.nodeNamePatterns)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
