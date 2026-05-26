// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSNIHostnamesIntersect(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "same exact hostname",
			a:    "api.example.test",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "different exact hostnames",
			a:    "api.example.test",
			b:    "web.example.test",
			want: false,
		},
		{
			name: "global wildcard intersects exact hostname",
			a:    "*",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "empty hostname is catch-all",
			a:    "",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "wildcard intersects matching exact hostname",
			a:    "*.example.test",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "wildcard does not match bare suffix",
			a:    "*.example.test",
			b:    "example.test",
			want: false,
		},
		{
			name: "wildcards with shared suffix intersect",
			a:    "*.example.test",
			b:    "*.test",
			want: true,
		},
		{
			name: "wildcards with disjoint suffixes do not intersect",
			a:    "*.example.test",
			b:    "*.example.org",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SNIHostnamesIntersect(tt.a, tt.b))
			assert.Equal(t, tt.want, SNIHostnamesIntersect(tt.b, tt.a))
		})
	}
}
