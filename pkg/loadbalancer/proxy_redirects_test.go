// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyRedirects_ForPort(t *testing.T) {
	tests := []struct {
		name      string
		redirects ProxyRedirects
		port      uint16
		want      *ProxyRedirect
	}{
		{
			name:      "nil redirects",
			redirects: nil,
			port:      80,
			want:      nil,
		},
		{
			name:      "empty redirects",
			redirects: ProxyRedirects{},
			port:      80,
			want:      nil,
		},
		{
			name: "exact port match",
			redirects: ProxyRedirects{
				{ProxyPort: 1000, Ports: []uint16{80}},
				{ProxyPort: 2000, Ports: []uint16{443}},
			},
			port: 443,
			want: &ProxyRedirect{ProxyPort: 2000, Ports: []uint16{443}},
		},
		{
			name: "wildcard match when no exact match",
			redirects: ProxyRedirects{
				{ProxyPort: 1000},
			},
			port: 8080,
			want: &ProxyRedirect{ProxyPort: 1000},
		},
		{
			name: "exact match preferred over wildcard (wildcard first)",
			redirects: ProxyRedirects{
				{ProxyPort: 1000}, // wildcard
				{ProxyPort: 2000, Ports: []uint16{80}},
			},
			port: 80,
			want: &ProxyRedirect{ProxyPort: 2000, Ports: []uint16{80}},
		},
		{
			name: "exact match preferred over wildcard (exact first)",
			redirects: ProxyRedirects{
				{ProxyPort: 2000, Ports: []uint16{80}},
				{ProxyPort: 1000}, // wildcard
			},
			port: 80,
			want: &ProxyRedirect{ProxyPort: 2000, Ports: []uint16{80}},
		},
		{
			name: "wildcard fallback when port not in any exact set",
			redirects: ProxyRedirects{
				{ProxyPort: 1000}, // wildcard
				{ProxyPort: 2000, Ports: []uint16{443}},
			},
			port: 8080,
			want: &ProxyRedirect{ProxyPort: 1000},
		},
		{
			name: "no match when port not in any set and no wildcard",
			redirects: ProxyRedirects{
				{ProxyPort: 1000, Ports: []uint16{80}},
				{ProxyPort: 2000, Ports: []uint16{443}},
			},
			port: 8080,
			want: nil,
		},
		{
			name: "multi-port redirect matches any listed port",
			redirects: ProxyRedirects{
				{ProxyPort: 1000, Ports: []uint16{80, 443}},
			},
			port: 443,
			want: &ProxyRedirect{ProxyPort: 1000, Ports: []uint16{80, 443}},
		},
		{
			name: "first wildcard wins when multiple wildcards exist",
			redirects: ProxyRedirects{
				{ProxyPort: 1000},
				{ProxyPort: 2000},
			},
			port: 80,
			want: &ProxyRedirect{ProxyPort: 1000},
		},
		{
			name: "multiple redirects different ports",
			redirects: ProxyRedirects{
				{ProxyPort: 1000, Ports: []uint16{80}},
				{ProxyPort: 2000, Ports: []uint16{443}},
				{ProxyPort: 3000, Ports: []uint16{8080}},
			},
			port: 8080,
			want: &ProxyRedirect{ProxyPort: 3000, Ports: []uint16{8080}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.redirects.ForPort(tt.port)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestProxyRedirects_Redirects(t *testing.T) {
	redirects := ProxyRedirects{
		{ProxyPort: 1000, Ports: []uint16{80}},
		{ProxyPort: 2000, Ports: []uint16{443}},
	}

	assert.True(t, redirects.Redirects(80))
	assert.True(t, redirects.Redirects(443))
	assert.False(t, redirects.Redirects(8080))
}

func TestProxyRedirects_Empty(t *testing.T) {
	assert.True(t, ProxyRedirects(nil).Empty())
	assert.True(t, ProxyRedirects{}.Empty())
	assert.False(t, ProxyRedirects{{ProxyPort: 1000}}.Empty())
}

func TestProxyRedirects_Equal(t *testing.T) {
	a := ProxyRedirects{
		{ProxyPort: 1000, Ports: []uint16{80}},
		{ProxyPort: 2000, Ports: []uint16{443}},
	}
	b := ProxyRedirects{
		{ProxyPort: 1000, Ports: []uint16{80}},
		{ProxyPort: 2000, Ports: []uint16{443}},
	}
	c := ProxyRedirects{
		{ProxyPort: 1000, Ports: []uint16{80}},
	}

	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(c))
	assert.True(t, ProxyRedirects(nil).Equal(nil))
}

func TestProxyRedirects_String(t *testing.T) {
	assert.Empty(t, ProxyRedirects(nil).String())
	assert.Equal(t, "1000 (ports: [80])", ProxyRedirects{{ProxyPort: 1000, Ports: []uint16{80}}}.String())
	assert.Equal(t, "[1000 (ports: [80]), 2000 (ports: [443])]",
		ProxyRedirects{
			{ProxyPort: 1000, Ports: []uint16{80}},
			{ProxyPort: 2000, Ports: []uint16{443}},
		}.String())
}
