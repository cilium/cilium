// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/assert"
)

func TestListenerHasDuplicateFilterChainMatch(t *testing.T) {
	tests := []struct {
		name            string
		listener        *envoy_config_listener.Listener
		expectDuplicate bool
	}{
		{
			name:     "no filter chains",
			listener: &envoy_config_listener.Listener{},
		},
		{
			name:     "single filter chain",
			listener: listenerWithFilterChains(t, &envoy_config_listener.FilterChainMatch{ServerNames: []string{"one.example.com"}}),
		},
		{
			name: "unique filter chain matches",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"one.example.com"}},
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"two.example.com"}},
			),
		},
		{
			name: "duplicate filter chain match",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}},
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}},
			),
			expectDuplicate: true,
		},
		{
			name: "duplicate empty filter chain matches",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{},
				&envoy_config_listener.FilterChainMatch{},
			),
			expectDuplicate: true,
		},
		{
			name: "duplicate nil filter chain matches",
			listener: listenerWithFilterChains(t,
				nil,
				nil,
			),
			expectDuplicate: true,
		},
		{
			name: "differing transport protocol is not a duplicate",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}, TransportProtocol: "tls"},
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}, TransportProtocol: "raw_buffer"},
			),
		},
		{
			name: "same server names with matching transport protocol is a duplicate",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}, TransportProtocol: "tls"},
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"same.example.com"}, TransportProtocol: "tls"},
			),
			expectDuplicate: true,
		},
		{
			// Known limitation: the validator is order-sensitive, so it does
			// not flag these as duplicates. Envoy will later reject them.
			name: "server name order difference not detected (known limitation vs Envoy)",
			listener: listenerWithFilterChains(t,
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"a.example.com", "b.example.com"}},
				&envoy_config_listener.FilterChainMatch{ServerNames: []string{"b.example.com", "a.example.com"}},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectDuplicate, listenerHasDuplicateFilterChainMatch(tt.listener))
		})
	}
}

func listenerWithFilterChains(t *testing.T, matches ...*envoy_config_listener.FilterChainMatch) *envoy_config_listener.Listener {
	t.Helper()

	listener := &envoy_config_listener.Listener{}
	for _, match := range matches {
		listener.FilterChains = append(listener.FilterChains, &envoy_config_listener.FilterChain{FilterChainMatch: match})
	}
	return listener
}
