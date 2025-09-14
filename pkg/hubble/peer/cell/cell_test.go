// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPort(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected int
		hasError bool
	}{
		{
			name:     "IPv4 with port",
			address:  "127.0.0.1:4244",
			expected: 4244,
		},
		{
			name:     "IPv6 with port",
			address:  "[::1]:4244",
			expected: 4244,
		},
		{
			name:     "Port only",
			address:  ":4244",
			expected: 4244,
		},
		{
			name:     "Invalid format",
			address:  "invalid",
			hasError: true,
		},
		{
			name:     "Invalid port",
			address:  "localhost:abc",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, err := getPort(tt.address)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, port)
			}
		})
	}
}

// mockHubbleConfig implements HubbleConfig interface for testing
type mockHubbleConfig struct {
	listenAddress string
	preferIPv6    bool
}

func (m *mockHubbleConfig) GetListenAddress() string {
	return m.listenAddress
}

func (m *mockHubbleConfig) GetPreferIPv6() bool {
	return m.preferIPv6
}

func TestHubbleConfigInterface(t *testing.T) {
	config := &mockHubbleConfig{
		listenAddress: "0.0.0.0:4244",
		preferIPv6:    true,
	}

	assert.Equal(t, "0.0.0.0:4244", config.GetListenAddress())
	assert.True(t, config.GetPreferIPv6())
}
