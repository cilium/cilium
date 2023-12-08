// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewServersInitialization(t *testing.T) {
	tests := []struct {
		name                  string
		address               []string
		expectedServerCount   int
		expectedServerAddress []string
	}{
		{
			name:                  "Initialize http server listening on all ports",
			address:               []string{""},
			expectedServerCount:   1,
			expectedServerAddress: []string{":4240"},
		},
		{
			name:                  "Initialize http server listening on ipv4 address",
			address:               []string{"192.168.1.4"},
			expectedServerCount:   1,
			expectedServerAddress: []string{"192.168.1.4:4240"},
		},
		{
			name:                  "Initialize http server listening on ipv4 and ipv6 address",
			address:               []string{"192.168.1.4", "fc00:c111::2"},
			expectedServerCount:   2,
			expectedServerAddress: []string{"192.168.1.4:4240", "[fc00:c111::2]:4240"},
		},
		{
			name:                  "Initialize http server with nil address",
			address:               []string{},
			expectedServerCount:   1,
			expectedServerAddress: []string{":4240"},
		},
	}

	for _, tt := range tests {
		s := NewServers(tt.address, 4240)
		assert.NotNil(t, s)
		assert.Equal(t, len(s.httpServers), tt.expectedServerCount, "Number of listen address doesn't match")
		for i, s := range s.httpServers {
			assert.Equal(t, tt.expectedServerAddress[i], s.Addr)
		}
	}
}
