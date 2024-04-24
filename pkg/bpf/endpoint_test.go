// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointKeyToString(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{"0.0.0.0"},
		{"192.0.2.3"},
		{"::"},
		{"fdff::ff"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		k := NewEndpointKey(ip, 0)
		require.Equal(t, tt.ip, k.ToIP().String())
	}
}
