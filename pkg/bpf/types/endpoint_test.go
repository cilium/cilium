// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndpointKeyToString(t *testing.T) {
	assert := assert.New(t)
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
		assert.Equal(tt.ip, k.ToIP().String())
	}
}
