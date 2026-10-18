// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceAddressString(t *testing.T) {
	addr := netip.MustParseAddr("2001::1")
	tests := []struct {
		addr DeviceAddress
		want string
	}{
		{DeviceAddress{Addr: addr, Scope: 0}, "2001::1 (scope=0)"},
		{DeviceAddress{Addr: addr, Secondary: true, Scope: 253}, "2001::1 (secondary, scope=253)"},
		{DeviceAddress{Addr: addr, Deprecated: true, Scope: 0}, "2001::1 (deprecated, scope=0)"},
		{DeviceAddress{Addr: addr, Secondary: true, Deprecated: true, Scope: 0}, "2001::1 (secondary, deprecated, scope=0)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.addr.String())
	}
}
