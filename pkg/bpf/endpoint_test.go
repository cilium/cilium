// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEndpointKeyToString(t *testing.T) {
	tests := []struct {
		addr netip.Addr
	}{
		{netip.IPv4Unspecified()},
		{netip.MustParseAddr("192.0.2.3")},
		{netip.IPv6Unspecified()},
		{netip.MustParseAddr("fdff::ff")},
	}

	for _, tt := range tests {
		k := NewEndpointKey(tt.addr, 0)
		require.Equal(t, tt.addr.String(), k.ToAddr().String())
	}
}
