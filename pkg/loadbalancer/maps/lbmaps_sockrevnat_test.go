// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSockRevNatByteOrder: the datapath copies the reverse NAT index of the service, in
// network byte order, into the socket-LB entry, so the entry has the one of a service entry.
func TestSockRevNatByteOrder(t *testing.T) {
	for _, tc := range []struct {
		name              string
		ipv6              bool
		backend, frontend string
	}{
		{name: "ipv4", backend: "10.1.0.1:8080", frontend: "172.18.0.10:80"},
		{name: "ipv6", ipv6: true, backend: "[fd01::1]:8080", frontend: "[fd00::10]:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFakeLBMaps().(*FakeLBMaps)
			entry := SockRevNatEntry{Cookie: 7, Backend: netip.MustParseAddrPort(tc.backend), Frontend: netip.MustParseAddrPort(tc.frontend), RevNatIndex: 3}
			require.NoError(t, f.UpdateSockRevNat(entry))

			want := uint16((&Service4Value{RevNat: 3}).ToNetwork().GetRevNat())
			f.sockRevNat.Range(func(_ string, p kvpair) bool {
				switch v := p.b.(type) {
				case *SockRevNat4Value:
					require.Equal(t, want, v.RevNatIndex)
				case *SockRevNat6Value:
					require.Equal(t, want, v.RevNatIndex)
				}
				return true
			})

			var dumped []SockRevNatEntry
			require.NoError(t, f.DumpSockRevNat(tc.ipv6, func(e SockRevNatEntry) { dumped = append(dumped, e) }))
			require.Equal(t, []SockRevNatEntry{entry}, dumped)
			require.NoError(t, f.DumpSockRevNat(!tc.ipv6, func(SockRevNatEntry) { t.Error("entry of the other IP family") }))
		})
	}
}
