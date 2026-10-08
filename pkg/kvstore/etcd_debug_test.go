// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEtcdDbgOutputIPs(t *testing.T) {
	tests := []struct {
		name string
		ips  []netip.Addr
		want string
	}{
		{name: "empty", ips: nil, want: ""},
		{name: "single IPv4", ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, want: "10.0.0.1"},
		{name: "single IPv6", ips: []netip.Addr{netip.MustParseAddr("fe80::1")}, want: "fe80::1"},
		{name: "IPv4-in-IPv6 is unmapped", ips: []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}, want: "10.0.0.1"},
		{
			name: "multiple addresses",
			ips:  []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
			want: "10.0.0.1, 10.0.0.2",
		},
		{
			name: "truncated after four",
			ips: []netip.Addr{
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
				netip.MustParseAddr("10.0.0.5"),
			},
			want: "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, ...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, etcdDbgOutputIPs(tt.ips))
		})
	}
}
