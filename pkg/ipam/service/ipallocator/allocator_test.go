package ipallocator

import (
	"math/big"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func addrForBig(i *big.Int) netip.Addr {
	return addAddrOffset(i, 0)
}

func TestNewCIDRRange(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   netip.Prefix
		wantBase netip.Addr
		wantMax  int
	}{
		{
			name:     "IPv4 /27",
			prefix:   netip.MustParsePrefix("192.168.0.1/27"),
			wantBase: netip.MustParseAddr("192.168.0.1"),
			wantMax:  30, // (2^(32-27) - 2
		},
		{
			name:     "IPv4 /31",
			prefix:   netip.MustParsePrefix("192.168.0.1/31"),
			wantBase: netip.MustParseAddr("192.168.0.0"),
			wantMax:  2, // 2^1
		},
		{
			name:     "IPv4 /32",
			prefix:   netip.MustParsePrefix("192.168.0.1/32"),
			wantBase: netip.MustParseAddr("192.168.0.1"),
			wantMax:  1, // 2^0
		},
		{
			name:     "IPv6 /64",
			prefix:   netip.MustParsePrefix("2001:db8::1/64"),
			wantBase: netip.MustParseAddr("2001:db8::1"),
			wantMax:  65534, // max(2^(128-64), 65536) - 2
		},
		{
			name:     "IPv6 /120",
			prefix:   netip.MustParsePrefix("2001:db8::1/120"),
			wantBase: netip.MustParseAddr("2001:db8::1"),
			wantMax:  254, // 2^(128-120) - 2
		},
		{
			name:     "IPv6 /127",
			prefix:   netip.MustParsePrefix("2001:db8::1/127"),
			wantBase: netip.MustParseAddr("2001:db8::0"),
			wantMax:  2, // 2^1
		},
		{
			name:     "IPv6 /128",
			prefix:   netip.MustParsePrefix("2001:db8::1/128"),
			wantBase: netip.MustParseAddr("2001:db8::1"),
			wantMax:  1, // 2^0
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewCIDRRange(tc.prefix)
			baseAddr := addrForBig(actual.base)
			require.Equal(t, tc.wantBase, baseAddr)
			require.Equal(t, tc.wantMax, actual.max)
		})
	}
}

func TestRangeSize(t *testing.T) {
	testCases := []struct {
		name   string
		prefix netip.Prefix
		want   int64
	}{
		{
			name:   "IPv4 /27",
			prefix: netip.MustParsePrefix("192.168.0.0/27"),
			want:   32,
		},
		{
			name:   "IPv4 /32",
			prefix: netip.MustParsePrefix("192.168.0.0/32"),
			want:   1,
		},
		{
			name:   "IPv6 /64",
			prefix: netip.MustParsePrefix("2001:db8::/64"),
			want:   65536,
		},
		{
			name:   "IPv6 /120",
			prefix: netip.MustParsePrefix("2001:db8::/120"),
			want:   256,
		},
		{
			name:   "IPv6 /128",
			prefix: netip.MustParsePrefix("2001:db8::/128"),
			want:   1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := rangeSize(tc.prefix)
			require.Equal(t, tc.want, actual)
		})
	}
}
