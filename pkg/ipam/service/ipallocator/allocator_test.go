package ipallocator

import (
	"fmt"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustParseCidr(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Errorf("net.ParseCIDR: %w", err))
	}
	return ipNet
}

func ipForBig(i *big.Int) net.IP {
	return addIPOffset(i, 0)
}

func TestNewCIDRRange(t *testing.T) {
	testCases := []struct {
		name     string
		ipNet    *net.IPNet
		wantBase net.IP
		wantMax  int
	}{
		{
			name:     "IPv4 /27",
			ipNet:    mustParseCidr("192.168.0.1/27"),
			wantBase: net.ParseIP("192.168.0.1"),
			wantMax:  30, // (2^(32-27) - 2
		},
		{
			name:     "IPv4 /31",
			ipNet:    mustParseCidr("192.168.0.1/31"),
			wantBase: net.ParseIP("192.168.0.0"),
			wantMax:  2, // 2^1
		},
		{
			name:     "IPv4 /32",
			ipNet:    mustParseCidr("192.168.0.1/32"),
			wantBase: net.ParseIP("192.168.0.1"),
			wantMax:  1, // 2^0
		},
		{
			name:     "IPv6 /64",
			ipNet:    mustParseCidr("2001:db8::1/64"),
			wantBase: net.ParseIP("2001:db8::1"),
			wantMax:  65534, // max(2^(128-64), 65536) - 2
		},
		{
			name:     "IPv6 /120",
			ipNet:    mustParseCidr("2001:db8::1/120"),
			wantBase: net.ParseIP("2001:db8::1"),
			wantMax:  254, // 2^(128-120) - 2
		},
		{
			name:     "IPv6 /127",
			ipNet:    mustParseCidr("2001:db8::1/127"),
			wantBase: net.ParseIP("2001:db8::0"),
			wantMax:  2, // 2^1
		},
		{
			name:     "IPv6 /128",
			ipNet:    mustParseCidr("2001:db8::1/128"),
			wantBase: net.ParseIP("2001:db8::1"),
			wantMax:  1, // 2^0
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewCIDRRange(tc.ipNet)
			baseIP := ipForBig(actual.base)
			require.Equal(t, tc.wantBase.String(), baseIP.String())
			require.Equal(t, tc.wantMax, actual.max)
		})
	}
}

func TestRangeSize(t *testing.T) {
	testCases := []struct {
		name  string
		ipNet *net.IPNet
		want  int64
	}{
		{
			name:  "IPv4 /27",
			ipNet: mustParseCidr("192.168.0.0/27"),
			want:  32,
		},
		{
			name:  "IPv4 /32",
			ipNet: mustParseCidr("192.168.0.0/32"),
			want:  1,
		},
		{
			name:  "IPv6 /64",
			ipNet: mustParseCidr("2001:db8::/64"),
			want:  65536,
		},
		{
			name:  "IPv6 /120",
			ipNet: mustParseCidr("2001:db8::/120"),
			want:  256,
		},
		{
			name:  "IPv6 /128",
			ipNet: mustParseCidr("2001:db8::/128"),
			want:  1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RangeSize(tc.ipNet)
			require.Equal(t, tc.want, actual)
		})
	}
}
