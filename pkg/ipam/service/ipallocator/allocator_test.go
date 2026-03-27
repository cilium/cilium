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
			wantMax:  30, // (2^(32-27)) - 2
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

func TestNewCIDRRangeWithAllowFirstLastIPs(t *testing.T) {
	testCases := []struct {
		name     string
		ipNet    *net.IPNet
		wantBase net.IP
		wantMax  int
	}{
		{
			name:     "IPv4 /28 prefix delegation",
			ipNet:    mustParseCidr("10.0.0.0/28"),
			wantBase: net.ParseIP("10.0.0.0"),
			wantMax:  16, // all 16 IPs usable
		},
		{
			name:     "IPv4 /24",
			ipNet:    mustParseCidr("10.0.0.0/24"),
			wantBase: net.ParseIP("10.0.0.0"),
			wantMax:  256, // all 256 IPs usable
		},
		{
			name:     "IPv6 /80 prefix delegation",
			ipNet:    mustParseCidr("2001:db8::/80"),
			wantBase: net.ParseIP("2001:db8::"),
			wantMax:  65536, // all 65536 IPs usable
		},
		{
			name:     "IPv4 /32 unchanged",
			ipNet:    mustParseCidr("10.0.0.1/32"),
			wantBase: net.ParseIP("10.0.0.1"),
			wantMax:  1, // /32 is unaffected by the option
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewCIDRRange(tc.ipNet, WithAllowFirstLastIPs())
			baseIP := ipForBig(r.base)
			require.Equal(t, tc.wantBase.String(), baseIP.String())
			require.Equal(t, tc.wantMax, r.max)
		})
	}
}

func TestAllowFirstLastIPsAllocateAll(t *testing.T) {
	// Verify all 16 IPs in a /28 are allocatable with WithAllowFirstLastIPs.
	cidr := mustParseCidr("10.0.0.0/28")
	r := NewCIDRRange(cidr, WithAllowFirstLastIPs())

	require.Equal(t, 16, r.Free())

	allocatedSet := map[string]struct{}{}
	for range 16 {
		ip, err := r.AllocateNext()
		require.NoError(t, err)
		allocatedSet[ip.String()] = struct{}{}
	}

	// Should be full now.
	_, err := r.AllocateNext()
	require.ErrorIs(t, err, ErrFull)
	require.Equal(t, 0, r.Free())

	// First and last IPs of the /28 should have been allocated.
	require.Contains(t, allocatedSet, "10.0.0.0")
	require.Contains(t, allocatedSet, "10.0.0.15")

	// Verify ForEach returns all allocated IPs.
	forEachSet := map[string]struct{}{}
	r.ForEach(func(ip net.IP) {
		forEachSet[ip.String()] = struct{}{}
	})
	require.Len(t, forEachSet, 16)
	require.Contains(t, forEachSet, "10.0.0.0")
	require.Contains(t, forEachSet, "10.0.0.15")
}

func TestAllowFirstLastIPsAllocateSpecific(t *testing.T) {
	cidr := mustParseCidr("10.0.0.0/28")
	r := NewCIDRRange(cidr, WithAllowFirstLastIPs())

	// Allocate the first IP (network address).
	require.NoError(t, r.Allocate(net.ParseIP("10.0.0.0")))
	require.True(t, r.Has(net.ParseIP("10.0.0.0")))

	// Allocate the last IP (broadcast address).
	require.NoError(t, r.Allocate(net.ParseIP("10.0.0.15")))
	require.True(t, r.Has(net.ParseIP("10.0.0.15")))

	require.Equal(t, 14, r.Free())
}

func TestDefaultRangeExcludesFirstLastIPs(t *testing.T) {
	cidr := mustParseCidr("10.0.0.0/28")
	r := NewCIDRRange(cidr)

	require.Equal(t, 14, r.Free())

	// .0 and .15 should be out of range.
	require.ErrorContains(t, r.Allocate(net.ParseIP("10.0.0.0")), "not in the valid range")
	require.ErrorContains(t, r.Allocate(net.ParseIP("10.0.0.15")), "not in the valid range")

	// .1 and .14 should be allocatable (first and last usable IPs).
	require.NoError(t, r.Allocate(net.ParseIP("10.0.0.1")))
	require.NoError(t, r.Allocate(net.ParseIP("10.0.0.14")))
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
