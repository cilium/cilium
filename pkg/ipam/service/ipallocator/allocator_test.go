package ipallocator

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCIDRRange(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   netip.Prefix
		wantBase netip.Addr
		wantMax  int
	}{
		{
			name:     "IPv4 /27",
			prefix:   netip.MustParsePrefix("192.168.0.0/27"),
			wantBase: netip.MustParseAddr("192.168.0.1"),
			wantMax:  30, // (2^(32-27)) - 2
		},
		{
			name:     "IPv4 /31",
			prefix:   netip.MustParsePrefix("192.168.0.0/31"),
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
			prefix:   netip.MustParsePrefix("2001:db8::/64"),
			wantBase: netip.MustParseAddr("2001:db8::1"),
			wantMax:  65534, // max(2^(128-64), 65536) - 2
		},
		{
			name:     "IPv6 /120",
			prefix:   netip.MustParsePrefix("2001:db8::/120"),
			wantBase: netip.MustParseAddr("2001:db8::1"),
			wantMax:  254, // 2^(128-120) - 2
		},
		{
			name:     "IPv6 /127",
			prefix:   netip.MustParsePrefix("2001:db8::/127"),
			wantBase: netip.MustParseAddr("2001:db8::"),
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
			require.Equal(t, tc.wantBase, actual.base)
			require.Equal(t, tc.wantMax, actual.max)
		})
	}
}

func TestNewCIDRRangeWithAllowFirstLastIPs(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   netip.Prefix
		wantBase netip.Addr
		wantMax  int
	}{
		{
			name:     "IPv4 /28 prefix delegation",
			prefix:   netip.MustParsePrefix("10.0.0.0/28"),
			wantBase: netip.MustParseAddr("10.0.0.0"),
			wantMax:  16, // all 16 IPs usable
		},
		{
			name:     "IPv4 /24",
			prefix:   netip.MustParsePrefix("10.0.0.0/24"),
			wantBase: netip.MustParseAddr("10.0.0.0"),
			wantMax:  256, // all 256 IPs usable
		},
		{
			name:     "IPv6 /80 prefix delegation",
			prefix:   netip.MustParsePrefix("2001:db8::/80"),
			wantBase: netip.MustParseAddr("2001:db8::"),
			wantMax:  65536, // all 65536 IPs usable
		},
		{
			name:     "IPv4 /32 unchanged",
			prefix:   netip.MustParsePrefix("10.0.0.1/32"),
			wantBase: netip.MustParseAddr("10.0.0.1"),
			wantMax:  1, // /32 is unaffected by the option
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewCIDRRange(tc.prefix, WithAllowFirstLastIPs())
			require.Equal(t, tc.wantBase, r.base)
			require.Equal(t, tc.wantMax, r.max)
		})
	}
}

func TestAllowFirstLastIPsAllocateAll(t *testing.T) {
	// Verify all 16 IPs in a /28 are allocatable with WithAllowFirstLastIPs.
	prefix := netip.MustParsePrefix("10.0.0.0/28")
	r := NewCIDRRange(prefix, WithAllowFirstLastIPs())

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
	r.ForEach(func(ip netip.Addr) {
		forEachSet[ip.String()] = struct{}{}
	})
	require.Len(t, forEachSet, 16)
	require.Contains(t, forEachSet, "10.0.0.0")
	require.Contains(t, forEachSet, "10.0.0.15")
}

func TestAllowFirstLastIPsAllocateSpecific(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/28")
	r := NewCIDRRange(prefix, WithAllowFirstLastIPs())

	// Allocate the first IP (network address).
	require.NoError(t, r.Allocate(netip.MustParseAddr("10.0.0.0")))
	require.True(t, r.Has(netip.MustParseAddr("10.0.0.0")))

	// Allocate the last IP (broadcast address).
	require.NoError(t, r.Allocate(netip.MustParseAddr("10.0.0.15")))
	require.True(t, r.Has(netip.MustParseAddr("10.0.0.15")))

	require.Equal(t, 14, r.Free())
}

func TestDefaultRangeExcludesFirstLastIPs(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/28")
	r := NewCIDRRange(prefix)

	require.Equal(t, 14, r.Free())

	// .0 and .15 should be out of range.
	require.ErrorContains(t, r.Allocate(netip.MustParseAddr("10.0.0.0")), "not in the valid range")
	require.ErrorContains(t, r.Allocate(netip.MustParseAddr("10.0.0.15")), "not in the valid range")

	// .1 and .14 should be allocatable (first and last usable IPs).
	require.NoError(t, r.Allocate(netip.MustParseAddr("10.0.0.1")))
	require.NoError(t, r.Allocate(netip.MustParseAddr("10.0.0.14")))
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
			actual := RangeSize(tc.prefix)
			require.Equal(t, tc.want, actual)
		})
	}
}

func TestAddOffset(t *testing.T) {
	testCases := []struct {
		name   string
		base   netip.Addr
		offset int
		want   netip.Addr
	}{
		{
			name:   "IPv4 +0",
			base:   netip.MustParseAddr("10.0.0.1"),
			offset: 0,
			want:   netip.MustParseAddr("10.0.0.1"),
		},
		{
			name:   "IPv4 +1",
			base:   netip.MustParseAddr("10.0.0.1"),
			offset: 1,
			want:   netip.MustParseAddr("10.0.0.2"),
		},
		{
			name:   "IPv4 byte carry",
			base:   netip.MustParseAddr("10.0.0.255"),
			offset: 1,
			want:   netip.MustParseAddr("10.0.1.0"),
		},
		{
			name:   "IPv4 large offset",
			base:   netip.MustParseAddr("10.0.0.0"),
			offset: 256,
			want:   netip.MustParseAddr("10.0.1.0"),
		},
		{
			name:   "IPv6 +1",
			base:   netip.MustParseAddr("2001:db8::1"),
			offset: 1,
			want:   netip.MustParseAddr("2001:db8::2"),
		},
		{
			name:   "IPv6 low word carry",
			base:   netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff"),
			offset: 1,
			want:   netip.MustParseAddr("2001:db8::1:0:0:0:0"),
		},
		{
			name:   "IPv6 large offset",
			base:   netip.MustParseAddr("2001:db8::"),
			offset: 65535,
			want:   netip.MustParseAddr("2001:db8::ffff"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := addOffset(tc.base, tc.offset)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAddrOffset(t *testing.T) {
	testCases := []struct {
		name string
		base netip.Addr
		addr netip.Addr
		want int
	}{
		{
			name: "IPv4 same address",
			base: netip.MustParseAddr("10.0.0.1"),
			addr: netip.MustParseAddr("10.0.0.1"),
			want: 0,
		},
		{
			name: "IPv4 +1",
			base: netip.MustParseAddr("10.0.0.1"),
			addr: netip.MustParseAddr("10.0.0.2"),
			want: 1,
		},
		{
			name: "IPv4 cross byte boundary",
			base: netip.MustParseAddr("10.0.0.255"),
			addr: netip.MustParseAddr("10.0.1.0"),
			want: 1,
		},
		{
			name: "IPv4 large offset",
			base: netip.MustParseAddr("10.0.0.0"),
			addr: netip.MustParseAddr("10.0.1.0"),
			want: 256,
		},
		{
			name: "IPv6 same address",
			base: netip.MustParseAddr("2001:db8::1"),
			addr: netip.MustParseAddr("2001:db8::1"),
			want: 0,
		},
		{
			name: "IPv6 +1",
			base: netip.MustParseAddr("2001:db8::1"),
			addr: netip.MustParseAddr("2001:db8::2"),
			want: 1,
		},
		{
			name: "IPv6 large offset",
			base: netip.MustParseAddr("2001:db8::"),
			addr: netip.MustParseAddr("2001:db8::ffff"),
			want: 65535,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := addrOffset(tc.base, tc.addr)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAddOffsetAddrOffsetRoundTrip(t *testing.T) {
	bases := []netip.Addr{
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("192.168.1.100"),
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("fe80::1"),
	}
	offsets := []int{0, 1, 127, 255, 256, 1000, 65535}

	for _, base := range bases {
		for _, offset := range offsets {
			addr := addOffset(base, offset)
			got := addrOffset(base, addr)
			require.Equal(t, offset, got, "roundtrip failed for base=%s offset=%d", base, offset)
		}
	}
}
