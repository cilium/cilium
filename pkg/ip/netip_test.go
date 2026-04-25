// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddrJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Addr
		want string
	}{
		{"ipv4", AddrFrom(netip.MustParseAddr("10.0.0.1")), `"10.0.0.1"`},
		{"ipv6", AddrFrom(netip.MustParseAddr("fd00::1")), `"fd00::1"`},
		{"zero", Addr{}, `""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(b))

			var got Addr
			require.NoError(t, json.Unmarshal(b, &got))
			assert.True(t, tc.in.DeepEqual(&got))
		})
	}
}

func TestPrefixJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Prefix
		want string
	}{
		{"ipv4", PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")), `"10.0.0.0/24"`},
		{"ipv6", PrefixFrom(netip.MustParsePrefix("fd00::/64")), `"fd00::/64"`},
		{"zero", Prefix{}, `""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(b))

			var got Prefix
			require.NoError(t, json.Unmarshal(b, &got))
			assert.True(t, tc.in.DeepEqual(&got))
		})
	}
}

func TestAddrUnmarshalInvalid(t *testing.T) {
	var a Addr
	assert.Error(t, json.Unmarshal([]byte(`"not-an-ip"`), &a))
}

func TestPrefixUnmarshalInvalid(t *testing.T) {
	var p Prefix
	assert.Error(t, json.Unmarshal([]byte(`"not-a-cidr"`), &p))
}

// TestOmitZero verifies the IsZero hooks drive encoding/json's `omitzero`
// tag option for both wrappers, including the invalid-but-non-zero Prefix
// case that a reflect-based zero check would miss.
func TestOmitZero(t *testing.T) {
	type holder struct {
		A Addr   `json:"a,omitzero"`
		P Prefix `json:"p,omitzero"`
	}
	tests := []struct {
		name string
		in   holder
		want string
	}{
		{"both-zero", holder{}, `{}`},
		{
			"invalid-prefix-non-zero",
			holder{P: PrefixFrom(netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), -1))},
			`{}`,
		},
		{
			"both-set",
			holder{
				A: AddrFrom(netip.MustParseAddr("10.0.0.1")),
				P: PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			},
			`{"a":"10.0.0.1","p":"10.0.0.0/24"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(b))
		})
	}
}

func TestAddrDeepCopy(t *testing.T) {
	orig := AddrFrom(netip.MustParseAddr("10.0.0.1"))
	cp := orig.DeepCopy()
	assert.True(t, orig.DeepEqual(cp))

	assert.Nil(t, (*Addr)(nil).DeepCopy())
}

func TestPrefixDeepCopy(t *testing.T) {
	orig := PrefixFrom(netip.MustParsePrefix("10.0.0.0/24"))
	cp := orig.DeepCopy()
	assert.True(t, orig.DeepEqual(cp))

	assert.Nil(t, (*Prefix)(nil).DeepCopy())
}

func TestAddrDeepEqualNil(t *testing.T) {
	a := AddrFrom(netip.MustParseAddr("10.0.0.1"))
	assert.True(t, (*Addr)(nil).DeepEqual(nil))
	assert.False(t, (*Addr)(nil).DeepEqual(&a))
	assert.False(t, a.DeepEqual(nil))
}

func TestPrefixDeepEqualNil(t *testing.T) {
	p := PrefixFrom(netip.MustParsePrefix("10.0.0.0/24"))
	assert.True(t, (*Prefix)(nil).DeepEqual(nil))
	assert.False(t, (*Prefix)(nil).DeepEqual(&p))
	assert.False(t, p.DeepEqual(nil))
}
