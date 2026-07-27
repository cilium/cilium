// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenLegacy is the exact on-wire encoding that agents predating this wrapper
// produce and expect (the promoted net.IPNet struct of the old *cidr.CIDR).
//
// If MarshalJSON ever stops producing these bytes, the change is not safe. Do not
// edit this map to make the test pass.
var goldenLegacy = map[string]string{
	"10.244.1.0/24": `{"IP":"10.244.1.0","Mask":"////AA=="}`,
	"fd00::/64":     `{"IP":"fd00::","Mask":"//////////8AAAAAAAAAAA=="}`,
}

func TestPrefix_MarshalMatchesLegacyGolden(t *testing.T) {
	for cidr, want := range goldenLegacy {
		got, err := json.Marshal(PrefixFrom(netip.MustParsePrefix(cidr)))
		require.NoError(t, err, cidr)
		// Byte-exact, not just JSONEq: field order and base64 mask must match
		// what old agents emit and diff against.
		assert.Equal(t, want, string(got), "wire-format drift for %s", cidr)
	}
}

func TestPrefix_UnmarshalAcceptsBothFormats(t *testing.T) {
	for cidr, legacy := range goldenLegacy {
		want := netip.MustParsePrefix(cidr)
		for name, in := range map[string]string{
			"legacy": legacy,
			"string": `"` + cidr + `"`,
		} {
			var p Prefix
			require.NoErrorf(t, json.Unmarshal([]byte(in), &p), "%s/%s", cidr, name)
			assert.Equalf(t, want, p.Prefix.Prefix, "%s/%s", cidr, name)
		}
	}
}

func TestPrefix_RoundTrip(t *testing.T) {
	for cidr := range goldenLegacy {
		orig := PrefixFrom(netip.MustParsePrefix(cidr))
		b, err := json.Marshal(orig)
		require.NoError(t, err, cidr)
		var back Prefix
		require.NoError(t, json.Unmarshal(b, &back), cidr)
		assert.Equal(t, orig, back, cidr)
	}
}

func TestPrefix_NilAndZero(t *testing.T) {
	// An unset Prefix marshals to null, matching a nil *cidr.CIDR.
	b, err := json.Marshal(Prefix{})
	require.NoError(t, err)
	assert.Equal(t, "null", string(b))

	var back Prefix
	require.NoError(t, json.Unmarshal([]byte("null"), &back))
	assert.False(t, back.IsValid())
}

func TestPrefix_NonCanonicalHostBitsAreMasked(t *testing.T) {
	// A prefix carrying host bits (e.g. from a hand-built value) is canonicalized
	// to its network address, matching net.ParseCIDR's behavior.
	p := PrefixFrom(netip.MustParsePrefix("10.244.1.5/24"))
	b, err := json.Marshal(p)
	require.NoError(t, err)
	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `{"IP":"10.244.1.0","Mask":"////AA=="}`, string(b))
}

func TestPrefix_RejectsGarbage(t *testing.T) {
	for _, in := range []string{`"not-a-cidr"`, `{"IP":"garbage","Mask":"////AA=="}`, `42`} {
		var p Prefix
		assert.Error(t, json.Unmarshal([]byte(in), &p), in)
	}
}
