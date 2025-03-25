// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitID(t *testing.T) {
	type want struct {
		prefixType PrefixType
		id         string
	}
	tests := []struct {
		name string
		id   string
		want want
	}{
		{
			name: "ID without a prefix",
			id:   "123456",
			want: want{
				prefixType: CiliumLocalIdPrefix,
				id:         "123456",
			},
		},
		{
			name: "ID CiliumLocalIdPrefix prefix",
			id:   string(CiliumLocalIdPrefix) + ":123456",
			want: want{
				prefixType: CiliumLocalIdPrefix,
				id:         "123456",
			},
		},
		{
			name: "ID with PodNamePrefix prefix",
			id:   string(PodNamePrefix) + ":default:foobar",
			want: want{
				prefixType: PodNamePrefix,
				id:         "default:foobar",
			},
		},
		{
			name: "ID with CEPNamePrefix prefix",
			id:   string(CEPNamePrefix) + ":default:baz-net1",
			want: want{
				prefixType: CEPNamePrefix,
				id:         "default:baz-net1",
			},
		},
		{
			name: "ID with ':'",
			id:   ":",
			want: want{
				prefixType: "",
				id:         "",
			},
		},
		{
			name: "Empty ID",
			id:   "",
			want: want{
				prefixType: CiliumLocalIdPrefix,
				id:         "",
			},
		},
	}
	for _, tt := range tests {
		prefixType, id := splitID(tt.id)
		require.Equal(t, tt.want.prefixType, prefixType, "Test Name: %s", tt.name)
		require.Equal(t, tt.want.id, id, "Test Name: %s", tt.name)
	}
}

func BenchmarkSplitID(b *testing.B) {
	tests := []struct {
		str        string
		prefixType PrefixType
		id         string
	}{
		{"123456", CiliumLocalIdPrefix, "123456"},
		{string(CiliumLocalIdPrefix + ":123456"), CiliumLocalIdPrefix, "123456"},
		{string(PodNamePrefix + ":default:foobar"), PodNamePrefix, "default:foobar"},
	}
	count := 0

	for b.Loop() {
		for _, test := range tests {
			pt, str := splitID(test.str)
			if pt == test.prefixType && str == test.id {
				count++
			}
		}
	}
	b.StopTimer()
	if count != len(tests)*b.N {
		b.Errorf("splitID didn't produce correct results")
	}
	b.ReportAllocs()
}

func TestParse(t *testing.T) {
	type test struct {
		input      PrefixType
		wantPrefix PrefixType
		wantID     string
		expectFail bool
	}

	tests := []test{
		{DockerEndpointPrefix + ":foo", DockerEndpointPrefix, "foo", false},
		{DockerEndpointPrefix + ":foo:foo", DockerEndpointPrefix, "foo:foo", false},
		{"unknown:unknown", "", "", true},
		{"unknown", CiliumLocalIdPrefix, "unknown", false},
	}

	for _, tt := range tests {
		prefix, id, err := Parse(string(tt.input))
		require.Equal(t, tt.wantPrefix, prefix)
		require.Equal(t, tt.wantID, id)
		if tt.expectFail {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestNewIPPrefix(t *testing.T) {
	require.True(t, strings.HasPrefix(NewIPPrefixID(netip.MustParseAddr("1.1.1.1")), string(IPv4Prefix)))
	require.True(t, strings.HasPrefix(NewIPPrefixID(netip.MustParseAddr("f00d::1")), string(IPv6Prefix)))
}
