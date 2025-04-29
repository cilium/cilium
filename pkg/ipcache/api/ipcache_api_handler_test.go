// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsSubnet(t *testing.T) {
	type args struct {
		outer, inner string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			args: args{"10.10.1.2/32", "10.10.1.2/32"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.0.1/32"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.0.1/8"},
			want: false,
		},
		{
			args: args{"10.10.0.0/16", "10.10.255.255/16"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.255.255/8"},
			want: false,
		},
		{
			args: args{"10.10.255.255/8", "10.10.0.0/16"},
			want: true,
		},
		{
			args: args{"0.0.0.0/0", "10.10.0.0/16"},
			want: true,
		},
		{
			args: args{"f00d::a10:0:0:0/64", "f00d::a10:0:0:1234/128"},
			want: true,
		},
		{
			args: args{"f00d::a10:0:0:1234/128", "f00d::a10:0:0:1234/64"},
			want: false,
		},
		{
			args: args{"::/0", "f00d::a10:0:0:1234/64"},
			want: true,
		},
	}
	for _, tt := range tests {
		_, outer, err := net.ParseCIDR(tt.args.outer)
		require.NoError(t, err)
		_, inner, err := net.ParseCIDR(tt.args.inner)
		require.NoError(t, err)
		got := containsSubnet(*outer, *inner)
		require.Equalf(t, tt.want, got, "expected containsSubnet(%q, %q) = %t, got %t", tt.args.outer, tt.args.inner, tt.want, got)
	}
}
