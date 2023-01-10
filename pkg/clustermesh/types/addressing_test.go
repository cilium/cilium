// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"
)

func TestParseAddrCluster(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantErr bool
	}{
		{"valid bare IPv4 address", "10.0.0.1", false},
		{"invalid bare IPv4 address", "257.0.0.1", true},

		{"valid IPv4 address and valid cluster-id", "10.0.0.1@1", false},
		{"invalid IPv4 address and valid cluster-id", "257.0.0.1@1", true},
		{"valid IPv4 address and invalid cluster-id", "10.0.0.1@foo", true},
		{"valid IPv4 address and enpty cluster-id", "10.0.0.1@", true},

		{"valid bare IPv6 address", "a::1", false},
		{"invalid bare IPv6 address", "g::1", true},

		{"valid IPv6 address and valid cluster-id", "a::1@1", false},
		{"invalid IPv6 address and valid cluster-id", "g::1@1", true},
		{"valid IPv6 address and invalid cluster-id", "a::1@foo", true},
		{"valid IPv6 address and enpty cluster-id", "a::1@", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrCluster(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddrCluster() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	// Ensure bare IP address equals to ClusterID = 0
	if MustParseAddrCluster("10.0.0.1") != MustParseAddrCluster("10.0.0.1@0") {
		t.Errorf("ParseAddrCluster() returns different results for bare IP address and IP address with zero ClusterID")
		return
	}
}

func TestAddrCluster_Equal(t *testing.T) {
	type fields struct {
		addr      netip.Addr
		clusterID uint32
	}
	type args struct {
		ac1 AddrCluster
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"same IP and same ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1}},
			true,
		},
		{
			"same IP and different ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 2}},
			false,
		},
		{
			"different IP and same ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.2"), clusterID: 1}},
			false,
		},
		{
			"different IP and different ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.2"), clusterID: 2}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac0 := AddrCluster{
				addr:      tt.fields.addr,
				clusterID: tt.fields.clusterID,
			}
			if got := ac0.Equal(tt.args.ac1); got != tt.want {
				t.Errorf("AddrCluster.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddrCluster_Less(t *testing.T) {
	type fields struct {
		addr      netip.Addr
		clusterID uint32
	}
	type args struct {
		ac1 AddrCluster
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"same IP and same ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1}},
			false,
		},
		{
			"larger IP and same ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.2"), clusterID: 1}},
			true,
		},
		{
			"smaller IP and smaller ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.2"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1}},
			false,
		},
		{
			"same IP and larger ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 2}},
			true,
		},
		{
			"same IP and smaller ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 2},
			args{ac1: AddrCluster{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac0 := AddrCluster{
				addr:      tt.fields.addr,
				clusterID: tt.fields.clusterID,
			}
			if got := ac0.Less(tt.args.ac1); got != tt.want {
				t.Errorf("AddrCluster.Less() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddrCluster_String(t *testing.T) {
	type fields struct {
		addr      netip.Addr
		clusterID uint32
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"zero ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 0},
			"10.0.0.1",
		},
		{
			"non-zero ClusterID",
			fields{addr: netip.MustParseAddr("10.0.0.1"), clusterID: 1},
			"10.0.0.1@1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := AddrCluster{
				addr:      tt.fields.addr,
				clusterID: tt.fields.clusterID,
			}
			if got := ac.String(); got != tt.want {
				t.Errorf("AddrCluster.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePrefixCluster(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantErr bool
	}{
		{"valid bare IPv4 prefix", "10.0.0.0/24", false},
		{"invalid bare IPv4 prefix 1", "10.0.0.0", true},
		{"invalid bare IPv4 prefix 2", "257.0.0.0/24", true},

		{"valid IPv4 prefix and valid cluster-id", "10.0.0.0/24@1", false},
		{"invalid IPv4 prefix and valid cluster-id", "257.0.0.0/24@1", true},
		{"valid IPv4 prefix and invalid cluster-id", "10.0.0.0/24@foo", true},
		{"valid IPv4 prefix and empty cluster-id", "10.0.0.0/24@", true},

		{"valid bare IPv6 prefix", "a::/64", false},
		{"invalid bare IPv6 prefix", "g::/64", true},

		{"valid IPv6 prefix and valid cluster-id", "a::/64@1", false},
		{"invalid IPv6 prefix and valid cluster-id", "g::/64@1", true},
		{"valid IPv6 prefix and invalid cluster-id", "a::/64@foo", true},
		{"valid IPv6 prefix and empty cluster-id", "a::/64@", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrefixCluster(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrefixCluster() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	// Ensure bare IP address equals to ClusterID = 0
	if MustParsePrefixCluster("10.0.0.0/24") != MustParsePrefixCluster("10.0.0.0/24@0") {
		t.Errorf("ParsePrefixCluster() returns different results for bare IP prefix and IP prefix with zero ClusterID")
		return
	}
}
